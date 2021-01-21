package checker

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/form3tech-oss/jwt-go"
	maoclient "github.com/openshift/machine-api-operator/pkg/generated/clientset/versioned"
	"github.com/operator-framework/operator-sdk/pkg/status"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	azureproviderv1beta1 "sigs.k8s.io/cluster-api-provider-azure/pkg/apis/azureprovider/v1beta1"

	"github.com/Azure/ARO-RP/pkg/api"
	"github.com/Azure/ARO-RP/pkg/api/validate"
	arov1alpha1 "github.com/Azure/ARO-RP/pkg/operator/apis/aro.openshift.io/v1alpha1"
	aroclient "github.com/Azure/ARO-RP/pkg/operator/clientset/versioned"
	"github.com/Azure/ARO-RP/pkg/operator/controllers"
	"github.com/Azure/ARO-RP/pkg/util/aad"
	"github.com/Azure/ARO-RP/pkg/util/refreshable"
	"github.com/Azure/go-autorest/autorest/azure"
)

type ServicePrincipalChecker struct {
	log           *logrus.Entry
	clustercli    maoclient.Interface
	arocli        aroclient.Interface
	kubernetescli kubernetes.Interface
	role          string
}

type azureCredentials struct {
	clientID       string
	clientSecret   string
	tenantID       string
	subscriptionID string
}

type azureClaim struct {
	Roles []string `json:"roles,omitempty"`
}

func (*azureClaim) Valid() error {
	return fmt.Errorf("unimplemented")
}

func NewServicePrincipalChecker(log *logrus.Entry, arocli aroclient.Interface, maocli maoclient.Interface, kubernetescli kubernetes.Interface, role string) *ServicePrincipalChecker {
	return &ServicePrincipalChecker{
		log:           log,
		clustercli:    maocli,
		arocli:        arocli,
		kubernetescli: kubernetescli,
		role:          role,
	}
}

func getAzureCredentialSecret(ctx context.Context, kubernetescli kubernetes.Interface) (azureCredentials, error) {
	var azCreds azureCredentials

	secret, err := kubernetescli.CoreV1().Secrets(azureCredentialSecretNamespace).Get(ctx, azureCredentialSecretName, metav1.GetOptions{})
	if err != nil {
		return azCreds, err
	}

	clientIDBytes, ok := secret.Data["azure_client_id"]
	if !ok {
		return azCreds, errors.New("azure_client_id doesn't exist")
	}
	azCreds.clientID = string(clientIDBytes)

	clientSecretBytes, ok := secret.Data["azure_client_secret"]
	if !ok {
		return azCreds, errors.New("azure_client_secret doesn't exist")
	}
	azCreds.clientSecret = string(clientSecretBytes)

	tenantIDBytes, ok := secret.Data["azure_tenant_id"]
	if !ok {
		return azCreds, errors.New("azure_tenant_id doesn't exist")
	}
	azCreds.tenantID = string(tenantIDBytes)

	subscriptionBytes, ok := secret.Data["azure_subscription_id"]
	if !ok {
		return azCreds, errors.New("azure_subscription_id doesn't exist")
	}
	azCreds.subscriptionID = string(subscriptionBytes)

	return azCreds, nil
}

func getSubnetIDs(ctx context.Context, vnetID string, clustercli maoclient.Interface) (masterSubnetID string, workerSubnetIDs []string, err error) {

	machines, err := clustercli.MachineV1beta1().Machines(machineSetsNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return masterSubnetID, workerSubnetIDs, err
	}

	workerSubnetNames := map[string]bool{}

	for _, machine := range machines.Items {
		if machine.Spec.ProviderSpec.Value == nil {
			return masterSubnetID, workerSubnetIDs, fmt.Errorf("machine %s: provider spec missing", machine.Name)
		}

		o, _, err := scheme.Codecs.UniversalDeserializer().Decode(machine.Spec.ProviderSpec.Value.Raw, nil, nil)
		if err != nil {
			return masterSubnetID, workerSubnetIDs, err
		}

		machineProviderSpec, ok := o.(*azureproviderv1beta1.AzureMachineProviderSpec)
		if !ok {
			// This should never happen: codecs uses scheme that has only one registered type
			// and if something is wrong with the provider spec - decoding should fail
			return masterSubnetID, workerSubnetIDs, fmt.Errorf("machine %s: failed to read provider spec: %T", machine.Name, o)
		}

		isMaster, err := isMasterRole(&machine)
		if err != nil {
			return masterSubnetID, workerSubnetIDs, err
		}

		if isMaster {
			// Don't need to reset the name if it's already set
			if masterSubnetID == "" {
				masterSubnetID = vnetID + "/subnets/" + machineProviderSpec.Subnet
			}
		} else {
			workerSubnetNames[machineProviderSpec.Subnet] = true
		}
	}

	// Add unique worker subnet names
	for k := range workerSubnetNames {
		workerSubnetIDs = append(workerSubnetIDs, vnetID+"/subnets/"+k)
	}

	return masterSubnetID, workerSubnetIDs, err
}

func validateServicePrincipalProfile(ctx context.Context, log *logrus.Entry, env *azure.Environment, azCred azureCredentials) (refreshable.Authorizer, error) {
	log.Print("validateServicePrincipalProfile")

	spp := api.ServicePrincipalProfile{
		ClientID:     azCred.clientID,
		ClientSecret: api.SecureString(azCred.clientSecret),
	}

	token, err := aad.GetToken(ctx, log, spp, azCred.tenantID, env.ResourceManagerEndpoint)
	if err != nil {
		return nil, err
	}

	p := &jwt.Parser{}
	c := &azureClaim{}
	_, _, err = p.ParseUnverified(token.OAuthToken(), c)
	if err != nil {
		return nil, err
	}

	for _, role := range c.Roles {
		if role == "Application.ReadWrite.OwnedBy" {
			return nil, api.NewCloudError(http.StatusBadRequest, api.CloudErrorCodeInvalidServicePrincipalCredentials, "properties.servicePrincipalProfile", "The provided service principal must not have the Application.ReadWrite.OwnedBy permission.")
		}
	}

	return refreshable.NewAuthorizer(token), nil
}

func (r *ServicePrincipalChecker) servicePrincipalValid(ctx context.Context) error {
	cluster, err := r.arocli.AroV1alpha1().Clusters().Get(ctx, arov1alpha1.SingletonClusterName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	azEnv, err := azure.EnvironmentFromName(cluster.Spec.AZEnvironment)
	if err != nil {
		return err
	}

	azCred, err := getAzureCredentialSecret(ctx, r.kubernetescli)
	if err != nil {
		return err
	}

	masterSubnetID, workerSubnetIDs, err := getSubnetIDs(ctx, cluster.Spec.VnetID, r.clustercli)
	if err != nil {
		return err
	}

	authorizer, err := validateServicePrincipalProfile(ctx, r.log, &azEnv, azCred)
	if err != nil {
		return err
	}

	validator, err := validate.NewValidator(r.log, &azEnv, masterSubnetID, workerSubnetIDs, azCred.subscriptionID, authorizer)
	if err != nil {
		return err
	}

	err = validator.ValidateVnetPermissions(ctx, api.CloudErrorCodeInvalidServicePrincipalPermissions, "service principal")
	if err != nil {
		return err
	}

	return nil
}

func (r *ServicePrincipalChecker) Name() string {
	return "ServicePrincipalChecker"
}

func (r *ServicePrincipalChecker) Check(ctx context.Context) error {
	cond := &status.Condition{
		Type:    arov1alpha1.ServicePrincipalValid,
		Status:  corev1.ConditionTrue,
		Message: "service principal is valid",
		Reason:  "CheckDone",
	}

	err := r.servicePrincipalValid(ctx)
	if err != nil {
		cond.Status = corev1.ConditionFalse
		cond.Message = err.Error()
	}

	return controllers.SetCondition(ctx, r.arocli, cond, r.role)
}
