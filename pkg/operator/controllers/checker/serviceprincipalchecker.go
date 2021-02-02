package checker

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"net/http"

	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/form3tech-oss/jwt-go"
	maoclient "github.com/openshift/machine-api-operator/pkg/generated/clientset/versioned"
	"github.com/operator-framework/operator-sdk/pkg/status"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/Azure/ARO-RP/pkg/api"
	"github.com/Azure/ARO-RP/pkg/api/validate"
	arov1alpha1 "github.com/Azure/ARO-RP/pkg/operator/apis/aro.openshift.io/v1alpha1"
	aroclient "github.com/Azure/ARO-RP/pkg/operator/clientset/versioned"
	"github.com/Azure/ARO-RP/pkg/operator/controllers"
	"github.com/Azure/ARO-RP/pkg/util/aad"
	"github.com/Azure/ARO-RP/pkg/util/refreshable"
)

type ServicePrincipalChecker struct {
	log           *logrus.Entry
	clustercli    maoclient.Interface
	arocli        aroclient.Interface
	kubernetescli kubernetes.Interface
	role          string
}

func NewServicePrincipalChecker(log *logrus.Entry, maocli maoclient.Interface, arocli aroclient.Interface, kubernetescli kubernetes.Interface, role string) *ServicePrincipalChecker {
	return &ServicePrincipalChecker{
		log:           log,
		clustercli:    maocli,
		arocli:        arocli,
		kubernetescli: kubernetescli,
		role:          role,
	}
}

func validateServicePrincipalProfile(ctx context.Context, log *logrus.Entry, env *azure.Environment, azCred *credentials) (refreshable.Authorizer, error) {
	log.Print("validateServicePrincipalProfile")

	token, err := aad.GetToken(ctx, log, string(azCred.clientID), api.SecureString(azCred.clientSecret), string(azCred.tenantID), env.ActiveDirectoryEndpoint, env.ResourceManagerEndpoint)
	if err != nil {
		return nil, err
	}

	p := &jwt.Parser{}
	c := &validate.AzureClaim{}
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

	azCred, err := azCredentials(ctx, r.kubernetescli)
	if err != nil {
		return err
	}

	authorizer, err := validateServicePrincipalProfile(ctx, r.log, &azEnv, azCred)
	if err != nil {
		return err
	}

	masterSubnetID, workerSubnetIDs, err := getSubnetIDs(ctx, cluster.Spec.VnetID, r.clustercli)
	if err != nil {
		return err
	}

	validator, err := validate.NewValidator(r.log, &azEnv, masterSubnetID, workerSubnetIDs, string(azCred.subscriptionID), authorizer)
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
