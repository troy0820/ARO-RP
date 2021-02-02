package checker

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"errors"
	"net/http"

	"github.com/Azure/go-autorest/autorest/adal"
	jwt "github.com/form3tech-oss/jwt-go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/Azure/ARO-RP/pkg/api"
	"github.com/Azure/ARO-RP/pkg/api/validate"
	"github.com/Azure/ARO-RP/pkg/util/refreshable"
)

type credentials struct {
	clientID       []byte
	clientSecret   []byte
	tenantID       []byte
	subscriptionID []byte
}

func newAuthorizer(token *adal.ServicePrincipalToken) (refreshable.Authorizer, error) {
	p := &jwt.Parser{}
	c := &validate.AzureClaim{}
	_, _, err := p.ParseUnverified(token.OAuthToken(), c)
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

func azCredentials(ctx context.Context, kubernetescli kubernetes.Interface) (*credentials, error) {
	var creds credentials
	mysec, err := kubernetescli.CoreV1().Secrets(azureCredentialSecretNamespace).Get(ctx, azureCredentialSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if _, ok := mysec.Data["azure_client_id"]; !ok {
		return nil, errors.New("azure_client_id does not exist")
	}
	creds.clientID = mysec.Data["azure_client_id"]

	if _, ok := mysec.Data["azure_client_secret"]; !ok {
		return nil, errors.New("azure_client_secret does not exist")
	}
	creds.clientSecret = mysec.Data["azure_client_secret"]

	if _, ok := mysec.Data["azure_tenant_id"]; !ok {
		return nil, errors.New("azure_tenant_id does not exist")
	}
	creds.tenantID = mysec.Data["azure_tenant_id"]

	if _, ok := mysec.Data["azure_subscription_id"]; !ok {
		return nil, errors.New("azure_subscription_id does not exist")
	}
	creds.subscriptionID = mysec.Data["azure_subscription_id"]

	return &creds, nil
}
