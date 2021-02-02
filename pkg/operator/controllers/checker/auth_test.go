package checker

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAZCredentials(t *testing.T) {
	newFakeSecretCli := func(s *v1.Secret) *fake.Clientset {
		s.ObjectMeta = metav1.ObjectMeta{
			Name:      azureCredentialSecretName,
			Namespace: azureCredentialSecretNamespace,
		}
		if s.Type == "" {
			s.Type = v1.SecretTypeOpaque
		}

		return fake.NewSimpleClientset(s)
	}

	tests := []struct {
		name    string
		fakecli *fake.Clientset
		wantErr bool
		want    *credentials
	}{
		{
			name:    "no secret exists",
			fakecli: fake.NewSimpleClientset(),
			wantErr: true,
		},
		{
			name: "no client id",
			fakecli: newFakeSecretCli(&v1.Secret{Data: map[string][]byte{
				"azure_client_secret":   []byte("super-secret-client-secret"),
				"azure_tenant_id":       []byte("tenant-id"),
				"azure_subscription_id": []byte("sub-id"),
			}}),
			wantErr: true,
		},
		{
			name: "no client secret",
			fakecli: newFakeSecretCli(&v1.Secret{Data: map[string][]byte{
				"azure_client_id":       []byte("client-id"),
				"azure_tenant_id":       []byte("tenant-id"),
				"azure_subscription_id": []byte("sub-id"),
			}}),
			wantErr: true,
		},
		{
			name: "no tenant-id",
			fakecli: newFakeSecretCli(&v1.Secret{Data: map[string][]byte{
				"azure_client_id":       []byte("client-id"),
				"azure_client_secret":   []byte("super-secret-client-secret"),
				"azure_subscription_id": []byte("sub-id"),
			}}),
			wantErr: true,
		},
		{
			name: "no sub id",
			fakecli: newFakeSecretCli(&v1.Secret{Data: map[string][]byte{
				"azure_client_id":     []byte("client-id"),
				"azure_client_secret": []byte("super-secret-client-secret"),
				"azure_tenant_id":     []byte("tenant-id"),
			}}),
			wantErr: true,
		},
		{
			name: "happy path",
			fakecli: newFakeSecretCli(&v1.Secret{Data: map[string][]byte{
				"azure_client_id":       []byte("client-id"),
				"azure_client_secret":   []byte("super-secret-client-secret"),
				"azure_tenant_id":       []byte("tenant-id"),
				"azure_subscription_id": []byte("sub-id"),
			}}),
			wantErr: false,
			want: &credentials{
				clientID:       []byte("client-id"),
				clientSecret:   []byte("super-secret-client-secret"),
				tenantID:       []byte("tenant-id"),
				subscriptionID: []byte("sub-id"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			azCred, err := azCredentials(context.Background(), tt.fakecli)
			if (err != nil) != tt.wantErr {
				t.Errorf("getAzureCredentials error %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if string(azCred.clientID) != string(tt.want.clientID) {
					t.Errorf("got: %v, want: %v", azCred.clientID, tt.want.clientID)
				}
				if string(azCred.clientSecret) != string(tt.want.clientSecret) {
					t.Errorf("got: %v, want: %v", azCred.clientSecret, tt.want.clientSecret)
				}
				if string(azCred.tenantID) != string(tt.want.tenantID) {
					t.Errorf("got: %v, want: %v", azCred.tenantID, tt.want.tenantID)
				}
				if string(azCred.subscriptionID) != string(tt.want.subscriptionID) {
					t.Errorf("got: %v, want: %v", azCred.subscriptionID, tt.want.subscriptionID)
				}
			}
		})
	}

}
