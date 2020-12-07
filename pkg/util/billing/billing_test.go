package billing

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"

	"github.com/Azure/ARO-RP/pkg/api"
	"github.com/Azure/ARO-RP/pkg/util/deployment"
	mock_env "github.com/Azure/ARO-RP/pkg/util/mocks/env"
	testdatabase "github.com/Azure/ARO-RP/test/database"
)

func TestIsSubscriptionRegisteredForE2E(t *testing.T) {
	mockSubID := "11111111-1111-1111-1111-111111111111"
	for _, tt := range []struct {
		name string
		sub  api.SubscriptionProperties
		want bool
	}{
		{
			name: "empty",
		},
		{
			name: "sub without feature flag registered and not internal tenant",
			sub: api.SubscriptionProperties{
				TenantID: mockSubID,
				RegisteredFeatures: []api.RegisteredFeatureProfile{
					{
						Name:  "RandomFeature",
						State: "Registered",
					},
				},
			},
		},
		{
			name: "sub with feature flag registered and not internal tenant",
			sub: api.SubscriptionProperties{
				TenantID: mockSubID,
				RegisteredFeatures: []api.RegisteredFeatureProfile{
					{
						Name:  featureSaveAROTestConfig,
						State: "Registered",
					},
				},
			},
		},
		{
			name: "AME internal tenant and feature flag not registered",
			sub: api.SubscriptionProperties{
				TenantID: tenantIDAME,
				RegisteredFeatures: []api.RegisteredFeatureProfile{
					{
						Name:  "RandomFeature",
						State: "Registered",
					},
				},
			},
		},
		{
			name: "MSFT internal tenant and feature flag not registered",
			sub: api.SubscriptionProperties{
				TenantID: tenantIDMSFT,
				RegisteredFeatures: []api.RegisteredFeatureProfile{
					{
						Name:  "RandomFeature",
						State: "Registered",
					},
				},
			},
		},
		{
			name: "AME internal tenant and feature flag registered",
			sub: api.SubscriptionProperties{
				TenantID: tenantIDAME,
				RegisteredFeatures: []api.RegisteredFeatureProfile{
					{
						Name:  featureSaveAROTestConfig,
						State: "Registered",
					},
				},
			},
			want: true,
		},
		{
			name: "MSFT internal tenant and feature flag registered",
			sub: api.SubscriptionProperties{
				TenantID: tenantIDMSFT,
				RegisteredFeatures: []api.RegisteredFeatureProfile{
					{
						Name:  featureSaveAROTestConfig,
						State: "Registered",
					},
				},
			},
			want: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := isSubscriptionRegisteredForE2E(&tt.sub)
			if got != tt.want {
				t.Error(got)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	mockSubID := "11111111-1111-1111-1111-111111111111"
	mockTenantID := mockSubID
	location := "eastus"

	type test struct {
		name          string
		fixture       func(*testdatabase.Fixture)
		wantDocuments func(*testdatabase.Checker)
		dbError       error
		wantErr       string
	}

	// Can't add tests for billing storage because there isn't an interface on
	// the azure storage clients.

	for _, tt := range []*test{
		{
			name: "successful mark for deletion on billing entity, with a subscription not registered for e2e",
			fixture: func(f *testdatabase.Fixture) {
				f.AddBillingDocuments(&api.BillingDocument{
					Key:                       strings.ToLower(testdatabase.GetResourcePath(mockSubID, "resourceName")),
					ClusterResourceGroupIDKey: fmt.Sprintf("/subscriptions/%s/resourcegroups/resourceGroup", mockSubID),
					ID:                        mockSubID,
					Billing: &api.Billing{
						TenantID: mockTenantID,
						Location: location,
					},
				})
			},
			wantDocuments: func(c *testdatabase.Checker) {
				c.AddBillingDocuments(&api.BillingDocument{
					Key:                       strings.ToLower(testdatabase.GetResourcePath(mockSubID, "resourceName")),
					ClusterResourceGroupIDKey: fmt.Sprintf("/subscriptions/%s/resourcegroups/resourceGroup", mockSubID),
					ID:                        mockSubID,
					Billing: &api.Billing{
						TenantID:     mockTenantID,
						Location:     location,
						DeletionTime: 1,
					},
				})
			},
		},
		{
			name: "no error on mark for deletion on billing entry that is not found",
			fixture: func(f *testdatabase.Fixture) {
				f.AddOpenShiftClusterDocuments(&api.OpenShiftClusterDocument{
					Key:                       strings.ToLower(testdatabase.GetResourcePath(mockSubID, "resourceName")),
					ClusterResourceGroupIDKey: fmt.Sprintf("/subscriptions/%s/resourcegroups/resourceGroup", mockSubID),
					ID:                        mockSubID,
					OpenShiftCluster: &api.OpenShiftCluster{
						Properties: api.OpenShiftClusterProperties{
							ServicePrincipalProfile: api.ServicePrincipalProfile{},
						},
						Location: location,
					},
				})
			},
		},
		{
			name: "error on mark for deletion on billing entry",
			fixture: func(f *testdatabase.Fixture) {
				f.AddOpenShiftClusterDocuments(&api.OpenShiftClusterDocument{
					Key:                       strings.ToLower(testdatabase.GetResourcePath(mockSubID, "resourceName")),
					ClusterResourceGroupIDKey: fmt.Sprintf("/subscriptions/%s/resourcegroups/resourceGroup", mockSubID),
					ID:                        mockSubID,
					OpenShiftCluster: &api.OpenShiftCluster{
						Properties: api.OpenShiftClusterProperties{
							ServicePrincipalProfile: api.ServicePrincipalProfile{},
						},
						Location: location,
					},
				})
			},
			dbError: errors.New("random error"),
			wantErr: "random error",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			controller := gomock.NewController(t)
			defer controller.Finish()

			_env := mock_env.NewMockInterface(controller)
			_env.EXPECT().DeploymentMode().AnyTimes().Return(deployment.Production)

			log := logrus.NewEntry(logrus.StandardLogger())
			openShiftClusterDatabase, _ := testdatabase.NewFakeOpenShiftClusters()
			billingDatabase, billingClient := testdatabase.NewFakeBilling()
			subscriptionsDatabase, _ := testdatabase.NewFakeSubscriptions()

			if tt.fixture != nil {
				fixture := testdatabase.NewFixture().
					WithOpenShiftClusters(openShiftClusterDatabase).
					WithBilling(billingDatabase).
					WithSubscriptions(subscriptionsDatabase)
				tt.fixture(fixture)
				err = fixture.Create()
				if err != nil {
					t.Fatal(err)
				}
			}

			if tt.dbError != nil {
				billingClient.SetError(tt.dbError)
			}

			m := &manager{
				log:       log,
				billingDB: billingDatabase,
				subDB:     subscriptionsDatabase,
				env:       _env,
			}

			err = m.Delete(ctx, &api.OpenShiftClusterDocument{ID: mockSubID})
			if err != nil && err.Error() != tt.wantErr ||
				err == nil && tt.wantErr != "" {
				t.Error(err)
			}

			if tt.wantDocuments != nil {
				checker := testdatabase.NewChecker()
				tt.wantDocuments(checker)
				errs := checker.CheckBilling(billingClient)
				for _, err := range errs {
					t.Error(err)
				}
			}
		})
	}
}

func TestEnsure(t *testing.T) {
	ctx := context.Background()
	mockSubID := "11111111-1111-1111-1111-111111111111"
	mockTenantID := mockSubID
	mockInfraID := "infra"
	location := "eastus"

	type test struct {
		name          string
		fixture       func(*testdatabase.Fixture)
		wantDocuments func(*testdatabase.Checker)
		dbError       error
		wantErr       string
	}

	// Can't add tests for billing storage because there isn't an interface on
	// the azure storage clients.

	for _, tt := range []*test{
		{
			name: "create a new billing entry with a subscription not registered for e2e",
			fixture: func(f *testdatabase.Fixture) {
				f.AddOpenShiftClusterDocuments(&api.OpenShiftClusterDocument{
					Key:                       strings.ToLower(testdatabase.GetResourcePath(mockSubID, "resourceName")),
					ClusterResourceGroupIDKey: fmt.Sprintf("/subscriptions/%s/resourcegroups/resourceGroup", mockSubID),
					ID:                        mockSubID,
					OpenShiftCluster: &api.OpenShiftCluster{
						Properties: api.OpenShiftClusterProperties{
							ServicePrincipalProfile: api.ServicePrincipalProfile{},
							InfraID:                 mockInfraID,
						},
						Location: location,
					},
				})
				f.AddSubscriptionDocuments(&api.SubscriptionDocument{
					Subscription: &api.Subscription{
						Properties: &api.SubscriptionProperties{
							RegisteredFeatures: []api.RegisteredFeatureProfile{
								{
									Name:  featureSaveAROTestConfig,
									State: "NotRegistered",
								},
							},
							TenantID: mockSubID,
						},
					},
				})
			},
			wantDocuments: func(c *testdatabase.Checker) {
				c.AddBillingDocuments(&api.BillingDocument{
					Key:                       strings.ToLower(testdatabase.GetResourcePath(mockSubID, "resourceName")),
					ClusterResourceGroupIDKey: fmt.Sprintf("/subscriptions/%s/resourcegroups/resourceGroup", mockSubID),
					ID:                        mockSubID,
					Billing: &api.Billing{
						TenantID: mockTenantID,
						Location: location,
					},
					InfraID: mockInfraID,
				})
			},
		},
		{
			name: "error on create a new billing entry",
			fixture: func(f *testdatabase.Fixture) {
				f.AddOpenShiftClusterDocuments(&api.OpenShiftClusterDocument{
					Key:                       strings.ToLower(testdatabase.GetResourcePath(mockSubID, "resourceName")),
					ClusterResourceGroupIDKey: fmt.Sprintf("/subscriptions/%s/resourcegroups/resourceGroup", mockSubID),
					ID:                        mockSubID,
					OpenShiftCluster: &api.OpenShiftCluster{
						Properties: api.OpenShiftClusterProperties{
							ServicePrincipalProfile: api.ServicePrincipalProfile{},
							InfraID:                 mockInfraID,
						},
						Location: location,
					},
				})
				f.AddSubscriptionDocuments(&api.SubscriptionDocument{
					Subscription: &api.Subscription{
						Properties: &api.SubscriptionProperties{
							RegisteredFeatures: []api.RegisteredFeatureProfile{
								{
									Name:  featureSaveAROTestConfig,
									State: "NotRegistered",
								},
							},
							TenantID: mockSubID,
						},
					},
				})
			},
			dbError: errors.New("random error"),
			wantErr: "random error",
		},
		{
			name: "billing document already existing on DB on create",
			fixture: func(f *testdatabase.Fixture) {
				f.AddOpenShiftClusterDocuments(&api.OpenShiftClusterDocument{
					Key:                       strings.ToLower(testdatabase.GetResourcePath(mockSubID, "resourceName")),
					ClusterResourceGroupIDKey: fmt.Sprintf("/subscriptions/%s/resourcegroups/resourceGroup", mockSubID),
					ID:                        mockSubID,
					OpenShiftCluster: &api.OpenShiftCluster{
						Properties: api.OpenShiftClusterProperties{
							ServicePrincipalProfile: api.ServicePrincipalProfile{},
							InfraID:                 mockInfraID,
						},
						Location: location,
					},
				})
				f.AddSubscriptionDocuments(&api.SubscriptionDocument{
					Subscription: &api.Subscription{
						Properties: &api.SubscriptionProperties{
							RegisteredFeatures: []api.RegisteredFeatureProfile{
								{
									Name:  featureSaveAROTestConfig,
									State: "NotRegistered",
								},
							},
							TenantID: mockSubID,
						},
					},
				})
				f.AddBillingDocuments(&api.BillingDocument{
					Key:                       testdatabase.GetResourcePath(mockSubID, "resourceName"),
					ClusterResourceGroupIDKey: fmt.Sprintf("/subscriptions/%s/resourcegroups/resourceGroup", mockSubID),
					ID:                        mockSubID,
					Billing: &api.Billing{
						TenantID: mockTenantID,
						Location: location,
					},
					InfraID: mockInfraID,
				})
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			controller := gomock.NewController(t)
			defer controller.Finish()

			_env := mock_env.NewMockInterface(controller)
			_env.EXPECT().DeploymentMode().AnyTimes().Return(deployment.Production)

			log := logrus.NewEntry(logrus.StandardLogger())
			openShiftClusterDatabase, _ := testdatabase.NewFakeOpenShiftClusters()
			billingDatabase, billingClient := testdatabase.NewFakeBilling()
			subscriptionsDatabase, _ := testdatabase.NewFakeSubscriptions()

			if tt.fixture != nil {
				fixture := testdatabase.NewFixture().
					WithOpenShiftClusters(openShiftClusterDatabase).
					WithBilling(billingDatabase).
					WithSubscriptions(subscriptionsDatabase)
				tt.fixture(fixture)
				err = fixture.Create()
				if err != nil {
					t.Fatal(err)
				}
			}

			if tt.dbError != nil {
				billingClient.SetError(tt.dbError)
			}

			m := &manager{
				log:       log,
				billingDB: billingDatabase,
				subDB:     subscriptionsDatabase,
				env:       _env,
			}

			doc, err := openShiftClusterDatabase.Get(ctx, strings.ToLower(testdatabase.GetResourcePath(mockSubID, "resourceName")))
			if err != nil {
				t.Fatal(err)
			}
			if err != nil {
				t.Fatal(err)
			}

			err = m.Ensure(ctx, doc, mockSubID)
			if err != nil && err.Error() != tt.wantErr ||
				err == nil && tt.wantErr != "" {
				t.Error(err)
			}

			if tt.wantDocuments != nil {
				checker := testdatabase.NewChecker()
				tt.wantDocuments(checker)
				errs := checker.CheckBilling(billingClient)
				for _, err := range errs {
					t.Error(err)
				}
			}
		})
	}
}
