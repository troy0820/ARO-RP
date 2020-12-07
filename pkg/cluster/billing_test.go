package cluster

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/Azure/ARO-RP/pkg/api"
	mock_billing "github.com/Azure/ARO-RP/pkg/util/mocks/billing"
)

func TestEnsureBillingEntry(t *testing.T) {
	mockTenantID := "11111111-1111-1111-1111-111111111111"
	ctx := context.Background()

	for _, tt := range []struct {
		name    string
		mocks   func(*mock_billing.MockManager)
		wantErr string
	}{
		{
			name: "manager create is called and doesn't return an error when create doesn't return an error",
			mocks: func(billing *mock_billing.MockManager) {
				billing.EXPECT().
					Ensure(gomock.Any(), &api.OpenShiftClusterDocument{}, mockTenantID).
					Return(nil)
			},
		},
		{
			name: "manager create is called and returns an error on create returning an error",
			mocks: func(billing *mock_billing.MockManager) {
				billing.EXPECT().
					Ensure(gomock.Any(), &api.OpenShiftClusterDocument{}, mockTenantID).
					Return(errors.New("random error"))
			},
			wantErr: "random error",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()

			billing := mock_billing.NewMockManager(controller)
			tt.mocks(billing)

			m := &manager{
				doc:     &api.OpenShiftClusterDocument{},
				billing: billing,
			}

			err := m.ensureBillingRecord(ctx)
			t.Log("the error", err)
			if err != nil && err.Error() != tt.wantErr ||
				err == nil && tt.wantErr != "" {
				t.Error(err)
			}
		})
	}
}
