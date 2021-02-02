package checker

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"fmt"

	maoclient "github.com/openshift/machine-api-operator/pkg/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	azureproviderv1beta1 "sigs.k8s.io/cluster-api-provider-azure/pkg/apis/azureprovider/v1beta1"
)

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
