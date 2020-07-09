package routefix

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	securityv1 "github.com/openshift/api/security/v1"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/Azure/ARO-RP/pkg/env"
	"github.com/Azure/ARO-RP/pkg/util/ensure"
)

const (
	kubeNamespace       = "openshift-azure-routefix"
	kubeServiceAccount  = "system:serviceaccount:" + kubeNamespace + ":default"
	routefixImageFormat = "%s.azurecr.io/routefix:c5c4a5db"
	shellScript         = `for ((;;))
do
  if ip route show cache | grep -q 'mtu 1450'; then
    ip route show cache
    ip route flush cache
  fi

  sleep 60
done`
)

type RouteFix interface {
	CreateOrUpdate(ctx context.Context) error
}

type routeFix struct {
	log     *logrus.Entry
	env     env.Interface
	ensurer ensure.Interface
}

func New(log *logrus.Entry, e env.Interface, ensurer ensure.Interface) RouteFix {
	return &routeFix{
		log:     log,
		env:     e,
		ensurer: ensurer,
	}
}

func (i *routeFix) routefixImage() string {
	return fmt.Sprintf(routefixImageFormat, i.env.ACRName())
}

func (i *routeFix) CreateOrUpdate(ctx context.Context) error {
	err := i.ensurer.Namespace(kubeNamespace)
	if err != nil {
		return err
	}

	i.log.Print("waiting for privileged security context constraint")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	var scc *securityv1.SecurityContextConstraints
	err = wait.PollImmediateUntil(10*time.Second, func() (bool, error) {
		var errx error
		scc, errx = i.ensurer.SccGet()
		return errx == nil, nil
	}, timeoutCtx.Done())

	if err != nil {
		return err
	}

	scc.ObjectMeta = metav1.ObjectMeta{
		Name: "privileged-routefix",
	}
	scc.Groups = nil
	scc.Users = []string{kubeServiceAccount}

	err = i.ensurer.SccCreate(scc)
	if err != nil {
		return err
	}

	return i.ensurer.DaemonSet(&appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "routefix",
			Namespace: kubeNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "routefix"},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "routefix"},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "routefix",
							Image: i.routefixImage(),
							Args: []string{
								"sh",
								"-c",
								shellScript,
							},
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									v1.ResourceCPU:    resource.MustParse("100m"),
									v1.ResourceMemory: resource.MustParse("200Mi"),
								},
								Requests: v1.ResourceList{
									v1.ResourceCPU:    resource.MustParse("100m"),
									v1.ResourceMemory: resource.MustParse("200Mi"),
								},
							},
							SecurityContext: &v1.SecurityContext{
								Privileged: to.BoolPtr(true),
							},
						},
					},
					HostNetwork: true,
					Tolerations: []v1.Toleration{
						{
							Effect:   v1.TaintEffectNoExecute,
							Operator: v1.TolerationOpExists,
						},
						{
							Effect:   v1.TaintEffectNoSchedule,
							Operator: v1.TolerationOpExists,
						},
					},
				},
			},
		},
	})
}
