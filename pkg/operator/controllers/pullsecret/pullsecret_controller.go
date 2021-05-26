package pullsecret

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

// Image Registry pull-secret reconciler
// Users tend to do damage to corev1.Secret openshift-config/pull-secret
// this controllers ensures valid ARO secret for Azure mirror with
// openshift images
// It also signals presense of Red Hat image registry keys in a
// cluster.status.RedHatKeysPresent field.

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/Azure/ARO-RP/pkg/operator"
	arov1alpha1 "github.com/Azure/ARO-RP/pkg/operator/apis/aro.openshift.io/v1alpha1"
	aroclient "github.com/Azure/ARO-RP/pkg/operator/clientset/versioned"
	"github.com/Azure/ARO-RP/pkg/operator/controllers"
	"github.com/Azure/ARO-RP/pkg/util/pullsecret"
)

var pullSecretName = types.NamespacedName{Name: "pull-secret", Namespace: "openshift-config"}
var rhKeys = []string{"registry.redhat.io", "cloud.redhat.com", "registry.connect.redhat.com"}

// PullSecretReconciler reconciles a Cluster object
type PullSecretReconciler struct {
	kubernetescli kubernetes.Interface
	arocli        aroclient.Interface
	log           *logrus.Entry
}

func NewReconciler(log *logrus.Entry, kubernetescli kubernetes.Interface, arocli aroclient.Interface) *PullSecretReconciler {
	return &PullSecretReconciler{
		log:           log,
		kubernetescli: kubernetescli,
		arocli:        arocli,
	}
}

// Reconcile will make sure that the ACR part of the pull secret is correct. The
// conditions under which Reconcile is called are slightly unusual and are as
// follows:
// * If the Cluster object changes, we'll see the *Cluster* object requested.
// * If a Secret object owned by the Cluster object changes (e.g., but not
//   limited to, the configuration Secret, we'll see the *Cluster* object
//   requested).
// * If the pull Secret object (which is not owned by the Cluster object)
//   changes, we'll see the pull Secret object requested.
func (r *PullSecretReconciler) Reconcile(request ctrl.Request) (ctrl.Result, error) {
	// TODO(mj): Reconcile will eventually be receiving a ctx (https://github.com/kubernetes-sigs/controller-runtime/blob/7ef2da0bc161d823f084ad21ff5f9c9bd6b0cc39/pkg/reconcile/reconcile.go#L93)
	ctx := context.TODO()

	operatorSecret, err := r.kubernetescli.CoreV1().Secrets(operator.Namespace).Get(ctx, operator.SecretName, metav1.GetOptions{})
	if err != nil {
		return reconcile.Result{}, err
	}

	var userSecret *corev1.Secret

	// reconcile global pull secret
	// detects if the global pull secret is broken and fixes it by using backup managed by ARO operator
	userSecret, err = r.kubernetescli.CoreV1().Secrets(pullSecretName.Namespace).Get(ctx, pullSecretName.Name, metav1.GetOptions{})
	if err != nil && !kerrors.IsNotFound(err) {
		return reconcile.Result{}, err
	}

	// fix pull secret if its broken to have at least the ARO pull secret
	userSecret, err = r.ensureGlobalPullSecret(ctx, operatorSecret, userSecret)
	if err != nil {
		return reconcile.Result{}, err
	}

	// reconcile cluster status
	// update the following information:
	// - list of Red Hat pull-secret keys in status.
	cluster, err := r.arocli.AroV1alpha1().Clusters().Get(ctx, arov1alpha1.SingletonClusterName, metav1.GetOptions{})
	if err != nil {
		return reconcile.Result{}, err
	}

	cluster.Status.RedHatKeysPresent, err = r.parseRedHatKeys(userSecret)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.arocli.AroV1alpha1().Clusters().UpdateStatus(ctx, cluster, metav1.UpdateOptions{})
	return reconcile.Result{}, err
}

// SetupWithManager setup our manager
func (r *PullSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.log.Info("staring pull-secret controller")
	aroClusterPredicate := predicate.NewPredicateFuncs(func(meta metav1.Object, object runtime.Object) bool {
		return meta.GetName() == arov1alpha1.SingletonClusterName
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&arov1alpha1.Cluster{}, builder.WithPredicates(aroClusterPredicate)).
		Owns(&corev1.Secret{}).
		Named(controllers.PullSecretControllerName).
		Complete(r)
}

// ensureGlobalPullSecret checks the state of the pull secrets, in case of missing or broken ARO pull secret
// it replaces it with working one from controller Secret
// it takes care only for ARO pull secret, it does not touch the customer keys
func (r *PullSecretReconciler) ensureGlobalPullSecret(ctx context.Context, operatorSecret, userSecret *corev1.Secret) (secret *corev1.Secret, err error) {
	if operatorSecret == nil {
		return nil, errors.New("nil operator secret, cannot verify userData integrity")
	}

	recreate := false

	// if there is no userSecret, create new, or when
	// userSecret have broken type, recreates it with proper type
	// unfortunately the type field is immutable, therefore the whole secret have to be deleted and create once more
	if userSecret == nil || (userSecret.Type != corev1.SecretTypeDockerConfigJson || userSecret.Data == nil) {
		recreate = true
	}

	if recreate {
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pullSecretName.Name,
				Namespace: pullSecretName.Namespace,
			},
			Type: corev1.SecretTypeDockerConfigJson,
			Data: make(map[string][]byte),
		}
	} else {
		secret = userSecret.DeepCopy()
		if !json.Valid(secret.Data[corev1.DockerConfigJsonKey]) {
			delete(secret.Data, corev1.DockerConfigJsonKey)
		}
	}

	fixedData, update, err := pullsecret.Merge(string(secret.Data[corev1.DockerConfigJsonKey]), string(operatorSecret.Data[corev1.DockerConfigJsonKey]))
	if err != nil {
		return nil, err
	}

	// update is true for any case when ARO keys are fixed, meaning no need to double check for recreation
	if !update {
		return userSecret, nil
	}

	secret.Data[corev1.DockerConfigJsonKey] = []byte(fixedData)

	if recreate {
		// delete possible existing userSecret, calling deletion everytime and ignoring when secret not found
		// allows for simpler logic flow, when delete and create are not handled separately
		// this call happens only when there is a need to change, it has no significant impact on performance
		err := r.kubernetescli.CoreV1().Secrets(secret.Namespace).Delete(ctx, secret.Name, metav1.DeleteOptions{})
		if err != nil && !kerrors.IsNotFound(err) {
			return nil, err
		}

		return r.kubernetescli.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	}

	return r.kubernetescli.CoreV1().Secrets(secret.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
}

// parseRedHatKeys unmarshal and extract following RH keys from pull-secret:
//   - redhat.registry.io
//   - cloud.redhat.com
//   - registry.connect.redhat.com
// if present, return error when the parsing fail, which means broken secret
func (r *PullSecretReconciler) parseRedHatKeys(secret *corev1.Secret) (foundKeys []string, err error) {
	// parse keys and validate JSON
	parsedKeys, err := pullsecret.UnmarshalSecretData(secret)
	if err != nil {
		r.log.Info("pull secret is not valid json - recreating")
		return foundKeys, err
	}

	if parsedKeys != nil {
		for _, rhKey := range rhKeys {
			if v := parsedKeys[rhKey]; len(v) > 0 {
				foundKeys = append(foundKeys, rhKey)
			}
		}
	}

	return foundKeys, nil
}
