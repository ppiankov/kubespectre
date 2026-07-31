package k8s

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// WO-34: defaultManagedSecretMarkers are annotation-key prefixes recognized as
// controller-managed secret provenance, used when AuditConfig.ManagedSecretMarkers
// is empty. Age alone is not a risk signal for a secret a controller actively owns.
var defaultManagedSecretMarkers = []string{"cert-manager.io/", "external-secrets.io/"}

// SecretScanner audits secrets for staleness and unused mounts.
type SecretScanner struct{}

func (s *SecretScanner) Name() string { return "secret" }

func (s *SecretScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	// WO-25: preserve the posture-only contract; discard the scanned-object count.
	findings, _, err := s.auditWithCount(ctx, client, cfg)
	return findings, err
}

// WO-25: auditWithCount reports the secrets examined for lifecycle posture.
func (s *SecretScanner) auditWithCount(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, int, error) {
	var findings []Finding

	ns := cfg.Namespace

	// WO-50: paginated so a mid-stream network reset only costs one page,
	// not this auditor's entire finding set for the run.
	secrets, err := listSecretsPaged(ctx, client, ns)
	if err != nil {
		return nil, 0, fmt.Errorf("list secrets: %w", err)
	}

	// WO-48: same transient-retry treatment for the auxiliary pod-mount lookup.
	pods, err := retryTransient(ctx, func() (*corev1.PodList, error) {
		return client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	})
	if err != nil {
		return nil, 0, fmt.Errorf("list pods: %w", err)
	}

	mountedSecrets := buildMountedSecretSet(pods.Items)

	// WO-53: Ingress .spec.tls[].secretName is the standard, non-pod-mount
	// consumption path for kubernetes.io/tls secrets -- best-effort merge:
	// a failure to list Ingresses degrades to pod-only detection rather than
	// failing the whole auditor, since this is an additive signal.
	if ingresses, ingErr := retryTransient(ctx, func() (*networkingv1.IngressList, error) {
		return client.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
	}); ingErr == nil {
		for key := range buildIngressTLSSecretSet(ingresses.Items) {
			mountedSecrets[key] = true
		}
	}

	staleDays := cfg.StaleDays
	if staleDays <= 0 {
		staleDays = 90
	}
	staleThreshold := time.Now().AddDate(0, 0, -staleDays)

	managedMarkers := cfg.ManagedSecretMarkers
	if len(managedMarkers) == 0 {
		managedMarkers = defaultManagedSecretMarkers
	}

	scanned := 0 // WO-33: count only secrets that survive exclusion filtering.
	for _, secret := range secrets.Items {
		// WO-21: Enforce the operator boundary before producing secret findings.
		if cfg.Exclusions.Matches(secret.Namespace, secret.Labels) {
			continue
		}
		// WO-33: count secrets examined post-exclusion; the type/helm skips below
		// are finding heuristics, not exclusions, so those secrets still count.
		scanned++
		// Skip service account tokens and helm secrets
		if secret.Type == corev1.SecretTypeServiceAccountToken {
			continue
		}
		if isHelmSecret(secret) {
			continue
		}

		// WO-34/WO-37: age and pod-mount absence alone do not indicate risk for a
		// secret a recognized controller actively owns (e.g. cert-manager,
		// external-secrets) -- such secrets are commonly consumed via Ingress
		// tls.secretName or webhook caBundle injection, never a pod mount. Both
		// checks below down-rank rather than silently drop the finding, unless
		// the operator has disabled this recognition.
		managed := !cfg.DisableManagedSecretDownranking && isManagedSecret(secret, managedMarkers)

		// WO-52: use the most recent of creationTimestamp and any
		// managedFields[].time as the staleness clock -- creationTimestamp
		// alone never changes when a secret is updated in place (the normal
		// pattern for most secret-managing controllers, not just cert-manager/
		// external-secrets), so a secret actively rotated for years would
		// otherwise still report a stale, multi-year-old creation date.
		lastModified := secretEffectiveLastModified(secret)
		if lastModified.Before(staleThreshold) {
			severity := SeverityHigh
			message := fmt.Sprintf("secret not modified in %d+ days (threshold: %d days)", staleDays, staleDays)
			if managed {
				severity = SeverityMedium
				message = fmt.Sprintf("secret not modified in %d+ days (threshold: %d days); carries a recognized controller-managed marker, so age alone does not indicate an unrotated or forgotten credential", staleDays, staleDays)
			}
			findings = append(findings, Finding{
				ID:           FindingStaleSecret,
				Severity:     severity,
				ResourceType: "Secret",
				ResourceID:   secret.Name,
				Namespace:    secret.Namespace,
				Cluster:      cfg.Cluster,
				Message:      message,
				Metadata: map[string]any{
					"created":       secret.CreationTimestamp.Format(time.RFC3339),
					"last_modified": lastModified.Format(time.RFC3339),
					"managed":       managed,
				},
			})
		}

		// Check if secret is mounted by any pod
		key := secret.Namespace + "/" + secret.Name
		if !mountedSecrets[key] {
			severity := SeverityHigh
			message := "secret is not mounted by any pod"
			if managed {
				severity = SeverityMedium
				message = "secret is not mounted by any pod; carries a recognized controller-managed marker, so it may be consumed via a non-pod-mount path (e.g. Ingress TLS, webhook caBundle injection)"
			}
			findings = append(findings, Finding{
				ID:           FindingUnusedSecretMount,
				Severity:     severity,
				ResourceType: "Secret",
				ResourceID:   secret.Name,
				Namespace:    secret.Namespace,
				Cluster:      cfg.Cluster,
				Message:      message,
				Metadata:     map[string]any{"managed": managed},
			})
		}
	}

	// WO-33: report only secrets examined post-exclusion; pods remain auxiliary
	// mount context, not the scanned unit for this auditor.
	return findings, scanned, nil
}

// WO-50: secretListPageSize bounds each List call's response size. Empirically,
// 3 of 4 real clusters checked in the same session (all with >2600 total
// scanned resources) failed this exact call with a transient stream-reset
// error before pagination -- the single unbounded List's response size
// correlated directly with the failure rate. A 500-item page keeps each
// individual call small enough that a mid-stream reset only costs one page.
const secretListPageSize = 500

// WO-50: listSecretsPaged fetches every secret in ns across as many pages as
// needed, retrying only the page that failed (via retryTransient) rather than
// restarting the whole list from the beginning. This is what actually
// addresses the large-cluster failure mode WO-48's single-call retry could
// not: a transient reset mid-response no longer discards everything already
// fetched.
func listSecretsPaged(ctx context.Context, client kubernetes.Interface, ns string) (*corev1.SecretList, error) {
	var all corev1.SecretList
	continueToken := ""
	for {
		opts := metav1.ListOptions{Limit: secretListPageSize, Continue: continueToken}
		page, err := retryTransient(ctx, func() (*corev1.SecretList, error) {
			return client.CoreV1().Secrets(ns).List(ctx, opts)
		})
		if err != nil {
			return nil, err
		}
		all.Items = append(all.Items, page.Items...)
		if page.Continue == "" {
			return &all, nil
		}
		continueToken = page.Continue
	}
}

func buildMountedSecretSet(pods []corev1.Pod) map[string]bool {
	mounted := make(map[string]bool)
	for _, pod := range pods {
		for _, vol := range pod.Spec.Volumes {
			if vol.Secret != nil {
				key := pod.Namespace + "/" + vol.Secret.SecretName
				mounted[key] = true
			}
		}
		allContainers := append(pod.Spec.Containers, pod.Spec.InitContainers...)
		for _, c := range allContainers {
			for _, env := range c.EnvFrom {
				if env.SecretRef != nil {
					key := pod.Namespace + "/" + env.SecretRef.Name
					mounted[key] = true
				}
			}
			for _, env := range c.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					key := pod.Namespace + "/" + env.ValueFrom.SecretKeyRef.Name
					mounted[key] = true
				}
			}
		}
	}
	return mounted
}

// WO-53: buildIngressTLSSecretSet marks every secret referenced by an
// Ingress's spec.tls[].secretName as consumed -- the standard, non-pod-mount
// consumption path for kubernetes.io/tls secrets. Without this, a manually
// created or non-cert-manager-managed TLS secret used only by an Ingress
// produces a false "not mounted by any pod" finding.
func buildIngressTLSSecretSet(ingresses []networkingv1.Ingress) map[string]bool {
	referenced := make(map[string]bool)
	for _, ing := range ingresses {
		for _, tls := range ing.Spec.TLS {
			if tls.SecretName == "" {
				continue
			}
			referenced[ing.Namespace+"/"+tls.SecretName] = true
		}
	}
	return referenced
}

// WO-52: secretEffectiveLastModified returns the most recent signal of when
// this secret's content was last touched: the latest managedFields[].time if
// present (populated by the API server's field-management tracking on any
// update, not just an explicit server-side apply), or creationTimestamp if no
// managedFields entry carries a time. This avoids treating a secret that is
// actively updated in place as if it were forgotten just because its object
// was created long ago.
func secretEffectiveLastModified(secret corev1.Secret) time.Time {
	latest := secret.CreationTimestamp.Time
	for _, mf := range secret.ManagedFields {
		if mf.Time != nil && mf.Time.After(latest) {
			latest = mf.Time.Time
		}
	}
	return latest
}

func isHelmSecret(secret corev1.Secret) bool {
	return secret.Type == "helm.sh/release.v1"
}

// WO-34: isManagedSecret reports whether any annotation key on the secret
// starts with a recognized controller-managed marker prefix.
func isManagedSecret(secret corev1.Secret, markers []string) bool {
	for key := range secret.Annotations {
		for _, marker := range markers {
			if strings.HasPrefix(key, marker) {
				return true
			}
		}
	}
	return false
}
