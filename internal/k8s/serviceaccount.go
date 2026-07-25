package k8s

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// WO-6: serviceAccountRoleARNAnnotation is the positive IRSA observation source.
const serviceAccountRoleARNAnnotation = "eks.amazonaws.com/role-arn"

// ServiceAccountScanner audits workloads using the default service account
// and automountServiceAccountToken.
// WO-6: Add deterministic positive evidence collection without changing posture findings.
type ServiceAccountScanner struct {
	now func() time.Time // WO-6: inject read time for deterministic snapshot evidence.
}

// WO-6: serviceAccountEvidenceResult keeps findings and evidence as separate planes.
type serviceAccountEvidenceResult struct {
	Findings             []Finding             // WO-6: existing posture findings remain unchanged.
	ClusterPositiveEdges []ClusterPositiveEdge // WO-6: positive observations only.
	Coverage             []NamespaceCoverage   // WO-6: independently proven namespace scope.
	Errors               []string              // WO-6: partial collection failures remain visible.
	ResourcesScanned     int                   // WO-25: pods examined for posture, reported to the summary.
}

func (s *ServiceAccountScanner) Name() string { return "service-account" }

// WO-6: Preserve the original posture-only auditor contract for direct callers.
func (s *ServiceAccountScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	// WO-6: the public auditor contract retains its pre-evidence finding behavior.
	pods, _, err := s.listPods(ctx, client, cfg.Namespace)
	if err != nil {
		return nil, err
	}
	findings, _ := serviceAccountFindings(pods, cfg)
	return findings, nil
}

// WO-6: auditWithEvidence keeps positive evidence separate from existing posture findings.
func (s *ServiceAccountScanner) auditWithEvidence(
	ctx context.Context,
	client kubernetes.Interface,
	cfg AuditConfig,
) (*serviceAccountEvidenceResult, error) {
	pods, podsObservedAt, err := s.listPods(ctx, client, cfg.Namespace)
	if err != nil {
		return nil, err
	}

	findings, scanned := serviceAccountFindings(pods, cfg)
	result := &serviceAccountEvidenceResult{Findings: findings}
	result.ResourcesScanned = scanned // WO-33: report only pods examined post-exclusion.
	namespaces, discoveryErrors := namespacesForEvidence(ctx, client, cfg.Namespace, pods, cfg.Exclusions)
	result.Errors = append(result.Errors, discoveryErrors...)

	var annotationEdges, workloadEdges, podEdges []ClusterPositiveEdge
	for _, namespace := range namespaces {
		coverage, proveErr := ProveNamespaceCoverage(ctx, client, namespace)
		if proveErr != nil {
			result.Errors = append(result.Errors, proveErr.Error())
		}
		if coverage.State != NamespaceCoverageComplete {
			result.Coverage = append(result.Coverage, coverage)
			continue
		}

		serviceAccounts, listErr := client.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
		coverage.ObservedAt = s.nowUTC()
		if listErr != nil {
			// WO-6: SSAR permission cannot prove completeness when enumeration itself fails.
			coverage.State = NamespaceCoverageUnknown
			result.Errors = append(result.Errors, fmt.Sprintf("list serviceaccounts in namespace %q: %v", namespace, listErr))
			result.Coverage = append(result.Coverage, coverage)
			continue
		}

		annotationEdges = append(annotationEdges, serviceAccountAnnotationEdges(
			serviceAccounts.Items,
			cfg.Cluster,
			coverage.ObservedAt,
			cfg.Exclusions,
		)...)

		observedWorkloads, workloadErrors := s.collectWorkloadReferenceEdges(
			ctx,
			client,
			cfg.Cluster,
			namespace,
			cfg.Exclusions,
		)
		workloadEdges = append(workloadEdges, observedWorkloads...)
		result.Errors = append(result.Errors, workloadErrors...)

		podEdges = append(podEdges, podReferenceEdges(
			pods,
			cfg.Cluster,
			namespace,
			podsObservedAt,
			cfg.Exclusions,
		)...)
		result.Coverage = append(result.Coverage, coverage)
	}

	sortClusterPositiveEdges(annotationEdges)
	sortClusterPositiveEdges(workloadEdges)
	sortClusterPositiveEdges(podEdges)
	result.ClusterPositiveEdges = append(result.ClusterPositiveEdges, annotationEdges...)
	result.ClusterPositiveEdges = append(result.ClusterPositiveEdges, workloadEdges...)
	result.ClusterPositiveEdges = append(result.ClusterPositiveEdges, podEdges...)
	sort.Slice(result.Coverage, func(i, j int) bool {
		return result.Coverage[i].Namespace < result.Coverage[j].Namespace
	})
	return result, nil
}

// WO-6: listPods binds pod observations to their source-collection instant.
func (s *ServiceAccountScanner) listPods(
	ctx context.Context,
	client kubernetes.Interface,
	namespace string,
) ([]corev1.Pod, time.Time, error) {
	if client == nil {
		return nil, time.Time{}, errCoverageClientUnavailable
	}
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, time.Time{}, err
	}
	return pods.Items, s.nowUTC(), nil
}

// WO-6: nowUTC supplies deterministic UTC snapshot instants in tests and production.
func (s *ServiceAccountScanner) nowUTC() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// WO-6: serviceAccountFindings preserves the established posture plane during evidence collection.
func serviceAccountFindings(pods []corev1.Pod, cfg AuditConfig) ([]Finding, int) {
	var findings []Finding
	scanned := 0 // WO-33: count only pods that survive exclusion filtering.

	for _, pod := range pods {
		// WO-22: Enforce exclusions before producing ServiceAccount posture findings.
		if cfg.Exclusions.Matches(pod.Namespace, pod.Labels) {
			continue
		}
		scanned++
		saName := resolvedServiceAccountName(pod.Spec.ServiceAccountName)

		if saName == "default" {
			findings = append(findings, Finding{
				ID:           FindingDefaultServiceAccount,
				Severity:     SeverityMedium,
				ResourceType: "Pod",
				ResourceID:   pod.Name,
				Namespace:    pod.Namespace,
				Cluster:      cfg.Cluster,
				Message:      "pod uses the default service account",
			})
		}

		if shouldFlagAutomount(pod.Spec) {
			findings = append(findings, Finding{
				ID:           FindingAutomountToken,
				Severity:     SeverityMedium,
				ResourceType: "Pod",
				ResourceID:   pod.Name,
				Namespace:    pod.Namespace,
				Cluster:      cfg.Cluster,
				Message:      "pod has automountServiceAccountToken enabled",
			})
		}
	}

	return findings, scanned
}

// WO-6: namespacesForEvidence discovers candidates but never asserts their completeness.
func namespacesForEvidence(
	ctx context.Context,
	client kubernetes.Interface,
	configuredNamespace string,
	pods []corev1.Pod,
	exclusions Exclusions,
) ([]string, []string) {
	if configuredNamespace != "" {
		// WO-22: An excluded namespace has no evidence coverage entry.
		if exclusions.Matches(configuredNamespace, nil) {
			return nil, nil
		}
		return []string{configuredNamespace}, nil
	}

	set := make(map[string]struct{})
	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, namespace := range namespaces.Items {
			if namespace.Name != "" && !exclusions.Matches(namespace.Name, namespace.Labels) {
				set[namespace.Name] = struct{}{}
			}
		}
	} else {
		// WO-6: pod namespaces are candidates only; each still requires a definitive SSAR.
		for _, pod := range pods {
			if pod.Namespace != "" && !exclusions.Matches(pod.Namespace, nil) {
				set[pod.Namespace] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(set))
	for namespace := range set {
		result = append(result, namespace)
	}
	sort.Strings(result)
	if err != nil {
		return result, []string{fmt.Sprintf("list namespaces: %v", err)}
	}
	return result, nil
}

// WO-6: serviceAccountAnnotationEdges emits only concrete non-empty role observations.
func serviceAccountAnnotationEdges(
	serviceAccounts []corev1.ServiceAccount,
	cluster string,
	observedAt time.Time,
	exclusions Exclusions,
) []ClusterPositiveEdge {
	edges := make([]ClusterPositiveEdge, 0, len(serviceAccounts))
	for _, serviceAccount := range serviceAccounts {
		// WO-22: Excluded ServiceAccounts cannot become correlation evidence.
		if exclusions.Matches(serviceAccount.Namespace, serviceAccount.Labels) {
			continue
		}
		roleARN := strings.TrimSpace(serviceAccount.Annotations[serviceAccountRoleARNAnnotation])
		if roleARN == "" {
			continue
		}
		edge := NewServiceAccountRoleAnnotationObservedEdge(
			cluster,
			serviceAccount.Namespace,
			serviceAccount.Name,
			roleARN,
			observedAt,
		)
		if edge != nil {
			edges = append(edges, edge)
		}
	}
	return edges
}

// WO-6: collectWorkloadReferenceEdges emits only list-confirmed workload-to-SA references.
func (s *ServiceAccountScanner) collectWorkloadReferenceEdges(
	ctx context.Context,
	client kubernetes.Interface,
	cluster, namespace string,
	exclusions Exclusions,
) ([]ClusterPositiveEdge, []string) {
	var edges []ClusterPositiveEdge
	var collectionErrors []string

	deployments, err := client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	observedAt := s.nowUTC()
	if err != nil {
		collectionErrors = append(collectionErrors, fmt.Sprintf("list deployments in namespace %q: %v", namespace, err))
	} else {
		for _, workload := range deployments.Items {
			if exclusions.Matches(namespace, workload.Labels) {
				continue
			}
			edges = appendWorkloadReferenceEdge(edges, cluster, namespace, "Deployment", workload.Name, workload.Spec.Template.Spec, observedAt)
		}
	}

	statefulSets, err := client.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	observedAt = s.nowUTC()
	if err != nil {
		collectionErrors = append(collectionErrors, fmt.Sprintf("list statefulsets in namespace %q: %v", namespace, err))
	} else {
		for _, workload := range statefulSets.Items {
			if exclusions.Matches(namespace, workload.Labels) {
				continue
			}
			edges = appendWorkloadReferenceEdge(edges, cluster, namespace, "StatefulSet", workload.Name, workload.Spec.Template.Spec, observedAt)
		}
	}

	daemonSets, err := client.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	observedAt = s.nowUTC()
	if err != nil {
		collectionErrors = append(collectionErrors, fmt.Sprintf("list daemonsets in namespace %q: %v", namespace, err))
	} else {
		for _, workload := range daemonSets.Items {
			if exclusions.Matches(namespace, workload.Labels) {
				continue
			}
			edges = appendWorkloadReferenceEdge(edges, cluster, namespace, "DaemonSet", workload.Name, workload.Spec.Template.Spec, observedAt)
		}
	}

	jobs, err := client.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	observedAt = s.nowUTC()
	if err != nil {
		collectionErrors = append(collectionErrors, fmt.Sprintf("list jobs in namespace %q: %v", namespace, err))
	} else {
		for _, workload := range jobs.Items {
			if exclusions.Matches(namespace, workload.Labels) {
				continue
			}
			edges = appendWorkloadReferenceEdge(edges, cluster, namespace, "Job", workload.Name, workload.Spec.Template.Spec, observedAt)
		}
	}

	cronJobs, err := client.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
	observedAt = s.nowUTC()
	if err != nil {
		collectionErrors = append(collectionErrors, fmt.Sprintf("list cronjobs in namespace %q: %v", namespace, err))
	} else {
		for _, workload := range cronJobs.Items {
			if exclusions.Matches(namespace, workload.Labels) {
				continue
			}
			edges = appendWorkloadReferenceEdge(
				edges,
				cluster,
				namespace,
				"CronJob",
				workload.Name,
				workload.Spec.JobTemplate.Spec.Template.Spec,
				observedAt,
			)
		}
	}

	return edges, collectionErrors
}

// WO-6: appendWorkloadReferenceEdge drops incomplete workload observations structurally.
func appendWorkloadReferenceEdge(
	edges []ClusterPositiveEdge,
	cluster, namespace, kind, name string,
	podSpec corev1.PodSpec,
	observedAt time.Time,
) []ClusterPositiveEdge {
	edge := NewWorkloadReferenceObservedEdge(
		cluster,
		namespace,
		resolvedServiceAccountName(podSpec.ServiceAccountName),
		kind,
		name,
		observedAt,
	)
	if edge == nil {
		return edges
	}
	return append(edges, edge)
}

// WO-6: podReferenceEdges emits only pods observed in the proven namespace.
func podReferenceEdges(
	pods []corev1.Pod,
	cluster, namespace string,
	observedAt time.Time,
	exclusions Exclusions,
) []ClusterPositiveEdge {
	var edges []ClusterPositiveEdge
	for _, pod := range pods {
		// WO-22: Excluded pods cannot become correlation evidence.
		if pod.Namespace != namespace || exclusions.Matches(pod.Namespace, pod.Labels) {
			continue
		}
		edge := NewPodReferenceObservedEdge(
			cluster,
			namespace,
			resolvedServiceAccountName(pod.Spec.ServiceAccountName),
			pod.Name,
			observedAt,
		)
		if edge != nil {
			edges = append(edges, edge)
		}
	}
	return edges
}

// WO-6: sortClusterPositiveEdges makes the evidence artifact deterministic.
func sortClusterPositiveEdges(edges []ClusterPositiveEdge) {
	sort.Slice(edges, func(i, j int) bool {
		return clusterPositiveEdgeSortKey(edges[i]) < clusterPositiveEdgeSortKey(edges[j])
	})
}

// WO-6: clusterPositiveEdgeSortKey orders private identity without serializing it.
func clusterPositiveEdgeSortKey(edge ClusterPositiveEdge) string {
	key := edge.Cluster() + "\x00" + edge.Namespace() + "\x00" + edge.ServiceAccount() + "\x00"
	if roleARN, ok := ServiceAccountRoleAnnotationEvidence(edge); ok {
		return key + roleARN
	}
	if kind, name, ok := WorkloadReferenceEvidence(edge); ok {
		return key + kind + "\x00" + name
	}
	if podName, ok := PodReferenceEvidence(edge); ok {
		return key + podName
	}
	return key
}

// WO-6: resolvedServiceAccountName mirrors Kubernetes' empty-name default deterministically.
func resolvedServiceAccountName(name string) string {
	if name == "" {
		return "default"
	}
	return name
}

// shouldFlagAutomount returns true if the pod will automount a SA token.
// The pod-level field overrides the SA-level default. If the pod spec
// does not explicitly set it to false, the token is mounted.
func shouldFlagAutomount(spec corev1.PodSpec) bool {
	if spec.AutomountServiceAccountToken != nil {
		return *spec.AutomountServiceAccountToken
	}
	// Not explicitly set — defaults to true (token is mounted)
	return true
}
