package k8s

import (
	"fmt"
	"strings"

	klabels "k8s.io/apimachinery/pkg/labels"
)

// WO-19: Exclusions is sealed runtime policy for exact namespaces and label selectors.
type Exclusions struct {
	namespaces map[string]struct{}
	selectors  []klabels.Selector
}

// WO-19: NewExclusions validates and copies operator input before scanners receive it.
func NewExclusions(namespaces, selectors []string) (Exclusions, error) {
	exclusions := Exclusions{
		namespaces: make(map[string]struct{}, len(namespaces)),
		selectors:  make([]klabels.Selector, 0, len(selectors)),
	}
	for _, namespace := range namespaces {
		namespace = strings.TrimSpace(namespace)
		if namespace != "" {
			exclusions.namespaces[namespace] = struct{}{}
		}
	}
	for _, expression := range selectors {
		expression = strings.TrimSpace(expression)
		if expression == "" {
			continue
		}
		selector, err := klabels.Parse(expression)
		if err != nil {
			return Exclusions{}, fmt.Errorf("parse exclusion label selector %q: %w", expression, err)
		}
		exclusions.selectors = append(exclusions.selectors, selector)
	}
	return exclusions, nil
}

// WO-19: Matches applies any-match exclusion semantics without exposing mutable policy.
func (e Exclusions) Matches(namespace string, resourceLabels map[string]string) bool {
	if _, ok := e.namespaces[namespace]; ok {
		return true
	}
	labelSet := klabels.Set(resourceLabels)
	for _, selector := range e.selectors {
		if selector.Matches(labelSet) {
			return true
		}
	}
	return false
}
