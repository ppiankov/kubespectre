package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

// Generate writes human-readable terminal output.
func (r *TextReporter) Generate(data Data) error {
	tw := tabwriter.NewWriter(r.Writer, 0, 4, 2, ' ', 0)
	w := &errWriter{w: r.Writer}

	w.println("kubespectre — Kubernetes Security Posture Report")
	w.println(strings.Repeat("=", 49))
	w.println("")

	if len(data.Findings) == 0 {
		w.println("No security issues found.")
		w.println("")
		writeTextSummary(w, data)
		return w.err
	}

	w.printf("Found %d security issues\n\n", data.Summary.TotalFindings)

	tw2 := &errWriter{w: tw}
	tw2.printf("SEVERITY\tTYPE\tRESOURCE\tNAMESPACE\tFINDING\tMESSAGE\n")
	tw2.printf("--------\t----\t--------\t---------\t-------\t-------\n")

	for _, f := range data.Findings {
		ns := f.Namespace
		if ns == "" {
			ns = "(cluster)"
		}
		tw2.printf("%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Severity, f.ResourceType, f.ResourceID, ns, f.ID, f.Message)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	w.println("")
	writeTextSummary(w, data)
	return w.err
}

func writeTextSummary(w *errWriter, data Data) {
	w.println("Summary")
	w.println("-------")
	w.printf("Resources scanned:  %d\n", data.Summary.TotalResourcesScanned)
	w.printf("Total findings:     %d\n", data.Summary.TotalFindings)

	if len(data.Summary.BySeverity) > 0 {
		parts := formatMapSorted(data.Summary.BySeverity)
		w.printf("By severity:        %s\n", strings.Join(parts, ", "))
	}
	if len(data.Summary.ByResourceType) > 0 {
		parts := formatMapSorted(data.Summary.ByResourceType)
		w.printf("By resource type:   %s\n", strings.Join(parts, ", "))
	}

	if len(data.Errors) > 0 {
		w.printf("\nWarnings (%d):\n", len(data.Errors))
		for _, e := range data.Errors {
			w.printf("  - %s\n", e)
		}
	}
}

type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

func (ew *errWriter) println(s string) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintln(ew.w, s)
}

func formatMapSorted(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return parts
}
