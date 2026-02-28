package k8s

import "testing"

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev  Severity
		want int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{Severity("unknown"), 0},
	}

	for _, tt := range tests {
		got := SeverityRank(tt.sev)
		if got != tt.want {
			t.Errorf("SeverityRank(%q) = %d, want %d", tt.sev, got, tt.want)
		}
	}
}

func TestMeetsSeverityMin(t *testing.T) {
	tests := []struct {
		s, min Severity
		want   bool
	}{
		{SeverityCritical, SeverityLow, true},
		{SeverityCritical, SeverityCritical, true},
		{SeverityHigh, SeverityCritical, false},
		{SeverityLow, SeverityLow, true},
		{SeverityLow, SeverityMedium, false},
		{SeverityMedium, SeverityMedium, true},
	}

	for _, tt := range tests {
		got := MeetsSeverityMin(tt.s, tt.min)
		if got != tt.want {
			t.Errorf("MeetsSeverityMin(%q, %q) = %v, want %v", tt.s, tt.min, got, tt.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{"critical", SeverityCritical},
		{"high", SeverityHigh},
		{"medium", SeverityMedium},
		{"low", SeverityLow},
		{"", SeverityLow},
		{"invalid", SeverityLow},
	}

	for _, tt := range tests {
		got := ParseSeverity(tt.input)
		if got != tt.want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
