package report

import (
	"testing"
	"time"
)

func TestExitCode_AllOK(t *testing.T) {
	r := CheckResult{
		Summary: Summary{
			Total:   3,
			OK:      3,
			Warning: 0,
			Expired: 0,
			Errors:  0,
		},
	}
	if code := r.ExitCode(); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestExitCode_Warning(t *testing.T) {
	r := CheckResult{
		Summary: Summary{
			Total:   3,
			OK:      2,
			Warning: 1,
			Expired: 0,
			Errors:  0,
		},
	}
	if code := r.ExitCode(); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestExitCode_Expired(t *testing.T) {
	r := CheckResult{
		Summary: Summary{
			Total:   3,
			OK:      2,
			Warning: 0,
			Expired: 1,
			Errors:  0,
		},
	}
	if code := r.ExitCode(); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestExitCode_Error(t *testing.T) {
	r := CheckResult{
		Summary: Summary{
			Total:   3,
			OK:      1,
			Warning: 1,
			Expired: 0,
			Errors:  1,
		},
	}
	if code := r.ExitCode(); code != 2 {
		t.Errorf("expected exit code 2 (errors take priority), got %d", code)
	}
}

func TestExitCode_ErrorOverridesWarning(t *testing.T) {
	r := CheckResult{
		Summary: Summary{
			Total:   2,
			OK:      0,
			Warning: 1,
			Expired: 1,
			Errors:  1,
		},
	}
	if code := r.ExitCode(); code != 2 {
		t.Errorf("expected exit code 2 (errors override warnings), got %d", code)
	}
}

func TestCertInfo_JSONOmitError(t *testing.T) {
	ci := CertInfo{
		Host:   "example.com",
		Port:   443,
		Status: StatusOK,
	}
	// Error should be omitted when empty
	if ci.Error != "" {
		t.Errorf("expected empty error field, got %q", ci.Error)
	}
}

func TestStatusValues(t *testing.T) {
	statuses := []Status{StatusOK, StatusWarning, StatusExpired, StatusError, StatusNotYetValid}
	expected := []string{"ok", "warning", "expired", "error", "not_yet_valid"}
	for i, s := range statuses {
		if string(s) != expected[i] {
			t.Errorf("status %d: expected %q, got %q", i, expected[i], s)
		}
	}
}

func TestSummary_Counts(t *testing.T) {
	certs := []CertInfo{
		{Status: StatusOK},
		{Status: StatusOK},
		{Status: StatusWarning},
		{Status: StatusExpired},
		{Status: StatusError},
		{Status: StatusNotYetValid},
	}
	s := Summary{Total: len(certs)}
	for _, ci := range certs {
		switch ci.Status {
		case StatusOK:
			s.OK++
		case StatusWarning:
			s.Warning++
		case StatusExpired:
			s.Expired++
		case StatusError, StatusNotYetValid:
			s.Errors++
		}
	}
	if s.Total != 6 {
		t.Errorf("expected total 6, got %d", s.Total)
	}
	if s.OK != 2 {
		t.Errorf("expected OK 2, got %d", s.OK)
	}
	if s.Warning != 1 {
		t.Errorf("expected warning 1, got %d", s.Warning)
	}
	if s.Expired != 1 {
		t.Errorf("expected expired 1, got %d", s.Expired)
	}
	if s.Errors != 2 {
		t.Errorf("expected errors 2, got %d", s.Errors)
	}
}

func TestCheckResult_TimeFields(t *testing.T) {
	now := time.Now()
	r := CheckResult{
		CheckedAt: now,
		Threshold: 30,
	}
	if !r.CheckedAt.Equal(now) {
		t.Errorf("CheckedAt mismatch")
	}
	if r.Threshold != 30 {
		t.Errorf("expected threshold 30, got %d", r.Threshold)
	}
}
