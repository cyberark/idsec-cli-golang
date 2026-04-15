package featureadoption

import (
	"context"
	"testing"
	"time"
)

func TestBuildTags(t *testing.T) {
	t.Parallel()

	got := buildTags(&ReportOptions{
		ExtraTags: map[string]string{
			"cli_command": "exec",
			"":            "empty_key",
			"empty_value": "",
		},
	})

	if len(got) != 1 {
		t.Fatalf("expected 1 tag, got %d", len(got))
	}
	if got["cli_command"] != "exec" {
		t.Fatalf("expected cli_command=exec, got %q", got["cli_command"])
	}
}

func TestBuildCustomData(t *testing.T) {
	t.Parallel()

	duration := 1234 * time.Millisecond
	got := buildCustomData(&ReportOptions{
		OperationDuration: &duration,
		OperationStatus:   "failure",
		Message:           "some error",
	})

	if got["correlation_id"] == "" {
		t.Fatal("expected correlation_id to be set")
	}
	if got["duration"] != "1234" {
		t.Fatalf("expected duration=1234, got %#v", got["duration"])
	}
	if got["ops"] != "failure" {
		t.Fatalf("expected ops=failure, got %#v", got["ops"])
	}
	if got["message"] != "some error" {
		t.Fatalf("expected message=some error, got %#v", got["message"])
	}
}

func TestReportOperationDefer_NoPanic(t *testing.T) {
	t.Parallel()

	status := "success"
	message := ""
	tags := map[string]string{
		TagKeyCLIService:   "pcloud",
		TagKeyCLIOperation: "create",
		TagKeyCLIResource:  "safes",
		TagKeyCLIVersion:   "0.2.0",
	}
	done := ReportOperationDefer(context.Background(), nil, nil, &status, &message, tags)

	status = "failure"
	message = "failed execution"

	done()
}

func TestReportOperationDefer_NilTags(t *testing.T) {
	t.Parallel()

	status := "success"
	message := ""
	done := ReportOperationDefer(context.Background(), nil, nil, &status, &message, nil)
	done()
}
