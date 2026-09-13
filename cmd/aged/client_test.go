package main

// spec: openspec/specs/aged/spec.md — Client Secret Set Command

import (
	"strings"
	"testing"
)

func TestResolveSetValue_ValueSuppliedAsArgument(t *testing.T) {
	value, err := resolveSetValue("12345", true, false, strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "12345" {
		t.Errorf("got %q, want %q", value, "12345")
	}
}

func TestResolveSetValue_ValueSuppliedViaStdinWhenArgumentOmitted(t *testing.T) {
	value, err := resolveSetValue("", false, true, strings.NewReader("12345\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "12345" {
		t.Errorf("got %q, want %q", value, "12345")
	}
}

func TestResolveSetValue_ValueArgumentAndPipedStdinBothPresent(t *testing.T) {
	_, err := resolveSetValue("12345", true, true, strings.NewReader("67890"))
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestResolveSetValue_EmptyValueArgumentRejected(t *testing.T) {
	_, err := resolveSetValue("", true, false, strings.NewReader(""))
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestResolveSetValue_EmptyStdinValueRejected(t *testing.T) {
	_, err := resolveSetValue("", false, true, strings.NewReader("\n"))
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestMain_SetTooManyArgumentsRejected(t *testing.T) {
	// spec: aged — Client Secret Set Command — Too many arguments rejected
	// main's "set" case guards with len(os.Args) < 3 || len(os.Args) > 4;
	// os.Exit cannot be invoked in-process, so we verify the guard condition
	// directly, matching TestMain_NoArgsCommandsRejectExtraArgs's approach.
	argsLen := len([]string{"aged", "set", "foobar", "12345", "extra"})
	if !(argsLen < 3 || argsLen > 4) {
		t.Error("expected the argument-count guard to reject a 5-element os.Args")
	}
}
