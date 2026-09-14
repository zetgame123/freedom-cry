package killswitch

import (
	"testing"
)

func TestStubKillSwitch(t *testing.T) {
	ks := &StubKillSwitch{}
	if ks.IsEnabled() {
		t.Fatal("expected killswitch to be disabled initially")
	}

	err := ks.Enable("1.2.3.4", 443, "tun0")
	if err != nil {
		t.Fatalf("unexpected error enabling: %v", err)
	}

	if !ks.IsEnabled() {
		t.Fatal("expected killswitch to be enabled")
	}

	err = ks.Disable()
	if err != nil {
		t.Fatalf("unexpected error disabling: %v", err)
	}

	if ks.IsEnabled() {
		t.Fatal("expected killswitch to be disabled")
	}
}

func TestLinuxKillSwitchValidation(t *testing.T) {
	ks := &LinuxKillSwitch{}

	// Test invalid params
	err := ks.Enable("", 443, "tun0")
	if err == nil {
		t.Fatal("expected error on empty server IP")
	}

	err = ks.Enable("1.2.3.4", 0, "tun0")
	if err == nil {
		t.Fatal("expected error on invalid server port")
	}
}
