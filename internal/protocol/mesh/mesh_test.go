package mesh

import (
	"strings"
	"testing"
)

func TestGenerateMeshConfig(t *testing.T) {
	psk, err := GeneratePresharedKey()
	if err != nil || len(psk) < 40 {
		t.Fatalf("GeneratePresharedKey failed: %v", err)
	}

	params := MeshConfigParams{
		PrivateKey: "privKey123=",
		Address:    "10.99.1.1/16",
		ListenPort: 51821,
		Peers: []MeshPeer{
			{
				PublicKey:    "pubKeyExit1=",
				Endpoint:     "exit1.freedomcry.net:51821",
				AllowedIPs:   "10.99.2.1/32, 0.0.0.0/0",
				PresharedKey: psk,
			},
		},
	}

	conf, err := GenerateMeshConfig(params)
	if err != nil {
		t.Fatalf("GenerateMeshConfig failed: %v", err)
	}

	expected := []string{
		"[Interface]",
		"PrivateKey = privKey123=",
		"Address = 10.99.1.1/16",
		"ListenPort = 51821",
		"[Peer]",
		"PublicKey = pubKeyExit1=",
		"PresharedKey = " + psk,
		"Endpoint = exit1.freedomcry.net:51821",
		"AllowedIPs = 10.99.2.1/32, 0.0.0.0/0",
	}

	for _, exp := range expected {
		if !strings.Contains(conf, exp) {
			t.Errorf("expected config to contain %q, got:\n%s", exp, conf)
		}
	}
}

func TestGenerateRoutingScripts(t *testing.T) {
	entryScript := GenerateEntryPolicyRoutingScript("eth0", "10.99.2.1")
	if !strings.Contains(entryScript, "0x99") || !strings.Contains(entryScript, "DROP") {
		t.Errorf("entry script missing fwmark or drop rule")
	}

	exitScript := GenerateExitNATScript("eth0")
	if !strings.Contains(exitScript, "MASQUERADE") || !strings.Contains(exitScript, "fc-mesh0") {
		t.Errorf("exit script missing MASQUERADE or fc-mesh0")
	}
}
