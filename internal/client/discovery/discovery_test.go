package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseTXTRecordNodes(t *testing.T) {
	txt := "v=fc1;nodes=198.51.100.1:443,198.51.100.2:8443;ttl=300"
	nodes := ParseTXTRecordNodes(txt)

	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	if nodes[0] != "198.51.100.1:443" || nodes[1] != "198.51.100.2:8443" {
		t.Fatalf("unexpected nodes: %v", nodes)
	}
}

func TestDiscoverFallbackEndpoints(t *testing.T) {
	// Mock DoH server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		qtype := r.URL.Query().Get("type")
		if name != "fallback.freedomcry.net" || qtype != "TXT" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/dns-json")
		fmt.Fprintf(w, `{
			"Status": 0,
			"Answer": [
				{
					"name": "fallback.freedomcry.net",
					"type": 16,
					"TTL": 300,
					"data": "\"v=fc1;nodes=1.2.3.4:443,5.6.7.8:8443\""
				}
			]
		}`)
	}))
	defer ts.Close()

	service := NewDiscoveryService([]string{ts.URL})
	endpoints, err := service.DiscoverFallbackEndpoints(context.Background(), "fallback.freedomcry.net")
	if err != nil {
		t.Fatalf("DiscoverFallbackEndpoints failed: %v", err)
	}

	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}
	if endpoints[0] != "1.2.3.4:443" || endpoints[1] != "5.6.7.8:8443" {
		t.Fatalf("unexpected endpoints: %v", endpoints)
	}
}
