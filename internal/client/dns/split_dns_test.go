package dns

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSplitDNS_IsDomestic(t *testing.T) {
	resolver := NewSplitDNSResolver("")

	if !resolver.IsDomestic("gosuslugi.ru") {
		t.Fatalf("expected gosuslugi.ru to be domestic")
	}
	if !resolver.IsDomestic("yandex.ru") {
		t.Fatalf("expected yandex.ru to be domestic")
	}
	if !resolver.IsDomestic("sub.sberbank.ru") {
		t.Fatalf("expected sub.sberbank.ru to be domestic")
	}
	if resolver.IsDomestic("instagram.com") {
		t.Fatalf("expected instagram.com to NOT be domestic")
	}
	if resolver.IsDomestic("rutracker.org") {
		t.Fatalf("expected rutracker.org to NOT be domestic")
	}
}

func TestSplitDNS_ResolveDoH(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name != "blocked-site.org" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/dns-json")
		fmt.Fprintf(w, `{
			"Status": 0,
			"Answer": [
				{
					"name": "blocked-site.org",
					"type": 1,
					"TTL": 300,
					"data": "104.21.45.67"
				}
			]
		}`)
	}))
	defer ts.Close()

	resolver := NewSplitDNSResolver(ts.URL)
	ips, err := resolver.ResolveHost(context.Background(), "blocked-site.org")
	if err != nil {
		t.Fatalf("ResolveHost failed: %v", err)
	}

	if len(ips) != 1 || ips[0].String() != "104.21.45.67" {
		t.Fatalf("expected 104.21.45.67, got %v", ips)
	}

	// Verify cached
	cachedIPs, err := resolver.ResolveHost(context.Background(), "blocked-site.org")
	if err != nil || len(cachedIPs) != 1 || cachedIPs[0].String() != "104.21.45.67" {
		t.Fatalf("cache lookup failed")
	}
}
