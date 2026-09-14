package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"freedom-cry/internal/probe"
)

type ProbeReportPayload struct {
	ProbeID       string              `json:"probe_id"`
	ProbeLocation string              `json:"probe_location"`
	Timestamp     time.Time           `json:"timestamp"`
	Results       []probe.ProbeResult `json:"results"`
}

func main() {
	masterURL := flag.String("master", "http://127.0.0.1:8080", "Freedom Cry Master API URL")
	probeID := flag.String("id", "ru-msk-sensor-1", "Probe Identifier")
	location := flag.String("location", "RU-Moscow", "Geographic location of sensor")
	secret := flag.String("secret", "fc-probe-shared-secret-2026", "Shared sensor authentication token")
	interval := flag.Duration("interval", 30*time.Second, "Probing interval")

	flag.Parse()

	log.Println("==================================================")
	log.Println("   🛰️ Freedom Cry - Censorship Probing Sensor     ")
	log.Println("==================================================")
	log.Printf("Sensor: %s | Location: %s | Target Master: %s", *probeID, *location, *masterURL)

	client := &http.Client{Timeout: 10 * time.Second}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	runProbeCycle := func() {
		// 1. Fetch active targets from Master
		req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/node/probe-targets", *masterURL), nil)
		if err != nil {
			log.Printf("[Probe] Error creating target request: %v", err)
			return
		}
		req.Header.Set("X-Probe-Secret", *secret)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[Probe] Failed to reach Master API: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("[Probe] Master returned status %d", resp.StatusCode)
			return
		}

		var targetsResponse struct {
			Targets []probe.NodeTarget `json:"targets"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&targetsResponse); err != nil {
			log.Printf("[Probe] Failed to decode targets: %v", err)
			return
		}

		if len(targetsResponse.Targets) == 0 {
			log.Println("[Probe] No active targets to probe")
			return
		}

		// 2. Perform probing on all targets
		var results []probe.ProbeResult
		for _, target := range targetsResponse.Targets {
			res := probe.ProbeVlessReality(target, 3*time.Second)
			results = append(results, res)

			if !res.IsReachable {
				log.Printf("🚨 [BLOCKED] Target %s (%s) unreachable: %s", target.NodeID, target.Host, res.Error)
			} else {
				log.Printf("✓ [OK] Target %s (%s) latency: %d ms", target.NodeID, target.Host, res.LatencyMs)
			}
		}

		// 3. Post probe report back to Master
		reportPayload := ProbeReportPayload{
			ProbeID:       *probeID,
			ProbeLocation: *location,
			Timestamp:     time.Now(),
			Results:       results,
		}

		data, _ := json.Marshal(reportPayload)
		postReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/node/probe-report", *masterURL), bytes.NewReader(data))
		if err == nil {
			postReq.Header.Set("Content-Type", "application/json")
			postReq.Header.Set("X-Probe-Secret", *secret)
			if postResp, err := client.Do(postReq); err == nil {
				_ = postResp.Body.Close()
				log.Printf("[Probe] Report successfully sent (%d results)", len(results))
			}
		}
	}

	// Run first probe immediately
	go runProbeCycle()

	for {
		select {
		case <-ticker.C:
			runProbeCycle()
		case sig := <-sigChan:
			log.Printf("Sensor received signal %v, shutting down...", sig)
			return
		}
	}
}
