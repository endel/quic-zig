package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	port := flag.Int("port", 4434, "server port")
	conns := flag.Int("c", 1, "number of connections (sequential)")
	reqs := flag.Int("n", 100, "requests per connection")
	flag.Parse()

	addr := fmt.Sprintf("https://localhost:%d/", *port)

	fmt.Printf("go-bench: %d conn × %d req → localhost:%d\n", *conns, *reqs, *port)

	totalRequests := *conns * *reqs
	latencies := make([]int64, 0, totalRequests)
	var mu sync.Mutex
	var totalBytes atomic.Int64
	var handshakeTotal int64
	var handshakesCompleted int32

	benchStart := time.Now()

	for c := 0; c < *conns; c++ {
		tr := &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h3"},
			},
			QUICConfig: &quic.Config{
				MaxIdleTimeout: 30 * time.Second,
			},
		}
		client := &http.Client{Transport: tr}

		hsStart := time.Now()
		// First request establishes connection (handshake)
		resp, err := client.Get(addr)
		if err != nil {
			fmt.Printf("  conn %d: handshake failed: %v\n", c, err)
			tr.Close()
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		hsEnd := time.Now()

		handshakeTotal += hsEnd.Sub(hsStart).Microseconds()
		handshakesCompleted++

		mu.Lock()
		latencies = append(latencies, hsEnd.Sub(hsStart).Nanoseconds())
		mu.Unlock()
		totalBytes.Add(int64(len(body)))

		// Remaining requests on same connection
		for r := 1; r < *reqs; r++ {
			reqStart := time.Now()
			resp, err := client.Get(addr)
			if err != nil {
				break
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			totalBytes.Add(int64(len(body)))
			lat := time.Since(reqStart).Nanoseconds()
			mu.Lock()
			latencies = append(latencies, lat)
			mu.Unlock()
		}

		tr.Close()
	}

	benchDuration := time.Since(benchStart)
	benchSec := benchDuration.Seconds()

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println("  go-bench results")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Printf("  Connections:    %d\n", *conns)
	fmt.Printf("  Requests/conn:  %d\n", *reqs)
	fmt.Printf("  Total requests: %d (%d completed)\n", totalRequests, len(latencies))
	fmt.Printf("  Total time:     %.2fs\n", benchSec)
	fmt.Println("───────────────────────────────────────────")

	if handshakesCompleted > 0 {
		avgHS := float64(handshakeTotal) / float64(handshakesCompleted)
		fmt.Printf("  Handshake avg:  %.0fµs\n", avgHS)
		fmt.Printf("  Handshakes/s:   %.0f\n", float64(handshakesCompleted)/benchSec)
	}

	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		n := len(latencies)
		p50 := latencies[n/2]
		p99 := latencies[min(n-1, n*99/100)]
		p999 := latencies[min(n-1, n*999/1000)]

		var sum int64
		for _, l := range latencies {
			sum += l
		}
		avg := float64(sum) / float64(n) / 1000.0

		rps := float64(n) / benchSec
		tput := float64(totalBytes.Load()) / benchSec / 1_048_576.0

		fmt.Printf("  Requests/s:     %.0f\n", rps)
		fmt.Printf("  Throughput:     %.2f MB/s\n", tput)
		fmt.Println("───────────────────────────────────────────")
		fmt.Println("  Latency (µs):")
		fmt.Printf("    min:   %.0f\n", float64(latencies[0])/1000.0)
		fmt.Printf("    avg:   %.0f\n", avg)
		fmt.Printf("    p50:   %.0f\n", float64(p50)/1000.0)
		fmt.Printf("    p99:   %.0f\n", float64(p99)/1000.0)
		fmt.Printf("    p99.9: %.0f\n", float64(p999)/1000.0)
		fmt.Printf("    max:   %.0f\n", float64(latencies[n-1])/1000.0)
	}
	fmt.Println("═══════════════════════════════════════════")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
