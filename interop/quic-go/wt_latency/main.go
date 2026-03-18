package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

const defaultIterations = 50

func main() {
	addr := flag.String("addr", "localhost:4434", "server address")
	path := flag.String("path", "/", "WebTransport path")
	n := flag.Int("n", defaultIterations, "number of iterations")
	flag.Parse()
	iterations := *n

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetOutput(os.Stdout)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	d := webtransport.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
	}

	url := fmt.Sprintf("https://%s%s", *addr, *path)
	log.Printf("Connecting to %s", url)

	rsp, sess, err := d.Dial(ctx, url, nil)
	if err != nil {
		log.Fatalf("dial failed: %v", err)
	}
	defer func() {
		if rsp.Body != nil {
			io.ReadAll(rsp.Body)
			rsp.Body.Close()
		}
	}()
	log.Printf("Session established (status: %d)", rsp.StatusCode)

	// Warm up: one bidi + one datagram to prime the path
	warmupBidi(ctx, sess)
	warmupDatagram(ctx, sess)
	time.Sleep(50 * time.Millisecond)

	// --- Bidi stream latency ---
	bidiLatencies := make([]time.Duration, 0, iterations)
	log.Printf("\n--- Bidi Stream Latency (%d iterations) ---", iterations)
	for i := range iterations {
		lat, err := measureBidi(ctx, sess, i)
		if err != nil {
			log.Printf("  bidi #%02d: ERROR %v", i, err)
			continue
		}
		bidiLatencies = append(bidiLatencies, lat)
		if lat > 1*time.Millisecond {
			log.Printf("  SPIKE bidi #%04d: %v", i, lat)
		}
	}

	// --- Datagram latency ---
	dgLatencies := make([]time.Duration, 0, iterations)
	log.Printf("\n--- Datagram Latency (%d iterations) ---", iterations)
	for i := range iterations {
		lat, err := measureDatagram(ctx, sess, i)
		if err != nil {
			log.Printf("  dg   #%02d: ERROR %v", i, err)
			continue
		}
		dgLatencies = append(dgLatencies, lat)
		if lat > 1*time.Millisecond {
			log.Printf("  SPIKE dg   #%04d: %v", i, lat)
		}
	}

	sess.CloseWithError(0, "done")

	// --- Results ---
	fmt.Println()
	fmt.Println("========================================")
	fmt.Printf("  WebTransport Latency Results (%s)\n", *addr)
	fmt.Println("========================================")
	printStats("Bidi Stream", bidiLatencies)
	printStats("Datagram   ", dgLatencies)
	fmt.Println("========================================")
}

func measureBidi(ctx context.Context, sess *webtransport.Session, idx int) (time.Duration, error) {
	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		return 0, fmt.Errorf("open stream: %w", err)
	}

	msg := fmt.Sprintf("ping-%04d", idx)
	start := time.Now()

	_, err = stream.Write([]byte(msg))
	if err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}
	stream.Close() // send FIN so server's ReadAll completes

	data, err := io.ReadAll(stream)
	elapsed := time.Since(start)
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}

	expected := "Echo: " + msg
	if !strings.HasPrefix(string(data), expected) {
		return 0, fmt.Errorf("unexpected response: %q (want prefix %q)", string(data), expected)
	}

	return elapsed, nil
}

func measureDatagram(ctx context.Context, sess *webtransport.Session, idx int) (time.Duration, error) {
	msg := fmt.Sprintf("ping-%04d", idx)
	start := time.Now()

	err := sess.SendDatagram([]byte(msg))
	if err != nil {
		return 0, fmt.Errorf("send: %w", err)
	}

	rcvCtx, rcvCancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcvCancel()

	data, err := sess.ReceiveDatagram(rcvCtx)
	elapsed := time.Since(start)
	if err != nil {
		return 0, fmt.Errorf("receive: %w", err)
	}

	expected := "Echo: " + msg
	if !strings.HasPrefix(string(data), expected) {
		return 0, fmt.Errorf("unexpected response: %q (want prefix %q)", string(data), expected)
	}

	return elapsed, nil
}

func warmupBidi(ctx context.Context, sess *webtransport.Session) {
	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		return
	}
	stream.Write([]byte("warmup"))
	stream.Close()
	io.ReadAll(stream)
}

func warmupDatagram(ctx context.Context, sess *webtransport.Session) {
	sess.SendDatagram([]byte("warmup"))
	rcvCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	sess.ReceiveDatagram(rcvCtx)
}

func printStats(label string, latencies []time.Duration) {
	if len(latencies) == 0 {
		fmt.Printf("  %s: no successful measurements\n", label)
		return
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}
	avg := sum / time.Duration(len(latencies))

	var sumSq float64
	avgF := float64(avg)
	for _, l := range latencies {
		d := float64(l) - avgF
		sumSq += d * d
	}
	stddev := time.Duration(math.Sqrt(sumSq / float64(len(latencies))))

	p50 := percentile(latencies, 50)
	p95 := percentile(latencies, 95)
	p99 := percentile(latencies, 99)

	fmt.Printf("  %s: n=%d  avg=%-10s median=%-10s p95=%-10s p99=%-10s stddev=%-10s min=%-10s max=%s\n",
		label,
		len(latencies),
		avg.Truncate(time.Microsecond),
		p50.Truncate(time.Microsecond),
		p95.Truncate(time.Microsecond),
		p99.Truncate(time.Microsecond),
		stddev.Truncate(time.Microsecond),
		latencies[0].Truncate(time.Microsecond),
		latencies[len(latencies)-1].Truncate(time.Microsecond),
	)
}

func percentile(sorted []time.Duration, pct int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (pct * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
