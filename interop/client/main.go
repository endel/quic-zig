package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	addr := flag.String("addr", "localhost:4433", "server address to connect to")
	alpn := flag.String("alpn", "h3", "ALPN protocol")
	message := flag.String("msg", "hello from quic-go client", "message to send")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetOutput(os.Stdout)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{*alpn},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	log.Printf("connecting to %s (ALPN: %s)", *addr, *alpn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, *addr, tlsConf, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	log.Printf("connection established (negotiated protocol: %s)", conn.ConnectionState().TLS.NegotiatedProtocol)

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("failed to open stream: %v", err)
	}
	log.Printf("opened bidirectional stream %d", stream.StreamID())

	_, err = stream.Write([]byte(*message))
	if err != nil {
		log.Fatalf("failed to write: %v", err)
	}
	log.Printf("sent: %q", *message)

	// Close write side to signal we're done sending
	stream.Close()

	// Read response
	resp, err := io.ReadAll(stream)
	if err != nil {
		log.Fatalf("failed to read response: %v", err)
	}
	log.Printf("received: %q", string(resp))

	fmt.Println("OK")
}
