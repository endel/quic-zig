package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"

	"github.com/quic-go/quic-go"
)

func main() {
	addr := flag.String("addr", "localhost:4434", "address to listen on")
	alpn := flag.String("alpn", "h3", "ALPN protocol")
	certFile := flag.String("cert", "", "TLS certificate file (default: interop/certs/server.crt)")
	keyFile := flag.String("key", "", "TLS private key file (default: interop/certs/server.key)")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetOutput(os.Stdout)

	// Default cert paths relative to this source file's directory
	if *certFile == "" || *keyFile == "" {
		_, thisFile, _, _ := runtime.Caller(0)
		interopDir := filepath.Dir(filepath.Dir(thisFile))
		if *certFile == "" {
			*certFile = filepath.Join(interopDir, "certs", "server.crt")
		}
		if *keyFile == "" {
			*keyFile = filepath.Join(interopDir, "certs", "server.key")
		}
	}

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("failed to load TLS certificate: %v\n  cert: %s\n  key: %s", err, *certFile, *keyFile)
	}
	log.Printf("loaded TLS certificate from %s", *certFile)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{*alpn},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	listener, err := quic.ListenAddr(*addr, tlsConf, &quic.Config{})
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("listening on %s (ALPN: %s)", *addr, *alpn)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		<-ctx.Done()
		log.Println("shutting down...")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			if ctx.Err() != nil {
				return // clean shutdown
			}
			log.Printf("accept error: %v", err)
			continue
		}
		log.Printf("accepted connection from %s", conn.RemoteAddr())
		go handleConnection(conn)
	}
}

func handleConnection(conn *quic.Conn) {
	defer conn.CloseWithError(0, "done")

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("[%s] accept stream error: %v", conn.RemoteAddr(), err)
			return
		}
		go handleStream(conn, stream)
	}
}

func handleStream(conn *quic.Conn, stream *quic.Stream) {
	log.Printf("[%s] accepted stream %d", conn.RemoteAddr(), stream.StreamID())

	data, err := io.ReadAll(stream)
	if err != nil {
		log.Printf("[%s] stream %d read error: %v", conn.RemoteAddr(), stream.StreamID(), err)
		return
	}
	log.Printf("[%s] stream %d received: %q", conn.RemoteAddr(), stream.StreamID(), string(data))

	// Echo back
	_, err = stream.Write(data)
	if err != nil {
		log.Printf("[%s] stream %d write error: %v", conn.RemoteAddr(), stream.StreamID(), err)
		return
	}
	stream.Close()

	log.Printf("[%s] stream %d echoed %d bytes", conn.RemoteAddr(), stream.StreamID(), len(data))
	fmt.Printf("[%s] stream %d: %q\n", conn.RemoteAddr(), stream.StreamID(), string(data))
}
