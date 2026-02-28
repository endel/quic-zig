package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

func main() {
	addr := flag.String("addr", "localhost:4434", "address to listen on")
	certFile := flag.String("cert", "", "TLS certificate file")
	keyFile := flag.String("key", "", "TLS private key file")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetOutput(os.Stdout)

	// Default cert paths
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

	h3Server := &http3.Server{
		Addr: *addr,
		TLSConfig: &tls.Config{
			NextProtos: []string{http3.NextProtoH3},
		},
	}
	webtransport.ConfigureHTTP3Server(h3Server)

	s := webtransport.Server{
		H3: h3Server,
		CheckOrigin: func(r *http.Request) bool {
			return true // Accept all origins for testing
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("WebTransport session request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		sess, err := s.Upgrade(w, r)
		if err != nil {
			log.Printf("upgrade failed: %v", err)
			w.WriteHeader(500)
			return
		}
		log.Printf("WebTransport session established")

		go handleSession(sess)
	})

	log.Printf("WebTransport server listening on %s", *addr)
	if err := s.ListenAndServeTLS(*certFile, *keyFile); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func handleSession(sess *webtransport.Session) {
	ctx := context.Background()

	// Handle bidi streams
	go func() {
		for {
			stream, err := sess.AcceptStream(ctx)
			if err != nil {
				log.Printf("AcceptStream error: %v", err)
				return
			}
			go handleBidiStream(stream)
		}
	}()

	// Handle uni streams
	go func() {
		for {
			stream, err := sess.AcceptUniStream(ctx)
			if err != nil {
				log.Printf("AcceptUniStream error: %v", err)
				return
			}
			go handleUniStream(sess, stream)
		}
	}()

	// Handle datagrams
	go func() {
		for {
			data, err := sess.ReceiveDatagram(ctx)
			if err != nil {
				log.Printf("ReceiveDatagram error: %v", err)
				return
			}
			log.Printf("Received datagram: %s", string(data))
			echo := fmt.Sprintf("Echo: %s", string(data))
			err = sess.SendDatagram([]byte(echo))
			if err != nil {
				log.Printf("SendDatagram error: %v", err)
			}
		}
	}()

	// Wait for session to close
	<-ctx.Done()
}

func handleBidiStream(stream *webtransport.Stream) {
	data, err := io.ReadAll(stream)
	if err != nil {
		log.Printf("read bidi stream error: %v", err)
		return
	}
	log.Printf("Received on bidi stream: %s", string(data))

	echo := fmt.Sprintf("Echo: %s", string(data))
	_, err = stream.Write([]byte(echo))
	if err != nil {
		log.Printf("write bidi stream error: %v", err)
		return
	}
	stream.Close()
	log.Printf("Sent echo on bidi stream: %s", echo)
}

func handleUniStream(sess *webtransport.Session, stream *webtransport.ReceiveStream) {
	data, err := io.ReadAll(stream)
	if err != nil {
		log.Printf("read uni stream error: %v", err)
		return
	}
	log.Printf("Received on uni stream: %s", string(data))

	// Echo back via a new uni stream
	sendStream, err := sess.OpenUniStream()
	if err != nil {
		log.Printf("open uni stream error: %v", err)
		return
	}
	echo := fmt.Sprintf("Echo: %s", string(data))
	_, err = sendStream.Write([]byte(echo))
	if err != nil {
		log.Printf("write uni stream error: %v", err)
		return
	}
	sendStream.Close()
}
