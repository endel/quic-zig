package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:4433", "address to listen on")
	certFile := flag.String("cert", "", "TLS certificate file")
	keyFile := flag.String("key", "", "TLS private key file")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if *certFile == "" || *keyFile == "" {
		_, thisFile, _, _ := runtime.Caller(0)
		browserDir := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))), "browser")
		if *certFile == "" {
			*certFile = filepath.Join(browserDir, "certs", "server.crt")
		}
		if *keyFile == "" {
			*keyFile = filepath.Join(browserDir, "certs", "server.key")
		}
	}

	// Print cert hash
	certPEM, _ := os.ReadFile(*certFile)
	if certPEM != nil {
		// Parse DER from PEM
		block := strings.Index(string(certPEM), "-----BEGIN CERTIFICATE-----")
		end := strings.Index(string(certPEM), "-----END CERTIFICATE-----")
		if block >= 0 && end > block {
			// Just print the hash from openssl
			log.Printf("Cert: %s", *certFile)
		}
	}
	// Get DER hash
	derBytes, _ := os.ReadFile(*certFile)
	_ = derBytes
	// Use openssl via shell would be complex, just print paths
	hash := sha256.New()
	hash.Write(certPEM)
	log.Printf("Cert PEM SHA-256: %s", hex.EncodeToString(hash.Sum(nil)))

	h3Server := &http3.Server{
		Addr: *addr,
		TLSConfig: &tls.Config{
			NextProtos: []string{http3.NextProtoH3},
		},
	}
	webtransport.ConfigureHTTP3Server(h3Server)

	s := webtransport.Server{
		H3:          h3Server,
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		log.Printf("CONNECT %s", r.URL.String())

		sess, err := s.Upgrade(w, r)
		if err != nil {
			log.Printf("upgrade failed: %v", err)
			return
		}
		log.Printf("session established for %s", path)

		// Route by handler name
		handler := ""
		if i := strings.LastIndex(path, "/"); i >= 0 {
			handler = strings.TrimSuffix(path[i+1:], ".py")
		}

		switch handler {
		case "echo":
			handleEcho(sess)
		case "server-close":
			handleServerClose(sess, r)
		case "server-connection-close":
			handleServerConnectionClose(sess)
		default:
			log.Printf("unknown handler: %s, defaulting to echo", handler)
			handleEcho(sess)
		}
	})

	log.Printf("WPT WebTransport server (Go) listening on %s", *addr)
	if err := s.ListenAndServeTLS(*certFile, *keyFile); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func handleEcho(sess *webtransport.Session) {
	ctx := context.Background()

	// Bidi echo
	go func() {
		for {
			stream, err := sess.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				data, err := io.ReadAll(stream)
				if err != nil {
					return
				}
				log.Printf("bidi echo: %d bytes", len(data))
				stream.Write(data)
				stream.Close()
			}()
		}
	}()

	// Uni echo
	go func() {
		for {
			stream, err := sess.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go func() {
				data, err := io.ReadAll(stream)
				if err != nil {
					return
				}
				log.Printf("uni echo: %d bytes", len(data))
				sendStream, err := sess.OpenUniStream()
				if err != nil {
					return
				}
				sendStream.Write(data)
				sendStream.Close()
			}()
		}
	}()

	// Datagram echo
	go func() {
		for {
			data, err := sess.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			log.Printf("datagram echo: %d bytes", len(data))
			sess.SendDatagram(data)
		}
	}()

	<-ctx.Done()
}

func handleServerClose(sess *webtransport.Session, r *http.Request) {
	codeStr := r.URL.Query().Get("code")
	reason := r.URL.Query().Get("reason")
	code, _ := strconv.Atoi(codeStr)

	log.Printf("server-close: code=%d reason=%s", code, reason)

	// Close with the specified code and reason
	sess.CloseWithError(webtransport.SessionErrorCode(code), reason)
}

func handleServerConnectionClose(sess *webtransport.Session) {
	log.Printf("server-connection-close")
	sess.CloseWithError(0, "connection close test")
}

func getQueryParam(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

func main2() {
	fmt.Println("test")
}
