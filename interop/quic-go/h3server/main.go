package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/quic-go/quic-go/http3"
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("H3 request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		w.Header().Set("Content-Type", "text/plain")
		body := fmt.Sprintf("Hello from Go HTTP/3 server! You requested %s %s\n", r.Method, r.URL.Path)
		w.Write([]byte(body))
	})

	server := &http3.Server{
		Addr:    *addr,
		Handler: mux,
	}

	log.Printf("HTTP/3 server listening on %s", *addr)
	err := server.ListenAndServeTLS(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("server error: %v", err)
	}
}
