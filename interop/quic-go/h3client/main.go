package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	addr := flag.String("addr", "localhost:4434", "server address")
	path := flag.String("path", "/", "request path")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetOutput(os.Stdout)

	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	defer transport.Close()

	client := &http.Client{
		Transport: transport,
	}

	url := fmt.Sprintf("https://%s%s", *addr, *path)
	log.Printf("H3 GET %s", url)

	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("read body failed: %v", err)
	}

	log.Printf("status: %d", resp.StatusCode)
	log.Printf("body: %s", string(body))

	for k, v := range resp.Header {
		log.Printf("header: %s: %v", k, v)
	}

	fmt.Printf("Response: %s", string(body))
	fmt.Println("OK")
}
