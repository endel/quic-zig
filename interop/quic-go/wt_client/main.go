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
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

func main() {
	addr := flag.String("addr", "localhost:4434", "server address")
	path := flag.String("path", "/", "WebTransport path")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetOutput(os.Stdout)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	d := webtransport.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:                    true,
			EnableStreamResetPartialDelivery:   true,
		},
	}

	url := fmt.Sprintf("https://%s%s", *addr, *path)
	log.Printf("Connecting to %s", url)

	rsp, sess, err := d.Dial(ctx, url, nil)
	if err != nil {
		log.Fatalf("dial failed: %v", err)
	}
	log.Printf("WebTransport session established (status: %d)", rsp.StatusCode)

	// Send data on a bidi stream
	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("open stream failed: %v", err)
	}

	msg := "Hello from Go WebTransport client!"
	_, err = stream.Write([]byte(msg))
	if err != nil {
		log.Fatalf("write failed: %v", err)
	}
	stream.Close()
	log.Printf("Sent on bidi stream: %s", msg)

	// Read echo response
	data, err := io.ReadAll(stream)
	if err != nil {
		log.Fatalf("read failed: %v", err)
	}
	fmt.Printf("Response: %s\n", string(data))

	// Try sending a datagram
	dgMsg := "Hello via datagram!"
	err = sess.SendDatagram([]byte(dgMsg))
	if err != nil {
		log.Printf("SendDatagram failed (may not be supported): %v", err)
	} else {
		log.Printf("Sent datagram: %s", dgMsg)

		// Try to receive datagram echo
		dgCtx, dgCancel := context.WithTimeout(ctx, 2*time.Second)
		defer dgCancel()
		dgData, err := sess.ReceiveDatagram(dgCtx)
		if err != nil {
			log.Printf("ReceiveDatagram error: %v", err)
		} else {
			fmt.Printf("Datagram response: %s\n", string(dgData))
		}
	}

	// Wait briefly for any remaining data
	time.Sleep(100 * time.Millisecond)

	sess.CloseWithError(0, "done")
	log.Printf("Session closed")

	// Signal success
	fmt.Println("WebTransport interop test completed successfully")

	// Consume the response body to avoid resource leak
	if rsp.Body != nil {
		_, _ = io.ReadAll(rsp.Body)
		rsp.Body.Close()
	} else {
		_ = http.Response{}
	}
}
