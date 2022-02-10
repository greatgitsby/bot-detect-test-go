package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/greatgitsby/bot-filter/crypto/tls"
	"github.com/greatgitsby/bot-filter/net/http"
)

type ServerSideCollectorEntry struct {
	JA3_Hash   string `json:"ja3_hash"`
	JA3_Raw    string `json:"ja3_raw"`
	UA         string `json:"user_agent"`
	RemoteAddr string `json:"remote_addr"`
}

type Protector struct {
	handler http.Handler
}

func NewProtector(handlerToWrap http.Handler) *Protector {
	return &Protector{handlerToWrap}
}

func GetServerSideCollectorEntry(r *http.Request) *ServerSideCollectorEntry {

	// Get JA3 fingerprint string
	hash := md5.Sum([]byte(r.JA3Fingerprint))
	out := make([]byte, 32)
	hex.Encode(out, hash[:])

	// Build entry
	// TODO brainstorm data I would like to be included here
	return &ServerSideCollectorEntry{
		JA3_Hash:   string(out),
		JA3_Raw:    r.JA3Fingerprint,
		UA:         r.Header.Get("User-Agent"),
		RemoteAddr: r.RemoteAddr,
	}
}

func (p *Protector) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	entry := GetServerSideCollectorEntry(r)

	fmt.Printf(
		"[%s] %s - %s - %s @ %s\n",
		time.Now().Local().Format(time.RFC3339Nano),
		entry.RemoteAddr,
		entry.JA3_Hash,
		r.Method,
		r.URL.Path,
	)

	p.handler.ServeHTTP(w, r)
}

func hello(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "%s\n", "{\"hello\": \"world\"}")
}

func main() {

	// TODO Parameterize
	listen_on := ":8443"

	// Ensure keys are provided
	if len(os.Args) != 3 {
		fmt.Printf("Syntax: %s path/to/certificate.pem path/to/key.pem\n", os.Args[0])
		return
	}

	mux := http.NewServeMux()

	// Route handlers
	mux.HandleFunc("/hello", hello)

	// Wrap routes in the protector handler (middleware)
	protectedMux := NewProtector(mux)

	// Create http server and listener on port
	server := &http.Server{Addr: listen_on, Handler: protectedMux}
	ln, err := net.Listen("tcp", listen_on)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		panic(err)
	}

	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	tlsListener := tls.NewListener(ln, &tlsConfig)

	fmt.Println("Listening")

	err = server.Serve(tlsListener)
	if err != nil {
		panic(err)
	}

	ln.Close()
}
