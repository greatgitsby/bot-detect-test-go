package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/CapacitorSet/ja3-server/crypto/tls"
	"github.com/CapacitorSet/ja3-server/net/http"
)

type ServerSideCollectorEntry struct {
	JA3        string `json:"ja3"`
	UA         string `json:"user_agent"`
	RemoteAddr string `json:"remote_addr"`
}

type Protector struct {
	handler http.Handler
}

func NewProtector(handlerToWrap http.Handler) *Protector {
	return &Protector{handlerToWrap}
}

func (p *Protector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hash := md5.Sum([]byte(r.JA3Fingerprint))

	out := make([]byte, 32)
	hex.Encode(out, hash[:])

	server_side_entry := ServerSideCollectorEntry{
		JA3:        string(out),
		UA:         r.Header.Get("User-Agent"),
		RemoteAddr: r.RemoteAddr,
	}

	server_side_entry_str, _ := json.Marshal(server_side_entry)

	fmt.Println(string(server_side_entry_str))

	if true {
		http.Error(w, "{\"status\": \"blocked\"}", http.StatusForbidden)
		return
	}

	p.handler.ServeHTTP(w, r)
}

func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s\n", "Hi")
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Syntax: %s path/to/certificate.pem path/to/key.pem\n", os.Args[0])
		return
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/hello", hello)

	protectedMux := NewProtector(mux)

	server := &http.Server{Addr: ":8443", Handler: protectedMux}

	ln, err := net.Listen("tcp", ":8443")
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
