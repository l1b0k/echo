package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	rd "math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

func main() {
	var counter int64 = 0
	gen()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "echo %s by l1b0k\n", version)
		fmt.Fprintf(w, "%s %s\n", r.Method, r.URL)
		fmt.Fprintf(w, "Host: %s\n", r.Host)
		atomic.AddInt64(&counter, 1)
		fmt.Fprintf(w, "Counter: %d\n", atomic.LoadInt64(&counter))
		if r.TLS != nil && r.TLS.PeerCertificates != nil {
			for _, t := range r.TLS.PeerCertificates {
				fmt.Fprintf(w, "Client certficate:\n")
				fmt.Fprintf(w, " Subject: %s\n", t.Subject.String())
				fmt.Fprintf(w, " Issuer: %s\n", t.Issuer.String())
				fmt.Fprintf(w, " Date: %s %s\n", t.NotBefore.String(), t.NotAfter.String())
				fmt.Fprintf(w, " DNS: %s \n", strings.Join(t.DNSNames, ","))

				var ips []string
				for _, ip := range t.IPAddresses {
					ips = append(ips, ip.String())
				}
				fmt.Fprintf(w, " IP: $s\n", strings.Join(ips, ","))

				var uris []string
				if t.URIs != nil {
					for _, u := range t.URIs {
						uris = append(uris, u.String())
					}
					fmt.Fprintf(w, " URI: %s\n", strings.Join(uris, ","))
				}
			}
		}

		var headers []string
		for k, v := range r.Header {
			for _, vv := range v {
				headers = append(headers, fmt.Sprintf("%s: %s\n", k, vv))
			}
		}
		sort.Strings(headers)
		for _, str := range headers {
			fmt.Fprintf(w, str)
		}
	})

	fs := http.FileServer(http.Dir("static/"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	ch := make(chan error)
	go func() {
		ch <- http.ListenAndServe(":80", nil)
	}()
	go func() {
		ch <- http.ListenAndServeTLS(":443", "ca.pem", "ca-key.pem", nil)
	}()

	select {
	case err := <-ch:
		println(err.Error())
	}
}

var version string

func gen() {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(rd.Int63()),
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Locality:           []string{"HZ"},
			Province:           []string{"ZheJiang"},
			OrganizationalUnit: []string{"test"},
			Organization:       []string{"test"},
			StreetAddress:      []string{"street"},
			PostalCode:         []string{"310000"},
		},
	}
	pk, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk)
	certOut, _ := os.Create("ca.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	keyOut, _ := os.Create("ca-key.pem")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})
	keyOut.Close()
}
