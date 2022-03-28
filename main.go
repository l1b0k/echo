/*
Copyright 2020-2022 l1b0k

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	rd "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var once sync.Once
var podInfo string

const (
	ExitCodeArgsErr = 10
	ExitCodeTimeout = 11
)

func getPodInfo() string {
	once.Do(func() {
		podInfo = fmt.Sprintf("%s %s/%s\n", os.Getenv("K8S_NODE_NAME"), os.Getenv("K8S_POD_NAME"), os.Getenv("K8S_POD_NAMESPACE"))
	})
	return podInfo
}

func getLocalAddrs() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err.Error()
	}
	var s []string
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}

		if !ipNet.IP.IsGlobalUnicast() {
			continue
		}
		s = append(s, a.String())
	}
	return strings.Join(s, ",")
}

var (
	mode             string // run mode server or client
	cases            string // run mode server or client
	httpBindAddress  string
	httpsBindAddress string
)

func init() {
	flag.StringVar(&mode, "mode", "server", "default as an HTTP/S Server")
	flag.StringVar(&cases, "cases", "", "comma separated list. dns://127.0.0.1:53,http://127.0.0.1:80,https://127.0.0.1:443")
	flag.StringVar(&httpBindAddress, "http-bind-address", ":80", "HTTP bind address")
	flag.StringVar(&httpsBindAddress, "https-bind-address", ":443", "HTTPS bind address")
}

func main() {
	flag.Parse()

	switch mode {
	case "client":
		handleCases()
	default:
		gen()
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
		http.HandleFunc("/version", version)
		http.HandleFunc("/echo", echo)
		fs := http.FileServer(http.Dir("static/"))
		http.Handle("/static/", http.StripPrefix("/static/", fs))

		ch := make(chan error)
		go func() {
			ch <- http.ListenAndServe(httpBindAddress, nil)
		}()
		go func() {
			ch <- http.ListenAndServeTLS(httpsBindAddress, "ca.pem", "ca-key.pem", nil)
		}()

		select {
		case err := <-ch:
			println(err.Error())
		}
	}
}

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
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	_ = certOut.Close()
	keyOut, _ := os.Create("ca-key.pem")
	_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})
	_ = keyOut.Close()
}

func version(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "text/json")
	b, _ := json.Marshal(map[string]string{
		"gitCommit": gitCommit,
		"buildDate": buildDate,
	})

	fmt.Fprint(w, string(b))
}

func echo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "text/plain")
	fmt.Fprintf(w, "%s %s\n", r.Method, r.URL)
	fmt.Fprintf(w, "Host: %s\n", r.Host)
	fmt.Fprintf(w, "RemoteAddr: %s\n", r.RemoteAddr)
	fmt.Fprintf(w, "LocalAddr: %s\n", getLocalAddrs())

	fmt.Fprintf(w, getPodInfo())

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
}

func handleCases() {
	for _, c := range strings.Split(cases, ",") {
		u, err := url.Parse(c)
		if err != nil {
			os.Exit(ExitCodeArgsErr)
		}
		switch u.Scheme {
		case "tcp":
			host, portStr, err := net.SplitHostPort(u.Host)
			if err != nil {
				os.Exit(ExitCodeArgsErr)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				os.Exit(ExitCodeArgsErr)
			}
			err = retry(func() (bool, error) {
				dial, err := net.DialTCP(u.Scheme, nil, &net.TCPAddr{
					IP:   net.ParseIP(host),
					Port: port,
				})
				if err != nil {
					return false, nil
				}
				_ = dial.Close()
				return true, nil
			})
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "dial %s %s", u.String(), err)
				os.Exit(ExitCodeTimeout)
			}
		case "http", "https":
			err = retry(func() (bool, error) {
				resp, err := http.Get(u.String())
				if err != nil {
					return false, nil
				}
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					return true, nil
				}
				return false, nil
			})
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "dial %s %s", u.String(), err)
				os.Exit(ExitCodeTimeout)
			}
		case "dns":
			err = retry(func() (bool, error) {
				_, err := net.LookupIP(u.Host)
				if err != nil {
					return false, nil
				}
				return true, nil
			})
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "dial %s %s", u.String(), err)
				os.Exit(ExitCodeTimeout)
			}
		}
	}
}

func retry(f func() (bool, error)) error {
	for i := 0; i < 5; i++ {
		ok, err := f()
		if err != nil {
			return err
		}
		if !ok {
			time.Sleep(1 * time.Second)
			continue
		}
		return nil
	}

	return fmt.Errorf("time out")
}

var (
	gitCommit = "$Format:%H$"
	buildDate = "1970-01-01T00:00:00Z"
)
