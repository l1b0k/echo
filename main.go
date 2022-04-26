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
	"math"
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

const body = `
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

`

func main() {
	flag.Parse()

	switch mode {
	case "client":
		handleCases()
	default:
		gen()
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
		http.HandleFunc("/load", func(w http.ResponseWriter, r *http.Request) {
			v := r.Header.Get("Complex")
			repeta, err := strconv.Atoi(v)
			if err != nil {
				repeta = 10000
			}
			computePI(r.Context().Done(), repeta)
			for i := 0; i < 100; i++ {
				fmt.Fprintf(w, body)
			}
		})
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
func computePI(ch <-chan struct{}, round int) float64 {
	rd.Seed(time.Now().UnixNano())
	var aa float64
	for i := 0; i < round; i++ {
		select {
		case <-ch:
			return 0
		default:
		}
		cosVal := float64(-1)
		for n := 4; n < 5000; n *= 2 {
			cosVal = math.Sqrt(0.5 * (cosVal + 1.0))
			c := math.Pow(0.5-0.5*cosVal, 0.5)
			aa = c * float64(n)
		}
	}
	return aa
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
