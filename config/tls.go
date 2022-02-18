package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

type HostnameList []string

func (hl *HostnameList) String() string {
	if hl != nil {
		strings.Join(*hl, ",")
	}
	return ""
}

func (hl *HostnameList) Set(value string) error {
	if hl == nil {
		panic("nil HostnameList variable")
	}

	*hl = strings.Split(value, ",")
	return nil
}

func LetsEncryptTLS(hostnames HostnameList, cacheDirectory string) *tls.Config {
	if (len(hostnames) > 0) && (cacheDirectory != "") {
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hostnames...),
			Cache:      autocert.DirCache(cacheDirectory),
		}

		return certManager.TLSConfig()
	}

	return nil
}

func TLS(certPath string, keyPath string, clientCAPath string) (*tls.Config, error) {
	var tlsConfig *tls.Config

	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("unable load key pair: %s", err)
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	if clientCAPath != "" {
		if tlsConfig == nil {
			return nil, fmt.Errorf("cannot check client certificate without a server certificate and key")
		}

		data, err := ioutil.ReadFile(clientCAPath)
		if err != nil {
			return nil, fmt.Errorf("unable read CA file: %s", err)
		}

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(data)

		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}
