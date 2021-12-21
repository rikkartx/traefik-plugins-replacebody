// Package plugin_replace_body a demo plugin.
package plugin_replace_body

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

// ClientTLS copy from traefik/pkg/types/tls.go
type ClientTLS struct {
	CA                 string `description:"TLS CA" json:"ca,omitempty" toml:"ca,omitempty" yaml:"ca,omitempty"`
	CAOptional         bool   `description:"TLS CA.Optional" json:"caOptional,omitempty" toml:"caOptional,omitempty" yaml:"caOptional,omitempty" export:"true"`
	Cert               string `description:"TLS cert" json:"cert,omitempty" toml:"cert,omitempty" yaml:"cert,omitempty"`
	Key                string `description:"TLS key" json:"key,omitempty" toml:"key,omitempty" yaml:"key,omitempty"`
	InsecureSkipVerify bool   `description:"TLS insecure skip verify" json:"insecureSkipVerify,omitempty" toml:"insecureSkipVerify,omitempty" yaml:"insecureSkipVerify,omitempty" export:"true"`
}

// Config the plugin configuration.
type Config struct {
	Address string     `json:"address" yaml:"address"`
	Method  string     `json:"method" yaml:"method"`
	TLS     *ClientTLS `json:"tls" yaml:"tls"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Address: "",
		Method:  http.MethodGet,
	}
}

// ReplaceBody a ReplaceBody plugin.
type ReplaceBody struct {
	next    http.Handler
	name    string
	address string
	method  string
	client  http.Client
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	replaceBody := &ReplaceBody{
		next:    next,
		name:    name,
		address: config.Address,
		method:  config.Method,
	}

	// copy from traefik/pkg/middlewares/auth/forward.go
	// Ensure our request client does not follow redirects
	replaceBody.client = http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	// copy from traefik/pkg/types/tls.go
	if config.TLS != nil {
		tlsConfig, err := config.TLS.CreateTLSConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to create client TLS configuration: %w", err)
		}

		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = tlsConfig
		replaceBody.client.Transport = tr
	}

	return replaceBody, nil
}

// CreateTLSConfig copy from traefik/pkg/types/tls.go
// CreateTLSConfig creates a TLS config from ClientTLS structures.
func (clientTLS *ClientTLS) CreateTLSConfig(ctx context.Context) (*tls.Config, error) {
	if clientTLS == nil {
		log.Println("warn: clientTLS is nil")
		return nil, nil
	}

	// Not initialized, to rely on system bundle.
	var caPool *x509.CertPool

	clientAuth := tls.NoClientCert
	if clientTLS.CA != "" {
		var ca []byte
		if _, errCA := os.Stat(clientTLS.CA); errCA == nil {
			var err error
			ca, err = os.ReadFile(clientTLS.CA)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA. %w", err)
			}
		} else {
			ca = []byte(clientTLS.CA)
		}

		caPool = x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(ca) {
			return nil, errors.New("failed to parse CA")
		}

		if clientTLS.CAOptional {
			clientAuth = tls.VerifyClientCertIfGiven
		} else {
			clientAuth = tls.RequireAndVerifyClientCert
		}
	}

	hasCert := len(clientTLS.Cert) > 0
	hasKey := len(clientTLS.Key) > 0

	if hasCert != hasKey {
		return nil, errors.New("both TLS cert and key must be defined")
	}

	if !hasCert || !hasKey {
		return &tls.Config{
			RootCAs:            caPool,
			InsecureSkipVerify: clientTLS.InsecureSkipVerify,
			ClientAuth:         clientAuth,
		}, nil
	}

	cert, err := loadKeyPair(clientTLS.Cert, clientTLS.Key)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: clientTLS.InsecureSkipVerify,
		ClientAuth:         clientAuth,
	}, nil
}

// copy from traefik/pkg/types/tls.go
func loadKeyPair(cert, key string) (tls.Certificate, error) {
	keyPair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err == nil {
		return keyPair, nil
	}

	_, err = os.Stat(cert)
	if err != nil {
		return tls.Certificate{}, errors.New("cert file does not exist")
	}

	_, err = os.Stat(key)
	if err != nil {
		return tls.Certificate{}, errors.New("key file does not exist")
	}

	keyPair, err = tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return keyPair, nil
}

func (a *ReplaceBody) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if a.address != "" {
		replaceReq, err := http.NewRequest(a.method, a.address, req.Body)
		if err != nil {
			logMessage := fmt.Sprintf("Error calling %s. Cause %s", a.address, err)
			log.Println(logMessage)
			writeErrorToResponse(rw, fmt.Sprintf("Can't make new request to remote server. Cause: %s", err))
			return
		}

		copyHeaders(req.Header, replaceReq.Header, false)
		replaceResponse, replaceErr := a.client.Do(replaceReq)
		if replaceErr != nil {
			writeErrorToResponse(rw, fmt.Sprintf("Can't reach remote server: %s, please check auth server status. Cause: %s", a.address, replaceErr))
			return
		}
		body, readError := io.ReadAll(replaceResponse.Body)
		if readError != nil {
			writeErrorToResponse(rw, fmt.Sprintf("Can't read body from remote server. Cause %s", readError))
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				fmt.Println("Can't close remote response")
			}
		}(replaceResponse.Body)
		copyHeaders(replaceResponse.Header, req.Header, true)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		req.ContentLength = int64(len(body))
	}

	a.next.ServeHTTP(rw, req)
}

func writeErrorToResponse(rw http.ResponseWriter, errMessage string) {
	errMessageMap := make(map[string]interface{})
	errMessageMap["code"] = 500
	errMessageMap["message"] = errMessage
	errMessageMap["data"] = nil

	errMessageByte, errJson := json.Marshal(errMessageMap)
	if errJson != nil {
		fmt.Println("Error: json.Marshal failed", errJson)
	}

	rw.Header().Add("Content-Type", "application/json")
	rw.WriteHeader(http.StatusInternalServerError)
	_, errWrite := rw.Write(errMessageByte)
	if errWrite != nil {
		fmt.Println("Error: request error message write to response failed", errWrite)
	}
}

func copyHeaders(src http.Header, dest http.Header, del bool) {
	// copy from https://github.com/vulcand/oxy/blob/master/utils/netutils.go
	for k, vv := range src {
		if del {
			dest.Del(k)
		}
		dest[k] = append(dest[k], vv...)
	}
}
