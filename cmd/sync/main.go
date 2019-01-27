package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	stepx509 "github.com/smallstep/cli/pkg/x509"

	"google.golang.org/grpc"

	// Load all the auth plugins for the cloud providers.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	pb "github.com/olix0r/l5d-id/gen/identity"
)

func main() {
	addr := flag.String("addr", "l5d-id:8083", "address to serve on")
	identity := flag.String("identity", "", "identity string")
	tokenPath := flag.String("token-path", "", "path to token")
	keyPath := flag.String("key-path", "", "path that the key is written to")
	crtPath := flag.String("crt-path", "", "path that the crt is written to")

	// override glog's default configuration
	flag.Set("logtostderr", "true")
	logLevel := flag.String("log-level", log.InfoLevel.String(),
		"log level, must be one of: panic, fatal, error, warn, info, debug")

	flag.Parse()

	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("invalid log-level: %s", *logLevel)
	}
	log.SetLevel(level)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ctx := context.Background()

	conn, err := grpc.Dial(*addr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err.Error())
	}
	client := pb.NewIdentityClient(conn)

	if *tokenPath == "" {
		log.Fatal("`-token-path` must be specified")
	}

	if *identity == "" {
		log.Fatal("`-identity` must be specified")
	}

	if *keyPath == "" {
		log.Fatal("`-key-path` must be specified")
	}

	if *crtPath == "" {
		log.Fatal("`-crt-path` must be specified")
	}

	privkey, err := newKey()
	if err != nil {
		log.Fatal(err.Error())
	}
	priv, err := pemutil.Serialize(privkey)
	if err != nil {
		log.Fatal(err.Error())
	}
	if err := ioutil.WriteFile(*keyPath, pem.EncodeToMemory(priv), 0600); err != nil {
		log.Fatal(err.Error())
	}

	csrReq := &x509.CertificateRequest{Subject: pkix.Name{CommonName: *identity}}
	csr, err := newCSR(privkey, csrReq)
	if err != nil {
		log.Fatal(err.Error())
	}

	for {
		token, err := ioutil.ReadFile(*tokenPath)
		if err != nil {
			log.Fatal(fmt.Errorf("failed to read token: %s: %s", *tokenPath, err.Error()))
		}

		rsp, err := client.Certify(ctx, &pb.CertifyRequest{
			Token:                     token,
			CertificateSigningRequest: csr,
		})
		if err != nil {
			log.Fatal(fmt.Errorf("Failed to obtain certificate: %s", err.Error()))
		}
		log.Debugf("certify=%v", rsp)

		crtb := rsp.GetCertificate()
		if len(crtb) == 0 {
			log.Fatal("Missing certificate in response")
		}

		p, err := pemutil.Parse(crtb, pemutil.WithStepCrypto())
		if err != nil {
			log.Fatal(err.Error())
		}
		log.Debugf("cert=%v", p)

		crt := p.(*stepx509.Certificate)

		if _, err = pemutil.Serialize(crt, pemutil.ToFile(*crtPath, 0600)); err != nil {
			log.Fatal(err.Error())
		}

		select {
		case <-time.NewTimer(time.Minute).C:
			continue
		case <-stop:
			os.Exit(0)
		}
	}
}

func newKey() (*ecdsa.PrivateKey, error) {
	k, err := keys.GenerateKey("EC", "P-256", 0)
	if err != nil {
		return nil, err
	}
	switch key := k.(type) {
	case *ecdsa.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("Unexpected key type")
	}
}

func newCSR(key *ecdsa.PrivateKey, req *x509.CertificateRequest) ([]byte, error) {
	csrb, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		return nil, err
	}
	p := &pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Bytes:   csrb,
		Headers: map[string]string{},
	}
	return pem.EncodeToMemory(p), nil
}
