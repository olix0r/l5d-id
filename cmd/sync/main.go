package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/smallstep/cli/crypto/x509util"

	"google.golang.org/grpc"

	// Load all the auth plugins for the cloud providers.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	pb "github.com/olix0r/l5d-id/gen/identity"
)

func main() {
	addr := flag.String("addr", "l5d-id:8083", "address to serve on")
	tokenPath := flag.String("token", "", "path to token")
	csrPath := flag.String("csr", "", "path to read CSR from")
	crtPath := flag.String("crt", "", "path that certificate is written to (for debugging)")
	rootPath := flag.String("trust", "", "path to root trust bundle")

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
		log.Fatal("`-token` must be specified")
	}

	if *csrPath == "" {
		log.Fatal("`-csr` must be specified")
	}

	if *crtPath == "" {
		log.Fatal("`-crt` must be specified")
	}

	if *rootPath == "" {
		log.Fatal("`-trust` must be specified")
	}

	csr, err := ioutil.ReadFile(*csrPath)
	if err != nil {
		log.Fatal(err.Error())
	}

	roots, err := x509util.ReadCertPool(*rootPath)
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

		crtb := rsp.GetCertificate()
		if len(crtb) == 0 {
			log.Fatal("Missing certificate in response")
		}

		crt, intermediates, err := parseCrt(crtb)
		if err != nil {
			log.Fatal(err.Error())
		}

		_, err = crt.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		})
		if err != nil {
			log.Fatal(err.Error())
		}

		if time.Now().After(crt.NotAfter) || time.Now().Before(crt.NotBefore) {
			log.Fatal("Received expired certificate")
		}

		if err := ioutil.WriteFile(*crtPath, crtb, 0600); err != nil {
			log.Fatal(err.Error())
		}

		// Refresh in 80% of the time expiry time, with a max of 1 day
		expiresIn := crt.NotAfter.Sub(time.Now())
		refreshIn := (expiresIn / time.Second) * (800 * time.Millisecond)
		if refreshIn > 24*time.Hour {
			refreshIn = 24 * time.Hour
		}

		sum := sha256.Sum256(crt.Raw)
		log.Infof("fp=%s; expiry=%s; refresh=%s", strings.ToLower(hex.EncodeToString(sum[:])), expiresIn, refreshIn)

		select {
		case <-time.NewTimer(refreshIn).C:
			// continue
		case <-stop:
			os.Exit(0)
		}
	}
}

func parseCrt(crtb []byte) (*x509.Certificate, *x509.CertPool, error) {
	var (
		block *pem.Block
		crt   *x509.Certificate
		ipems []byte
		err   error
	)

	intermediates := x509.NewCertPool()

	for len(crtb) > 0 {
		block, crtb = pem.Decode(crtb)
		if block == nil {
			return nil, nil, errors.New("Failed to decode PEM certificate")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if crt == nil {
			crt, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
		} else {
			ipems = append(ipems, pem.EncodeToMemory(block)...)
		}
	}

	if crt == nil {
		return nil, nil, errors.New("Certificate did not contain PEM certificate blocks")
	}

	if len(ipems) > 0 && !intermediates.AppendCertsFromPEM(ipems) {
		return nil, nil, errors.New("Failed to create intermediate chain")
	}

	return crt, intermediates, nil
}
