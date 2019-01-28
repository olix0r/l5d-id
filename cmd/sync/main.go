package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/pkg/x509"

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

	csr, err := ioutil.ReadFile(*csrPath)
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

		// Assert that the certificate is valid.
		p, err := pemutil.Parse(crtb, pemutil.WithStepCrypto())
		if err != nil {
			log.Fatal(err.Error())
		}
		crt := p.(*x509.Certificate)

		if err := ioutil.WriteFile(*crtPath, crtb, 0600); err != nil {
			log.Fatal(err.Error())
		}

		expiresIn := crt.NotAfter.Sub(time.Now())

		// Refresh in 80% of the time expiry time, with a max of 1 day
		refreshIn := (expiresIn / time.Second) * (800 * time.Millisecond)
		if refreshIn > 24*time.Hour {
			refreshIn = 24 * time.Hour
		}

		sum := sha256.Sum256(crt.Raw)

		log.Infof("fp=%s; expiry=%s; refresh=%s", strings.ToLower(hex.EncodeToString(sum[:])), expiresIn, refreshIn)
		select {
		case <-time.NewTimer(refreshIn).C:
			continue
		case <-stop:
			os.Exit(0)
		}
	}
}
