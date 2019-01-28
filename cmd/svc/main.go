package main

import (
	"context"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/smallstep/cli/crypto/x509util"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kauthnApi "k8s.io/api/authentication/v1"
	kauthn "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/tools/clientcmd"

	// Load all the auth plugins for the cloud providers.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	pb "github.com/olix0r/l5d-id/gen/identity"
)

func main() {
	addr := flag.String("addr", ":8083", "address to serve on")
	kubeConfigPath := flag.String("kubeconfig", "", "path to kube config")
	lifetime := flag.Duration("lifetime", 2*time.Hour, "certificate lifetime")
	signingKey := flag.String("signing-key", "", "path to signing key")
	signingCrt := flag.String("signing-crt", "", "path to signing certificate")

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

	authn, err := newAuthn(*kubeConfigPath)
	if err != nil {
		log.Fatal(err.Error())
	}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err.Error())
	}

	issuer, err := x509util.LoadIdentityFromDisk(*signingCrt, *signingKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	srv := grpc.NewServer()
	pb.RegisterIdentityServer(srv, &idSvc{authn, issuer, *lifetime})

	go func() {
		log.Infof("starting gRPC server on %s", *addr)
		srv.Serve(lis)
	}()

	<-stop
	log.Infof("shutting down gRPC server on %s", *addr)
	srv.GracefulStop()
}

func newAuthn(configFile string) (*kauthn.AuthenticationV1Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if configFile != "" {
		rules.ExplicitPath = configFile
	}

	config, err := clientcmd.
		NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).
		ClientConfig()
	if err != nil {
		return nil, err
	}

	return kauthn.NewForConfig(config)
}

type idSvc struct {
	authn    *kauthn.AuthenticationV1Client
	issuer   *x509util.Identity
	lifetime time.Duration
}

func (s *idSvc) Certify(ctx context.Context, req *pb.CertifyRequest) (*pb.CertifyResponse, error) {
	tok := req.GetToken()
	if len(tok) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing token")
	}

	csrb := req.GetCertificateSigningRequest()
	if len(csrb) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing certificate signing request")
	}
	csr, err := x509util.LoadCSRFromBytes(csrb)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	tr := kauthnApi.TokenReview{Spec: kauthnApi.TokenReviewSpec{Token: string(tok)}}
	log.Debugf("requesting token review to certify %s", csr.Subject.CommonName)

	// XXX what to do about the context?
	rvw, err := s.authn.TokenReviews().Create(&tr)

	if err != nil {
		return nil, status.Error(codes.Internal, "TokenReview failed")
	}
	if rvw.Status.Error != "" {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("TokenReview failed: %s", rvw.Status.Error))
	}
	if !rvw.Status.Authenticated {
		return nil, status.Error(codes.FailedPrecondition, "token was not authenticated")
	}

	log.Debugf("uid=%s; uname=%s", rvw.Status.User.UID, rvw.Status.User.Username)
	if rvw.Status.User.UID == "" || rvw.Status.User.Username == "" {
		return nil, status.Error(codes.Internal, "TokenReview provided invaliduser")
	}

	// Validate that the Certificate's metadata to the proper uid/...
	nameparts := strings.Split(rvw.Status.User.Username, ":")
	if len(nameparts) != 4 || nameparts[0] != "system" || nameparts[1] != "serviceaccount" {
		msg := fmt.Sprintf("Unexpected username: %s", rvw.Status.User.Username)
		return nil, status.Error(codes.Internal, msg)
	}

	ns := nameparts[2]
	if ns == "" || strings.Contains(ns, ".") {
		msg := fmt.Sprintf("Unexpected namespace: %s", ns)
		return nil, status.Error(codes.Internal, msg)
	}

	sa := nameparts[3]
	if sa == "" || strings.Contains(sa, ".") {
		msg := fmt.Sprintf("Unexpected service account: %s", sa)
		return nil, status.Error(codes.Internal, msg)
	}

	validName := fmt.Sprintf("%s.%s.%s", rvw.Status.User.UID, sa, ns)

	if csr.Subject.CommonName != validName {
		msg := fmt.Sprintf("Identity could not be validated for %s: %s", csr.Subject.CommonName, validName)
		return nil, status.Error(codes.FailedPrecondition, msg)
	}

	for _, n := range csr.DNSNames {
		if n != validName {
			msg := fmt.Sprintf("Cannot validate name: %s", n)
			return nil, status.Error(codes.FailedPrecondition, msg)
		}
	}

	if len(csr.EmailAddresses) > 0 {
		return nil, status.Error(codes.FailedPrecondition, "Cannot validate email addresses")
	}

	// TODO should we support POD IPs?
	if len(csr.IPAddresses) > 0 {
		return nil, status.Error(codes.FailedPrecondition, "Cannot validate IP addresses")
	}

	// TODO permit spiffe ids?
	if len(csr.URIs) > 0 {
		return nil, status.Error(codes.FailedPrecondition, "Cannot validate URIs")
	}

	notAfterLifetime := x509util.WithNotBeforeAfterDuration(time.Time{}, time.Time{}, s.lifetime)
	profile, err := x509util.NewLeafProfileWithCSR(csr, s.issuer.Crt, s.issuer.Key, notAfterLifetime)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	log.Infof("certifying %s for %s", csr.Subject.CommonName, s.lifetime)
	crtb, err := profile.CreateCertificate()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	c := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtb,
	})
	return &pb.CertifyResponse{Certificate: c}, nil
}
