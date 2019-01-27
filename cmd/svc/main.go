package main

import (
	"context"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

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
	// keyDuration := flag.Duration("identityLifetime", 24*time.Hour, "path to signing key")
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
	pb.RegisterIdentityServer(srv, &idSvc{authn, issuer})

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
	authn  *kauthn.AuthenticationV1Client
	issuer *x509util.Identity
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
	log.Debugf("requesting token review: %v", tr)
	// XXX what to do about the context?
	rvw, err := s.authn.TokenReviews().Create(&tr)
	log.Debugf("token review: %v", rvw)

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

	profile, err := x509util.NewLeafProfileWithCSR(csr, s.issuer.Crt, s.issuer.Key)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	crtb, err := profile.CreateCertificate()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	p := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtb,
	}

	rsp := &pb.CertifyResponse{
		Certificate: pem.EncodeToMemory(p),
	}
	return rsp, nil
}
