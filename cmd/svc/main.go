package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
	pb "github.com/olix0r/l5d-id/gen/identity"

	// Load all the auth plugins for the cloud providers.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)
)

func main() {
	addr := flag.String("addr", ":8083", "address to serve on")
	kubeConfigPath := flag.String("kubeconfig", "", "path to kube config")
	flags.ConfigureAndParse()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	done := make(chan struct{})

	k8s, err := newK8s(*kubeConfigPath)
	if err != nil {
		log.Fatal(err.Error())
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err.Error())
	}

	srv := prometheus.NewGrpcServer()
	pb.RegisterDestinationServer(srv, &idsvc{k8s})

	go func() {
		log.Infof("starting gRPC server on %s", *addr)
		srv.Serve(lis)
	}()

	<-stop

	log.Infof("shutting down gRPC server on %s", *addr)
	close(done)
	srv.GracefulStop()
}

// GetConfig returns kubernetes config based on the current environment.
// If fpath is provided, loads configuration from that file. Otherwise,
// GetConfig uses default strategy to load configuration from $KUBECONFIG,
// .kube/config, or just returns in-cluster config.
func newK8s(configFile string) (*kubernetes.Clientset, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if configFile != "" {
		rules.ExplicitPath = configFile
	}
	config, err := clientcmd.
		NewNonInteractiveDeferredLoadingClientConfig(rules, nil).
		ClientConfig()
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(config)
}

type idsvc struct { *kubernetes.Clientset }

func (*grpc) Certify(pb.CertifyRequest) (pb.CertifyResponse, error) {
	return nil, nil
}
