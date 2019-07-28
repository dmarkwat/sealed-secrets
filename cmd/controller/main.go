package main

import (
	goflag "flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	sealedsecrets "github.com/bitnami-labs/sealed-secrets/pkg/client/clientset/versioned"
	ssinformers "github.com/bitnami-labs/sealed-secrets/pkg/client/informers/externalversions"
)

var (
	keyPrefix       = flag.String("key-prefix", "sealed-secrets-key", "Prefix used to name keys.")
	keySize         = flag.Int("key-size", 4096, "Size of encryption key.")
	validFor        = flag.Duration("key-ttl", 10*365*24*time.Hour, "Duration that certificate is valid for.")
	myCN            = flag.String("my-cn", "", "CN to use in generated certificate.")
	printVersion    = flag.Bool("version", false, "Print version information and exit")
	keyRotatePeriod = flag.Duration("rotate-period", 0, "New key generation period (automatic rotation disabled if 0)")

	enabledKeyRegistries = flag.StringArray("registries", []string{"x509"}, "Enabled key registries, including: x509, cloud-kms (default: x509)")

	listenAddr   = flag.String("listen-addr", ":8080", "HTTP serving address.")
	readTimeout  = flag.Duration("read-timeout", 2*time.Minute, "HTTP request timeout.")
	writeTimeout = flag.Duration("write-timeout", 2*time.Minute, "HTTP response timeout.")

	// VERSION set from Makefile
	VERSION = "UNKNOWN"

	// Selector used to find existing public/private key pairs on startup
	keySelector = fields.OneTermEqualSelector(SealedSecretsKeyLabel, "active")
)

func init() {
	// Standard goflags (glog in particular)
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	if f := flag.CommandLine.Lookup("logtostderr"); f != nil {
		f.DefValue = "true"
		f.Value.Set(f.DefValue)
	}
}

type controller struct {
	clientset kubernetes.Interface
}

func initKeyPrefix(keyPrefix string) (string, error) {
	prefix, err := validateKeyPrefix(keyPrefix)
	if err != nil {
		return "", err
	}
	return prefix, err
}

func myNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}

	// Fall back to the namespace associated with the service account token, if available
	if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns
		}
	}

	return metav1.NamespaceDefault
}

func initKeyGenSignalListener(trigger func()) {
	sigChannel := make(chan os.Signal)
	signal.Notify(sigChannel, syscall.SIGUSR1)
	go func() {
		for {
			<-sigChannel
			trigger()
		}
	}()
}

func main2() error {
	registries := map[string]KeyRegistry{}
	for _, registry := range *enabledKeyRegistries {
		registries[registry] = nil
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	ssclientset, err := sealedsecrets.NewForConfig(config)
	if err != nil {
		return err
	}

	myNs := myNamespace()

	prefix, err := initKeyPrefix(*keyPrefix)
	if err != nil {
		return err
	}

	for registry, _ := range registries {
		var keyRegistry KeyRegistry
		switch registry {
		case x509_REGISTRY:
			keyRegistry, err = Newx509KeyRegistry(clientset, myNs, prefix, SealedSecretsKeyLabel, *keySize)
			if err != nil {
				return err
			}
			break
		default:
		}

		trigger, err := keyRegistry.KeyRotation(*keyRotatePeriod)
		if err != nil {
			return err
		}

		initKeyGenSignalListener(trigger)
	}

	ssinformer := ssinformers.NewSharedInformerFactory(ssclientset, 0)
	controller := NewController(clientset, ssclientset, ssinformer, registries)

	stop := make(chan struct{})
	defer close(stop)

	go controller.Run(stop)

	server := NewApiServer(controller.AttemptUnseal, controller.Rotate)

	go server.Listen(*listenAddr, *readTimeout, *writeTimeout)

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGTERM)
	<-sigterm

	return nil
}

func main() {
	flag.Parse()
	goflag.CommandLine.Parse([]string{})

	if *printVersion {
		fmt.Printf("controller version: %s\n", VERSION)
		return
	}

	log.Printf("Starting sealed-secrets controller version: %s\n", VERSION)

	if err := main2(); err != nil {
		panic(err.Error())
	}
}
