package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/bitnami-labs/sealed-secrets/pkg/crypto"
	"k8s.io/apimachinery/pkg/api/errors"
	"log"
	"net/http"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"k8s.io/client-go/kubernetes"
	certUtil "k8s.io/client-go/util/cert"
)

type x509KeyRegistry struct {
	KeyRegistry
	client      kubernetes.Interface
	namespace   string
	keyPrefix   string
	keyLabel    string
	keysize     int
	privateKeys []*rsa.PrivateKey
	cert        *x509.Certificate
}

func Newx509KeyRegistry(client kubernetes.Interface, namespace, keyPrefix, keyLabel string, keysize int) (*x509KeyRegistry, error) {
	log.Printf("Searching for existing private keys")
	secretList, err := client.CoreV1().Secrets(namespace).List(metav1.ListOptions{
		LabelSelector: keySelector.String(),
	})
	if err != nil {
		return nil, err
	}
	items := secretList.Items
	if len(items) == 0 {
		s, err := client.CoreV1().Secrets(namespace).Get(keyPrefix, metav1.GetOptions{})
		if !errors.IsNotFound(err) {
			if err != nil {
				return nil, err
			}
			items = append(items, *s)
			// TODO(mkm): add the label to the legacy secret
		}
	}

	keyRegistry := &x509KeyRegistry{
		client:      client,
		namespace:   namespace,
		keyPrefix:   keyPrefix,
		keysize:     keysize,
		keyLabel:    keyLabel,
		privateKeys: []*rsa.PrivateKey{},
	}

	sort.Sort(ssv1alpha1.ByCreationTimestamp(items))
	for _, secret := range items {
		key, certs, err := readKey(secret)
		if err != nil {
			log.Printf("Error reading key %s: %v", secret.Name, err)
		}
		keyRegistry.registerNewKey(secret.Name, key, certs[0])
		log.Printf("----- %s", secret.Name)
	}
	return keyRegistry, nil
}

func (kr *x509KeyRegistry) generateKey() (string, error) {
	key, cert, err := generatePrivateKeyAndCert(kr.keysize)
	if err != nil {
		return "", err
	}
	certs := []*x509.Certificate{cert}
	generatedName, err := writeKey(kr.client, key, certs, kr.namespace, kr.keyLabel, kr.keyPrefix)
	if err != nil {
		return "", err
	}
	// Only store key to local store if write to k8s worked
	kr.registerNewKey(generatedName, key, cert)
	log.Printf("New key written to %s/%s\n", kr.namespace, generatedName)
	log.Printf("Certificate is \n%s\n", pem.EncodeToMemory(&pem.Block{Type: certUtil.CertificateBlockType, Bytes: cert.Raw}))
	return generatedName, nil
}

func (kr *x509KeyRegistry) registerNewKey(keyName string, privKey *rsa.PrivateKey, cert *x509.Certificate) {
	kr.privateKeys = append(kr.privateKeys, privKey)
	kr.cert = cert
}

func (kr *x509KeyRegistry) latestPrivateKey() *rsa.PrivateKey {
	return kr.privateKeys[len(kr.privateKeys)-1]
}

func (kr *x509KeyRegistry) getCert(keyname string) (*x509.Certificate, error) {
	return kr.cert, nil
}

func (kr *x509KeyRegistry) Seal(plainText []byte, label []byte) ([]byte, error) {
	return crypto.X509Sealer(&kr.latestPrivateKey().PublicKey)(plainText, label)
	//return crypto.HybridEncrypt(rand.Reader, &kr.latestPrivateKey().PublicKey, plainText, label)
}

func (kr *x509KeyRegistry) Unseal(data []byte, label []byte) ([]byte, error) {
	for _, key := range kr.privateKeys {
		secret, err := crypto.X509Unsealer(key)(data, label)
		if err == nil {
			return secret, nil
		}
	}
	return nil, fmt.Errorf("couldn't decrypt secret")
}

// Initialises the first key and starts the rotation job. returns an early trigger function.
// A period of 0 disables automatic rotation, but manual rotation (e.g. triggered by SIGUSR1)
// is still honoured.
func (kr *x509KeyRegistry) KeyRotation(period time.Duration) (func(), error) {
	// Create a new key only if it's the first key or if we have automatic key rotation.
	// Since the rotation period might be longer than the average pod run time (eviction, updates, crashes etc)
	// we err on the side of increased rotation frequency rather than overshooting the rotation goals.
	//
	// TODO(mkm): implement rotation cadence based on resource times rather than just an in-process timer.
	if period != 0 || len(kr.privateKeys) == 0 {
		if _, err := kr.generateKey(); err != nil {
			return nil, err
		}
	}
	// wrapper function to log error thrown by generateKey function
	keyGenFunc := func() {
		if _, err := kr.generateKey(); err != nil {
			log.Printf("Failed to generate new key : %v\n", err)
		}
	}
	if period == 0 {
		return keyGenFunc, nil
	}
	return ScheduleJobWithTrigger(period, keyGenFunc), nil
}

func (kr *x509KeyRegistry) Init(server *ApiServer) error {
	cp := func() []*x509.Certificate {
		return []*x509.Certificate{kr.cert}
	}

	pubkey := func(w http.ResponseWriter, r *http.Request) {
		certs := cp()
		w.Header().Set("Content-Type", "application/x-pem-file")
		for _, cert := range certs {
			_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: certUtil.CertificateBlockType, Bytes: cert.Raw}))
		}
	}

	server.V1("cert.pem", pubkey)

	server.V2(kr, "cert.pem", pubkey)

	return nil
}

func (kr *x509KeyRegistry) Name() string {
	return X509Registry.String()
}
