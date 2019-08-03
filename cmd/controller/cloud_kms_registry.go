package main

import (
	cloudkms "cloud.google.com/go/kms/apiv1"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/bitnami-labs/sealed-secrets/pkg/crypto"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"hash"
	"log"
	"net/http"
	"time"
)

type CloudKMSKeyRegistry struct {
	KeyRegistry
	keyName string
	client  *cloudkms.KeyManagementClient
}

func NewCloudKMSKeyRegistry(keyName string) (*CloudKMSKeyRegistry, error) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	// todo should consider caching pub key between rotations
	// 		but how to accommodate an external rotation?
	//key, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: keyName})
	//if err != nil {
	//	return nil, err
	//}

	return &CloudKMSKeyRegistry{
		keyName: keyName,
		client:  client,
	}, nil
}

func chooseHash(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (hash.Hash, error) {
	var hashval hash.Hash
	switch algorithm {
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256:
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256:
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256:
		hashval = sha256.New()
		break
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512:
		hashval = sha512.New()
		break
	default:
		return nil, fmt.Errorf("invalid encryption & hash function specified, %s", algorithm.String())
	}
	return hashval, nil
}

func (ck *CloudKMSKeyRegistry) getPubKey() (*kmspb.PublicKey, error) {
	request := &kmspb.GetPublicKeyRequest{
		Name: ck.keyName,
	}
	key, err := ck.client.GetPublicKey(context.Background(), request)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (ck *CloudKMSKeyRegistry) Seal(plainText []byte, label []byte) ([]byte, error) {
	key, err := ck.getPubKey()
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(key.Pem))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("")
	}
	hashval, err := chooseHash(key.Algorithm)
	if err != nil {
		return nil, err
	}
	bytes, err := crypto.CloudKMSSealer(pubKey, hashval)(plainText, label)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func (ck *CloudKMSKeyRegistry) Unseal(data []byte, label []byte) ([]byte, error) {
	plainText, err := crypto.CloudKMSUnsealer(ck.keyName, ck.client, context.Background())(data, label)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func (ck *CloudKMSKeyRegistry) KeyRotation(period time.Duration) (func(), error) {
	rotate := func() error {
		version, err := ck.client.CreateCryptoKeyVersion(context.Background(), &kmspb.CreateCryptoKeyVersionRequest{
			Parent: ck.keyName,
		})
		if err != nil {
			return fmt.Errorf("failed to create new key version")
		}
		_, err = ck.client.UpdateCryptoKeyPrimaryVersion(context.Background(), &kmspb.UpdateCryptoKeyPrimaryVersionRequest{
			Name:               ck.keyName,
			CryptoKeyVersionId: version.Name,
		})
		if err != nil {
			return fmt.Errorf("failed to update primary key version")
		}
		return nil
	}

	err := rotate()
	if err != nil {
		return nil, err
	}

	return func() {
		if err = rotate(); err != nil {
			// todo maybe bubble this up to the calling method using a channel?
			log.Panic(err)
		}
	}, nil
}

func (ck *CloudKMSKeyRegistry) Init(server *ApiServer) error {
	server.V2(ck, "cert.pem", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/x-pem-file")
		key, err := ck.getPubKey()
		if err != nil {
			// todo
		} else {
			_, _ = writer.Write([]byte(key.Pem))
		}
	})

	return nil
}

func (ck *CloudKMSKeyRegistry) Name() string {
	return CloudKMSRegistry.String()
}
