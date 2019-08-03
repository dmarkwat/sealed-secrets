package crypto

import (
	cloudkms "cloud.google.com/go/kms/apiv1"
	"context"
	"crypto/rand"
	"crypto/rsa"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"hash"
)

type Unsealer func(data []byte, label []byte) ([]byte, error)
type Sealer func(plainText []byte, label []byte) ([]byte, error)

func X509Sealer(pubKey *rsa.PublicKey) Sealer {
	return func(plainText []byte, label []byte) ([]byte, error) {
		return HybridEncrypt(rand.Reader, pubKey, plainText, label)
	}
}

func X509Unsealer(privKey *rsa.PrivateKey) Unsealer {
	return func(data []byte, label []byte) ([]byte, error) {
		return HybridDecrypt(rand.Reader, privKey, data, label)
	}
}

func CloudKMSSealer(pubKey *rsa.PublicKey, hash hash.Hash) Sealer {
	return func(plainText []byte, label []byte) ([]byte, error) {
		return rsa.EncryptOAEP(hash, rand.Reader, pubKey, plainText, nil)
	}
}

func CloudKMSUnsealer(keyName string, client *cloudkms.KeyManagementClient, ctx context.Context) Unsealer {
	return func(data []byte, label []byte) ([]byte, error) {
		response, err := client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
			Name:       keyName,
			Ciphertext: data,
		})
		if err != nil {
			return nil, err
		} else {
			return response.Plaintext, nil
		}
	}
}
