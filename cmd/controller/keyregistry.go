package main

import (
	"github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	v1 "k8s.io/api/core/v1"
	"time"
)

type KeyRegistry interface {
	Name() string
	Seal(secret *v1.Secret) (*v1alpha1.SealedSecret, error)
	Unseal(sealed *v1alpha1.SealedSecret) (*v1.Secret, error)
	KeyRotation(period time.Duration) (func(), error)
	Init(server *ApiServer) error
}
