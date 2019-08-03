package main

import (
	"time"
)

const (
	X509Registry     RegistryType = iota
	CloudKMSRegistry RegistryType = iota
)

const (
	X509RegistryName     = "x509"
	CloudKMSRegistryName = "cloud_kms"
)

var Registries_name = map[RegistryType]string{
	X509Registry:     X509RegistryName,
	CloudKMSRegistry: CloudKMSRegistryName,
}

var Registries_type = map[string]RegistryType{
	Registries_name[X509Registry]:     X509Registry,
	Registries_name[CloudKMSRegistry]: CloudKMSRegistry,
}

type RegistryType int

func (rt RegistryType) String() string {
	return Registries_name[rt]
}

type KeyRegistry interface {
	Name() string
	Seal(plainText []byte, label []byte) ([]byte, error)
	Unseal(data []byte, label []byte) ([]byte, error)
	KeyRotation(period time.Duration) (func(), error)
	Init(server *ApiServer) error
}
