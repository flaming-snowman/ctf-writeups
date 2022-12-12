package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

const (
	address   = ":8631"
	printPath = "/ipp/print"
	certFile  = "cert.pem"
	keyFile   = "key.pem"
)

func initTLS() error {
	const bits = 2048
	var bigOne = big.NewInt(1)
	var p, pok = new(big.Int).SetString("165339883928642242629847294883458685963640668251014793081329796385871983032700795766517754311983873160016406682708055537482988728652632038079657041006483997556079287226894265000609524171791597509889310313801896383127687512046470579717961037934509735800195322616396412844608553274191538518702473973801282757329", 10)
	if !pok {
		return fmt.Errorf("failed to create p")
	}
	var q, qok = new(big.Int).SetString("142868719742863293783230979998595876793415956014235960922151036241155398557013175374929194646682931157376392447724131367775640007550829960268051112176549732008858300548786079341071746721635835744957674944791270662022918676753662719533721899116906331154776508780823125564615147531881573980598054432598254739019", 10)
	if !qok {
		return fmt.Errorf("failed to create q")
	}
	privateKey := &rsa.PrivateKey{}
	privateKey.Primes = []*big.Int{p, q}
	privateKey.N = new(big.Int).Mul(p, q)
	privateKey.E = 65537

	pminus1 := new(big.Int).Sub(p, bigOne)
	qminus1 := new(big.Int).Sub(q, bigOne)
	totient := new(big.Int).Mul(pminus1, qminus1)

	privateKey.D = new(big.Int)
	bigE := big.NewInt(int64(privateKey.E))
	ok := privateKey.D.ModInverse(bigE, totient)
	if ok == nil {
		return fmt.Errorf("failed prime number generation")
	}
	privateKey.Precompute()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My Cool Printer"},
		},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDERBytes})
	if err := os.WriteFile(certFile, certPEMBytes, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	keyDERBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDERBytes})
	if err := os.WriteFile(keyFile, keyPEMBytes, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

func main() {
	initTLS()
}
