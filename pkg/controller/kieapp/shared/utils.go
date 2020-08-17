package shared

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"math/rand"
	"reflect"
	"time"

	"github.com/kiegroup/kie-cloud-operator/pkg/controller/kieapp/constants"
	"github.com/pavel-v-chernykh/keystore-go/v4"
	"github.com/prometheus/common/log"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// GenerateKeystore returns a Java Keystore with a self-signed certificate
func GenerateKeystore(commonName string, password []byte) ([]byte, error) {
	var b bytes.Buffer
	certificate, derPK, err := genCert(commonName)
	if err != nil {
		return []byte{}, err
	}
	keyStore := keystore.New()
	pkeIn := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   derPK,
		CertificateChain: []keystore.Certificate{
			{
				Type:    "X509",
				Content: certificate,
			},
		},
	}
	if err := keyStore.SetPrivateKeyEntry(constants.KeystoreAlias, pkeIn, password); err != nil {
		return []byte{}, err
	}
	if err := keyStore.Store(&b, password); err != nil {
		return []byte{}, err
	}
	return b.Bytes(), nil
}

func IsValidKeyStoreSecret(secret corev1.Secret, keystoreCN string, keyStorePassword []byte) bool {
	if secret.Data[constants.KeystoreName] != nil {
		return IsValidKeyStore(keystoreCN, keyStorePassword, secret.Data[constants.KeystoreName])
	}
	return false
}

func IsValidKeyStore(keystoreCN string, keyStorePassword, keyStoreData []byte) bool {
	keyStore := keystore.New()
	// FIX!!!! err == nil or something else!
	if err := keyStore.Load(bytes.NewReader(keyStoreData), keyStorePassword); err != nil {
		log.Error(err)
		return false
	}
	if ok := keyStore.IsPrivateKeyEntry(constants.KeystoreAlias); !ok {
		return false
	}
	pke, err := keyStore.GetPrivateKeyEntry(constants.KeystoreAlias, keyStorePassword)
	if err != nil {
		log.Error(err)
		return false
	}
	if commonNameExists(keystoreCN, pke.CertificateChain) {
		return true
	}
	return false
}

func commonNameExists(keystoreCN string, certChain []keystore.Certificate) bool {
	for _, certEntry := range certChain {
		cert, err := x509.ParseCertificate(certEntry.Content)
		if err != nil {
			log.Error(err)
		}
		if cert.Subject.CommonName == keystoreCN {
			return true
		}
	}
	return false
}

// GenerateTruststore returns a Java Truststore with a Trusted CA bundle
func GenerateTruststore(caBundle []byte) ([]byte, error) {
	var b bytes.Buffer
	trustIn := keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: keystore.Certificate{
			Type:    "X509",
			Content: caBundle,
		},
	}
	trustStore := keystore.New()
	if err := trustStore.SetTrustedCertificateEntry(constants.KeystoreAlias, trustIn); err != nil {
		return []byte{}, err
	}
	if err := trustStore.Store(&b, []byte(constants.TruststorePwd)); err != nil {
		return []byte{}, err
	}
	return b.Bytes(), nil
}

func IsValidTruststoreSecret(secret corev1.Secret, caBundle []byte) bool {
	if secret.Data[constants.TruststoreName] != nil {
		return IsValidTruststore(caBundle, secret.Data[constants.TruststoreName])
	}
	return false
}

func IsValidTruststore(caBundle, keyStoreData []byte) bool {
	trustStore := keystore.New()
	if err := trustStore.Load(bytes.NewReader(keyStoreData), []byte(constants.TruststorePwd)); err != nil {
		log.Error(err)
		return false
	}
	if ok := trustStore.IsTrustedCertificateEntry(constants.KeystoreAlias); !ok {
		return false
	}
	trust, err := trustStore.GetTrustedCertificateEntry(constants.KeystoreAlias)
	if err != nil {
		log.Error(err)
		return false
	}
	if caBundleExists(caBundle, trust.Certificate) {
		return true
	}
	return false
}

func caBundleExists(caBundle []byte, certificate keystore.Certificate) bool {
	if len(caBundle) > 0 {
		if reflect.DeepEqual(caBundle, certificate.Content) {
			return true
		}
	}
	return false
}

// ????????????????
// any way to use openshift's CA for signing instead ??
func genCert(commonName string) (cert []byte, derPK []byte, err error) {
	sAndI := pkix.Name{
		CommonName: commonName,
		//OrganizationalUnit: []string{"Engineering"},
		//Organization:       []string{"RedHat"},
		//Locality:           []string{"Raleigh"},
		//Province:           []string{"NC"},
		//Country:            []string{"US"},
	}

	serialNumber, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Error("Error getting serial number. ", err)
		return nil, nil, err
	}

	ca := &x509.Certificate{
		Subject:            sAndI,
		Issuer:             sAndI,
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.ECDSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(10, 0, 0),
		SerialNumber:       serialNumber,
		SubjectKeyId:       sha256.New().Sum(nil),
		IsCA:               true,
		// BasicConstraintsValid: true,
		// ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		log.Error("create key failed. ", err)
		return nil, nil, err
	}

	cert, err = x509.CreateCertificate(crand.Reader, ca, ca, &priv.PublicKey, priv)
	if err != nil {
		log.Error("create cert failed. ", err)
		return nil, nil, err
	}

	derPK, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Error("Marshal to PKCS8 key failed. ", err)
		return nil, nil, err
	}

	return cert, derPK, nil
}

// GeneratePassword returns an alphanumeric password of the length provided
func GeneratePassword(length int) []byte {
	rand.Seed(time.Now().UnixNano())
	digits := "0123456789"
	all := "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		digits
	buf := make([]byte, length)
	buf[0] = digits[rand.Intn(len(digits))]
	for i := 1; i < length; i++ {
		buf[i] = all[rand.Intn(len(all))]
	}

	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})

	return buf
}

// GetEnvVar returns the position of the EnvVar found by name
func GetEnvVar(envName string, env []corev1.EnvVar) int {
	for pos, v := range env {
		if v.Name == envName {
			return pos
		}
	}
	return -1
}

func EnvVarSet(env corev1.EnvVar, envList []corev1.EnvVar) bool {
	for _, e := range envList {
		if env.Name == e.Name && env.Value == e.Value {
			return true
		}
	}
	return false
}

// EnvOverride replaces or appends the provided EnvVar to the collection
func EnvOverride(dst, src []corev1.EnvVar) []corev1.EnvVar {
	for _, cre := range src {
		pos := GetEnvVar(cre.Name, dst)
		if pos != -1 {
			dst[pos] = cre
		} else {
			dst = append(dst, cre)
		}
	}
	return dst
}

// EnvVarCheck checks whether the src and dst []EnvVar have the same values
func EnvVarCheck(dst, src []corev1.EnvVar) bool {
	for _, denv := range dst {
		if !EnvVarSet(denv, src) {
			return false
		}
	}
	for _, senv := range src {
		if !EnvVarSet(senv, dst) {
			return false
		}
	}
	return true
}

func GetNamespacedName(object metav1.Object) types.NamespacedName {
	return types.NamespacedName{
		Name:      object.GetName(),
		Namespace: object.GetNamespace(),
	}
}

func Find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}
