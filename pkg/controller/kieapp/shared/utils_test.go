package shared

import (
	"io/ioutil"
	"testing"

	"github.com/kiegroup/kie-cloud-operator/pkg/controller/kieapp/constants"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestEnvOverride(t *testing.T) {
	src := []corev1.EnvVar{
		{
			Name:  "test1",
			Value: "value1",
		},
		{
			Name:  "test2",
			Value: "value2",
		},
	}
	dst := []corev1.EnvVar{
		{
			Name:  "test1",
			Value: "valueX",
		},
		{
			Name:  "test3",
			Value: "value3",
		},
	}
	result := EnvOverride(src, dst)
	assert.Equal(t, 3, len(result))
	assert.Equal(t, result[0], dst[0])
	assert.Equal(t, result[1], src[1])
	assert.Equal(t, result[2], dst[1])
}

func TestGetEnvVar(t *testing.T) {
	vars := []corev1.EnvVar{
		{
			Name:  "test1",
			Value: "value1",
		},
		{
			Name:  "test2",
			Value: "value2",
		},
	}
	pos := GetEnvVar("test1", vars)
	assert.Equal(t, 0, pos)

	pos = GetEnvVar("other", vars)
	assert.Equal(t, -1, pos)
}

func TestGenerateKeystore(t *testing.T) {
	password := GeneratePassword(8)
	assert.Len(t, password, 8)

	commonName := "test-https"
	keyBytes, err := GenerateKeystore(commonName, password)
	assert.Nil(t, err)
	assert.True(t, IsValidKeyStore(commonName, password, keyBytes))
}

func TestGenerateTruststore(t *testing.T) {
	caBundle, err := ioutil.ReadFile(constants.CaBundleKey)
	assert.Nil(t, err)
	assert.NotEmpty(t, caBundle)

	keyBytes, err := GenerateTruststore(caBundle)
	assert.Nil(t, err)
	assert.True(t, IsValidTruststore(caBundle, keyBytes))
}

func TestEnvVarCheck(t *testing.T) {
	empty := []corev1.EnvVar{}
	a := []corev1.EnvVar{
		{Name: "A", Value: "1"},
	}
	b := []corev1.EnvVar{
		{Name: "A", Value: "2"},
	}
	c := []corev1.EnvVar{
		{Name: "A", Value: "1"},
		{Name: "B", Value: "1"},
	}

	assert.True(t, EnvVarCheck(empty, empty))
	assert.True(t, EnvVarCheck(a, a))

	assert.False(t, EnvVarCheck(empty, a))
	assert.False(t, EnvVarCheck(a, empty))

	assert.False(t, EnvVarCheck(a, b))
	assert.False(t, EnvVarCheck(b, a))

	assert.False(t, EnvVarCheck(a, c))
	assert.False(t, EnvVarCheck(c, b))
}
