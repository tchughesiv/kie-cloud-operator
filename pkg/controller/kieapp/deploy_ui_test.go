package kieapp

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/blang/semver"
	"github.com/ghodss/yaml"
	"github.com/gobuffalo/packr/v2"
	"github.com/kiegroup/kie-cloud-operator/pkg/controller/kieapp/constants"
	"github.com/kiegroup/kie-cloud-operator/pkg/controller/kieapp/defaults"
	"github.com/kiegroup/kie-cloud-operator/pkg/controller/kieapp/shared"
	"github.com/kiegroup/kie-cloud-operator/pkg/controller/kieapp/test"
	"github.com/kiegroup/kie-cloud-operator/version"
	routev1 "github.com/openshift/api/route/v1"
	operators "github.com/operator-framework/operator-lifecycle-manager/pkg/api/apis/operators/v1alpha1"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func TestUpdateLink(t *testing.T) {
	opMajor, opMinor, _ := defaults.MajorMinorMicro(version.Version)
	box := packr.New("CSV", "../../../deploy/catalog_resources/redhat/"+opMajor+"."+opMinor)
	bytes, err := box.Find("businessautomation-operator." + version.Version + ".clusterserviceversion.yaml")
	assert.Nil(t, err, "Error reading CSV file")
	csv := &operators.ClusterServiceVersion{}
	err = yaml.Unmarshal(bytes, csv)
	assert.Nil(t, err, "Error parsing CSV file")
	assert.False(t, strings.Contains(csv.Spec.Description, constants.ConsoleDescription), "Should be no information about link in description")
	checkCSV(t, csv)
}

func TestUpdateExistingLink(t *testing.T) {
	opMajor, opMinor, _ := defaults.MajorMinorMicro(version.Version)
	box := packr.New("CSV", "../../../deploy/catalog_resources/redhat/"+opMajor+"."+opMinor)
	bytes, err := box.Find("businessautomation-operator." + version.Version + ".clusterserviceversion.yaml")
	assert.Nil(t, err, "Error reading CSV file")
	csv := &operators.ClusterServiceVersion{}
	err = yaml.Unmarshal(bytes, csv)
	assert.Nil(t, err, "Error parsing CSV file")
	assert.False(t, strings.Contains(csv.Spec.Description, constants.ConsoleDescription), "Should be no information about link in description")
	csv.Spec.Links = append([]operators.AppLink{{Name: constants.ConsoleLinkName, URL: "some-bad-link"}}, csv.Spec.Links...)
	checkCSV(t, csv)
}

func TestProxyVersion(t *testing.T) {
	checkConsoleProxySettings(t, semver.MustParse("4.3.2"))
	checkConsoleProxySettings(t, semver.MustParse("4.3.0"))
	checkConsoleProxySettings(t, semver.MustParse("4.2.0"))
	checkConsoleProxySettings(t, semver.MustParse("4.1.0"))

	// ocp 3.x versions should default to latest oauth3 image
	checkConsoleProxySettings(t, semver.MustParse("3.11.0"))
	checkConsoleProxySettings(t, semver.MustParse("3.5.0"))

	// unknown ocp version should default to 'latest' proxy image
	checkConsoleProxySettings(t, semver.MustParse("7.3.5"))
	checkConsoleProxySettings(t, semver.MustParse("4.11.0"))
	checkConsoleProxySettings(t, semver.Version{})
}

func checkConsoleProxySettings(t *testing.T, v semver.Version) {
	box := packr.New("Operator", "../../../deploy")
	bytes, err := box.Find("operator.yaml")
	assert.Nil(t, err, "Error reading Operator file")
	operator := &appsv1.Deployment{}
	err = yaml.Unmarshal(bytes, operator)
	assert.Nil(t, err, "Error parsing Operator file")
	operatorName = operator.Name
	for _, envVar := range operator.Spec.Template.Spec.Containers[0].Env {
		if envVar.Name == fmt.Sprintf(constants.OauthVar+"%d.%d", v.Major, v.Minor) {
			os.Setenv(envVar.Name, envVar.Value)
		}
	}
	for _, envVar := range operator.Spec.Template.Spec.Containers[0].Env {
		if envVar.Name == fmt.Sprintf(constants.OauthVar+"%d", v.Minor) {
			os.Setenv(envVar.Name, envVar.Value)
		}
	}
	pod := getPod(operator.Namespace, getImage(operator), "saName", v, operator)
	caBundlePath := "--openshift-ca=/etc/pki/ca-trust/extracted/crt/ca-bundle.crt"
	if v.Major == 3 {
		assert.NotContains(t, pod.Spec.Containers[0].Args, caBundlePath)
		assert.Equal(t,
			map[string]string{
				"service.alpha.openshift.io/serving-cert-secret-name": operator.Name + "-proxy-tls",
			},
			getService(pod.Namespace, v.Major).Annotations,
			"should use service.alpha.openshift.io version of serving-cert-secret-name",
		)
		assert.Equal(t, constants.Oauth3ImageLatestURL, pod.Spec.Containers[0].Image)
	} else {
		if v.GE(semver.MustParse("4.2.0")) || reflect.DeepEqual(v, semver.Version{}) {
			assert.Contains(t, pod.Spec.Containers[0].Args, caBundlePath)
		} else {
			log.Warn(err)
		}
		assert.Equal(t,
			map[string]string{
				"service.beta.openshift.io/serving-cert-secret-name": operator.Name + "-proxy-tls",
			},
			getService(pod.Namespace, v.Major).Annotations,
			"should use service.beta.openshift.io version of serving-cert-secret-name",
		)
		if _, ok := shared.Find(constants.SupportedOcpVersions, fmt.Sprintf("%d.%d", v.Major, v.Minor)); ok {
			assert.Equal(t, constants.Oauth4ImageURL+":"+fmt.Sprintf("%d.%d", v.Major, v.Minor), pod.Spec.Containers[0].Image)
		} else {
			assert.Equal(t, constants.Oauth4ImageLatestURL, pod.Spec.Containers[0].Image)
		}
	}
}

func checkCSV(t *testing.T, csv *operators.ClusterServiceVersion) {
	service := test.MockServiceWithExtraScheme(&operators.ClusterServiceVersion{}, &appsv1.Deployment{}, &corev1.Pod{})
	err := service.Create(context.TODO(), csv)
	assert.Nil(t, err, "Error creating the CSV")

	box := packr.New("Operator", "../../../deploy")
	bytes, err := box.Find("operator.yaml")
	assert.Nil(t, err, "Error reading Operator file")
	operator := &appsv1.Deployment{}
	err = yaml.Unmarshal(bytes, operator)
	assert.Nil(t, err, "Error parsing Operator file")

	operator.Namespace = "placeholder"
	err = controllerutil.SetControllerReference(csv, operator, service.GetScheme())
	assert.Nil(t, err, "Error setting operator owner as CSV")

	err = service.Create(context.TODO(), operator)
	assert.Nil(t, err, "Error creating the Operator")

	var url string
	service.CreateFunc = func(ctx context.Context, obj runtime.Object, opts ...client.CreateOption) error {
		if route, matched := obj.(*routev1.Route); matched {
			url = fmt.Sprintf("%s.apps.example.com", route.Name)
			route.Spec.Host = url
		}
		return service.Client.Create(ctx, obj, opts...)
	}
	deployConsole(&Reconciler{Service: service, OcpVersion: semver.Version{}}, operator)

	updatedCSV := &operators.ClusterServiceVersion{}
	err = service.Get(context.TODO(), types.NamespacedName{Name: csv.Name, Namespace: csv.Namespace}, updatedCSV)
	assert.Nil(t, err, "Error fetching CSV from client")

	link := getConsoleLink(updatedCSV)
	assert.NotNil(t, link, "Found no console link in CSV")
	assert.True(t, strings.Contains(updatedCSV.Spec.Description, constants.ConsoleDescription), "Found no information about link in description")
	assert.Equal(t, fmt.Sprintf("https://%s", url), link.URL, "The console link did not have the expected value")
}
