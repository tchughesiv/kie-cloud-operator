package controller

import (
	"fmt"

	"github.com/RHsyseng/operator-utils/pkg/logs"
	"github.com/RHsyseng/operator-utils/pkg/utils/kubernetes"
	"github.com/RHsyseng/operator-utils/pkg/utils/openshift"
	"github.com/kiegroup/kie-cloud-operator/pkg/controller/kieapp"
	"github.com/kiegroup/kie-cloud-operator/pkg/controller/kieapp/constants"
	"github.com/kiegroup/kie-cloud-operator/pkg/controller/kieapp/shared"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var log = logs.GetLogger("kieapp.initializer")

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	addManager := func(mgr manager.Manager) error {
		k8sService := kubernetes.GetInstance(mgr)
		reconciler := kieapp.Reconciler{Service: &k8sService}
		info, err := openshift.GetPlatformInfo(mgr.GetConfig())
		if err != nil {
			log.Error(err)
		}
		if info.IsOpenShift() {
			mappedVersion := openshift.MapKnownVersion(info)
			if mappedVersion.Version != "" {
				log.Info(fmt.Sprintf("OpenShift Version: %s", mappedVersion.Version))
				reconciler.OcpVersion.Version = mappedVersion.Version
				reconciler.OcpVersion.Major = mappedVersion.MajorVersion()
				reconciler.OcpVersion.Minor = mappedVersion.MinorVersion()
				if _, ok := shared.Find(constants.SupportedOcpVersions, reconciler.OcpVersion.Version); !ok {
					log.Warn("OpenShift version not supported.")
				}
			} else {
				log.Warn("OpenShift version could not be determined.")
			}
			if i, err := kieapp.CompareVersion(reconciler.OcpVersion, "4.3"); err == nil && i >= 0 {
				kieapp.CreateConsoleYAMLSamples(&reconciler)
			} else {
				log.Warn(err)
			}
		}
		return kieapp.Add(mgr, &reconciler)
	}
	AddToManagerFuncs = []func(manager.Manager) error{addManager}
}
