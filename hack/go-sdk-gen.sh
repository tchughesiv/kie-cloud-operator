#!/bin/sh

source ./hack/go-mod-env.sh

operator-sdk generate k8s
operator-sdk generate crds
mv deploy/crds/app.kiegroup.org_kieapps_crd.yaml deploy/crds/kieapp.crd.yaml

CSVVERSION=$(go run getversion.go -csv)
for OLMDIR in deploy/olm-catalog/dev deploy/olm-catalog/test deploy/olm-catalog/prod
do
    cp -p deploy/crds/kieapp.crd.yaml ${OLMDIR}/${CSVVERSION}/manifests/
done
