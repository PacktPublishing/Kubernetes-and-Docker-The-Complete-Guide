#!/bin/bash
clear

tput setaf 5
echo -e "\n*******************************************************************************************************************"
echo -e "Installing Step 1 of OIDC Installation"
echo -e "*******************************************************************************************************************"

echo -e "\n\n*******************************************************************************************************************"
echo -e "Deploying Dashboard 2"
echo -e "*******************************************************************************************************************"
tput setaf 2
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.0/aio/deploy/recommended.yaml

tput setaf 5
echo -e "\n*******************************************************************************************************************"
echo -e "Adding Helm repository and updating"
echo -e "*******************************************************************************************************************"
tput setaf 2
helm repo add tremolo https://nexus.tremolo.io/repository/helm/
helm repo update

tput setaf 5
echo -e "\n*******************************************************************************************************************"
echo -e "Creating openunison namespace"
echo -e "*******************************************************************************************************************"
tput setaf 2
kubectl create ns openunison

tput setaf 5
echo -e "\n*******************************************************************************************************************"
echo -e "Deploying chart operator"
echo -e "*******************************************************************************************************************"
tput setaf 2
helm install openunison tremolo/openunison-operator --namespace openunison

tput setaf 5
echo -e "\n*******************************************************************************************************************"
echo -e "Creating secret - DO NOT USE THIS IN PRODUCTION"
echo -e "*******************************************************************************************************************"
tput setaf 2

kubectl create -f - <<EOF
 apiVersion: v1
 type: Opaque
 metadata:
   name: orchestra-secrets-source
   namespace: openunison
 data:
   K8S_DB_SECRET: cGFzc3dvcmQK
   unisonKeystorePassword: cGFzc3dvcmQK
 kind: Secret
EOF

tput setaf 3
echo -e "\n\n*******************************************************************************************************************"
echo -e "Operator deployed.  Please register for the SAML2 Test Lab before running the step 2 installation script"
echo -e "After regitering, edit the values.yaml file with the information for your SAML2 lab. \n"
echo -e "\nOnce you register and you have updates the values.yaml file, execute the next script ./install-oidc-step2.sh"
echo -e "*******************************************************************************************************************\n"
tput setaf 2


