#!/bin/bash

mkdir -p ssl

cat << EOF > ssl/req.cnf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
#subjectAltName = @alt_names

#[alt_names]
#DNS.1 = unison.rheldemo.lan
EOF

openssl genrsa -out ssl/ca-key.pem 2048
openssl req -x509 -new -nodes -key ssl/ca-key.pem -days 3650 -sha256 -out ssl/ca.pem -subj "/CN=kube-ca"


#Change your subject to match your OU_HOST
openssl genrsa -out ssl/key.pem 2048
openssl req -new -key ssl/key.pem -out ssl/csr.pem -subj "/C=US/ST=Virginia/L=Arlington/O=Trmeolo Security/OU=Demo/CN=oidcidp.tremolo.lan" -sha256 -config ssl/req.cnf
openssl x509 -req -in ssl/csr.pem -CA ssl/ca.pem -CAkey ssl/ca-key.pem -CAcreateserial -sha256 -out ssl/cert.pem -days 3650  -extensions v3_req -extfile ssl/req.cnf
