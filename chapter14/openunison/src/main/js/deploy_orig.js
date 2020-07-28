//    Copyright 2018 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

inProp['K8S_DB_SECRET'] = java.util.UUID.randomUUID().toString();


print("Loading CertUtils");
var CertUtils = Java.type("com.tremolosecurity.kubernetes.artifacts.util.CertUtils");

print("Creating openunison keystore");

ksPassword = inProp['unisonKeystorePassword'];
ouKs = Java.type("java.security.KeyStore").getInstance("PKCS12");
ouKs.load(null,ksPassword.toCharArray());

use_k8s_cm = inProp['USE_K8S_CM'] == "true";

print("Generating client certificate for activemq");
amqCertInfo = {
    "serverName":"amq-client",
    "ou":"kubernetes",
    "o":"tremolo",
    "l":"cloud",
    "st":"cncf",
    "c":"ea",
    "caCert":false
}

var amqClientx509data = CertUtils.createCertificate(amqCertInfo);

CertUtils.saveX509ToKeystore(ouKs,ksPassword,"amq-client",amqClientx509data);

print("generate the amq keystore");

amqKS = Java.type("java.security.KeyStore").getInstance("PKCS12");
amqKS.load(null,ksPassword.toCharArray());

print("trusting the amq client cert");
amqKS.setCertificateEntry('trusted-amq-client',ouKs.getCertificate('amq-client'));

print("generating the server side certificate");

amqSrvCertInfo = {
  "serverName":"amq.openunison.svc.cluster.local",
  "ou":"kubernetes",
  "o":"tremolo",
  "l":"cloud",
  "st":"cncf",
  "c":"ea",
  "caCert":false
}

var amqSrvx509data = CertUtils.createCertificate(amqSrvCertInfo);

if (use_k8s_cm) {
  print("create csr for activemq");

  amqCsrReq = {
    "apiVersion": "certificates.k8s.io/v1beta1",
    "kind": "CertificateSigningRequest",
    "metadata": {
      "name": "amq.openunison.svc.cluster.local",
    },
    "spec": {
      "request": java.util.Base64.getEncoder().encodeToString(CertUtils.generateCSR(amqSrvx509data).getBytes("utf-8")),
      "usages": [
        "digital signature",
        "key encipherment",
        "server auth"
      ]
    }
  };

  print("Requesting amq certificate");
  apiResp = k8s.postWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests',JSON.stringify(amqCsrReq));

  if (apiResp.code == 409) {
    print("CertManager is not enabled on this cluster.  Change USE_K8S_CM=false in your input.props");
    exit(1);
  }


  print("Approving amq certificate");
  approveReq = JSON.parse(apiResp.data);
  approveReq.status.conditions = [
    {
        "type":"Approved",
        "reason":"OpenUnison Deployment",
        "message":"This CSR was approved by the OpenUnison artifact deployment job"
    }
  ];

  apiResp = k8s.putWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/amq.openunison.svc.cluster.local/approval',JSON.stringify(approveReq));
  print("Retrieving amq certificate from API server");
  apiResp = k8s.callWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/amq.openunison.svc.cluster.local');
  print(apiResp.data);
  certResp = JSON.parse(apiResp.data);
  b64cert = certResp.status.certificate;

  if (b64cert == null || b64cert === "") {
    print("CertManager is not enabled on this cluster.  Change USE_K8S_CM=false in your input.props");
    exit(1);
  }

  CertUtils.importSignedCert(amqSrvx509data,b64cert);
} else {
  //not using CM, so store the amq cert directly into the openunison keystore
  ouKs.setCertificateEntry('trusted-amq-server',amqSrvx509data.getCertificate());
}

print("Saving amq certificate to amq keystore");
CertUtils.saveX509ToKeystore(amqKS,ksPassword,"broker",amqSrvx509data);







print("Generating openunison tls certificate");
certInfo = {
    "serverName":"openunison.openunison.svc.cluster.local",
    "ou":"kubernetes",
    "o":"tremolo",
    "l":"cloud",
    "st":"cncf",
    "c":"ea",
    "caCert":false
}

var x509data = CertUtils.createCertificate(certInfo);

if (use_k8s_cm) {
  print("Creating CSR for API server");



  csrReq = {
      "apiVersion": "certificates.k8s.io/v1beta1",
      "kind": "CertificateSigningRequest",
      "metadata": {
        "name": "openunison.openunison.svc.cluster.local",
      },
      "spec": {
        "request": java.util.Base64.getEncoder().encodeToString(CertUtils.generateCSR(x509data).getBytes("utf-8")),
        "usages": [
          "digital signature",
          "key encipherment",
          "server auth"
        ]
      }
    };

  print("Requesting certificate");
  apiResp = k8s.postWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests',JSON.stringify(csrReq));

  print("Approving certificate");
  approveReq = JSON.parse(apiResp.data);
  approveReq.status.conditions = [
      {
          "type":"Approved",
          "reason":"OpenUnison Deployment",
          "message":"This CSR was approved by the OpenUnison artifact deployment job"
      }
  ];

  apiResp = k8s.putWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/openunison.openunison.svc.cluster.local/approval',JSON.stringify(approveReq));
  print("Retrieving certificate from API server");
  apiResp = k8s.callWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/openunison.openunison.svc.cluster.local','java.util.Base64.getDecoder().decode(JSON.parse(ws_response_json).status.certificate);check_ws_response=true;',10);
  print(apiResp.data);
  certResp = JSON.parse(apiResp.data);
  b64cert = certResp.status.certificate;
  CertUtils.importSignedCert(x509data,b64cert);
}

print("Saving certificate to keystore");
CertUtils.saveX509ToKeystore(ouKs,ksPassword,"unison-tls",x509data);
CertUtils.createKey(ouKs,"session-unison",ksPassword);
CertUtils.createKey(ouKs,"lastmile-oidc",ksPassword);

print("Generating OIDC Certificate");

certInfo = {
    "serverName":"unison-saml2-rp-sig",
    "ou":"kubernetes",
    "o":"tremolo",
    "l":"cloud",
    "st":"cncf",
    "c":"ea",
    "caCert":false
}

x509data = CertUtils.createCertificate(certInfo);
CertUtils.saveX509ToKeystore(ouKs,ksPassword,"unison-saml2-rp-sig",x509data);

rp_sig_cert_bytes = x509data.getCertificate();

print("Storing k8s certs");
ouKs.setCertificateEntry('k8s-master',k8s.getCertificate('k8s-master'));


//import metadata

fXmlFile = new java.io.File("/etc/extracerts/saml2-metadata.xml");
dbFactory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
dBuilder = dbFactory.newDocumentBuilder();
doc = dBuilder.parse(fXmlFile);

//get entity id
entityId = doc.getElementsByTagName("EntityDescriptor").item(0).getAttribute("entityID");

idp = doc.getElementsByTagName("IDPSSODescriptor").item(0);

singleLogoutURL = "";
ssoGetURL = "";
ssoPostURL = "";
sig_certs = [];
sig_cert_to_use = ""

current_cert_choice = null;


//single logout
slos = idp.getElementsByTagName("SingleLogoutService");

for (i = 0;i<slos.getLength();i++) {
    slo = slos.item(i);
    if (slo.getAttribute("Binding").equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")) {
        singleLogoutURL = slo.getAttribute("Location");
    }
}

//single sign on
ssos = idp.getElementsByTagName("SingleSignOnService");

for (i = 0;i<ssos.getLength();i++) {
    sso = ssos.item(i);
    if (sso.getAttribute("Binding").equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")) {
        ssoGetURL = sso.getAttribute("Location");
    } else if (sso.getAttribute("Binding").equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")) {
        ssoPostURL = sso.getAttribute("Location");
    }
}

keys = idp.getElementsByTagName("KeyDescriptor");

for (i=0;i<keys.getLength();i++) {
    key = keys.item(i);

    if (key.getAttribute("use").equalsIgnoreCase("signing")) {
        sig_cert = key.getElementsByTagName("KeyInfo").item(0).getElementsByTagName("X509Data").item(0).getElementsByTagName("X509Certificate").item(0).getTextContent();
        sig_certs.push(sig_cert);
    }
}

if (sig_certs.length == 1) {
    current_cert_choice = com.tremolosecurity.kubernetes.artifacts.util.CertUtils.string2cert(sig_certs[0]);
} else {
    for (i=0;i<sig_certs.length;i++) {
        current_cert = com.tremolosecurity.kubernetes.artifacts.util.CertUtils.string2cert(sig_certs[i]);
        if (current_cert_choice == null) {
            current_cert_choice = current_cert;
        } else {
            if (current_cert_choice.getNotAfter().compareTo(current_cert.getNotAfter())  < 0  ) {
                current_cert_choice = current_cert;
            }
        }
    }
    
}


inProp['IDP_ENTITY_ID'] = entityId;
inProp['IDP_POST'] = ssoPostURL;
inProp['IDP_REDIR'] = ssoGetURL;
inProp['IDP_LOGOUT'] = singleLogoutURL;


ouKs.setCertificateEntry('idp-saml2-sig',current_cert_choice);












print("Generate Ingress Certificate");

ingressCertInfo = {
    "serverName": inProp["OU_HOST"],
    "ou":inProp["OU_CERT_OU"],
    "o":inProp["OU_CERT_O"],
    "l":inProp["OU_CERT_L"],
    "st":inProp["OU_CERT_ST"],
    "c":inProp["OU_CERT_C"],
    "caCert":true,
    "subjectAlternativeNames":[
        inProp["K8S_DASHBOARD_HOST"]
    ]
}

ingressX509data = CertUtils.createCertificate(ingressCertInfo);

print("Import OpenUnison certificate into keystore");
ouKs.setCertificateEntry('unison-ca',ingressX509data.getCertificate());

print("Importing the dashboard");

res = k8s.callWS('/api/v1/namespaces/kube-system/pods');
pods = JSON.parse(res.data);

 k8s_db_uri = null;

 for (i=0;i<pods.items.length;i++) {
  pod = pods.items[i];
  if (pod.metadata.name.startsWith("kubernetes-dashboard")) {
    k8s_db_uri = pod.metadata.selfLink;
  }
}


 if (k8s_db_uri == null) {
  print("Dashboard not present, deploying");
  k8s.kubectlCreateFromURL("https://raw.githubusercontent.com/kubernetes/dashboard/v1.10.1/src/deploy/recommended/kubernetes-dashboard.yaml");

   res = k8s.callWS('/api/v1/namespaces/kube-system/pods');
  pods = JSON.parse(res.data);


   for (i=0;i<pods.items.length;i++) {
    pod = pods.items[i];
    if (pod.metadata.name.startsWith("kubernetes-dashboard")) {
      k8s_db_uri = pod.metadata.selfLink;
    }
  }
} else {
  print("Skipping import of dashboard");
}


print("Generating dashboard tls certificate");
dbCertInfo = {
    "serverName":"kubernetes-dashboard.kube-system.svc.cluster.local",
    "ou":"kubernetes",
    "o":"tremolo",
    "l":"cloud",
    "st":"cncf",
    "c":"ea",
    "caCert":false
}

dbX509data = CertUtils.createCertificate(dbCertInfo);

if (use_k8s_cm) {
  print("Creating CSR for API server");



  csrReq = {
      "apiVersion": "certificates.k8s.io/v1beta1",
      "kind": "CertificateSigningRequest",
      "metadata": {
        "name": "kubernetes-dashboard.kube-system.svc.cluster.local",
      },
      "spec": {
        "request": java.util.Base64.getEncoder().encodeToString(CertUtils.generateCSR(dbX509data).getBytes("utf-8")),
        "usages": [
          "digital signature",
          "key encipherment",
          "server auth"
        ]
      }
    };

  print("Requesting certificate");
  apiResp = k8s.postWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests',JSON.stringify(csrReq));
  print("Approving certificate");
  approveReq = JSON.parse(apiResp.data);
  approveReq.status.conditions = [
      {
          "type":"Approved",
          "reason":"OpenUnison Deployment",
          "message":"This CSR was approved by the OpenUnison artifact deployment job"
      }
  ];

  apiResp = k8s.putWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/kubernetes-dashboard.kube-system.svc.cluster.local/approval',JSON.stringify(approveReq));
  print("Retrieving certificate from API server");
  apiResp = k8s.callWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/kubernetes-dashboard.kube-system.svc.cluster.local','java.util.Base64.getDecoder().decode(JSON.parse(ws_response_json).status.certificate);check_ws_response=true;',10);
  print(apiResp.data);
  certResp = JSON.parse(apiResp.data);
  b64cert = certResp.status.certificate;
  CertUtils.importSignedCert(dbX509data,b64cert);
} else {
  //not using k8s cm, so just import the dashboard cert into the openunison keystore
  ouKs.setCertificateEntry("trusted-k8s-dasboard",dbX509data.getCertificate());
}
print("Creating dashboard secret");

dbsecret = {
    "apiVersion":"v1",
    "kind":"Secret",
    "type":"Opaque",
    "metadata": {
        "name":"kubernetes-dashboard-certs",
        "namespace":"kube-system"
    },
    "data":{
        "dashboard.crt": java.util.Base64.getEncoder().encodeToString(CertUtils.exportCert(dbX509data.getCertificate()).getBytes("UTF-8")),
        "dashboard.key": java.util.Base64.getEncoder().encodeToString(CertUtils.exportKey(dbX509data.getKeyData().getPrivate()).getBytes("UTF-8"))
    }
};

res = k8s.postWS('/api/v1/namespaces/kube-system/secrets',JSON.stringify(dbsecret));

if (res["code"] == 409) {
  print("Secret alread exists, lets delete then recreate");
  k8s.deleteWS('/api/v1/namespaces/kube-system/secrets/kubernetes-dashboard-certs');

  print("re-creating");
  k8s.postWS('/api/v1/namespaces/kube-system/secrets',JSON.stringify(dbsecret));
}

print("restarting the dashboard")

print("Deleting " + k8s_db_uri);
k8s.deleteWS(k8s_db_uri);


print("Create the openunison namespace");

ouNS = {
    "apiVersion":"v1",
    "kind":"Namespace",
    "metadata":{
        "creationTimestamp":null,
        "name":"openunison"
    },
    "spec":{},
    "status":{}
};

k8s.postWS('/api/v1/namespaces',JSON.stringify(ouNS));

print("Create openunison service account");

k8s.postWS('/api/v1/namespaces/openunison/serviceaccounts',JSON.stringify({"apiVersion":"v1","kind":"ServiceAccount","metadata":{"creationTimestamp":null,"name":"openunison"}}));


print("Creating RBAC Bindings");

rbac = {
    "kind": "ClusterRoleBinding",
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "metadata": {
      "name": "openunison-cluster-administrators"
    },
    "subjects": [
      {
        "kind": "Group",
        "name": "k8s-cluster-administrators",
        "apiGroup": "rbac.authorization.k8s.io"
      },
      {
        "kind": "ServiceAccount",
        "name": "openunison",
        "namespace": "openunison"
      }
    ],
    "roleRef": {
      "kind": "ClusterRole",
      "name": "cluster-admin",
      "apiGroup": "rbac.authorization.k8s.io"
    }
  };

k8s.postWS("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",JSON.stringify(rbac));

rbac = {
    "kind": "ClusterRole",
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "metadata": {
      "name": "list-namespaces"
    },
    "rules": [
      {
        "apiGroups": [
          ""
        ],
        "resources": [
          "namespaces"
        ],
        "verbs": [
          "list"
        ]
      }
    ]
  };

k8s.postWS("/apis/rbac.authorization.k8s.io/v1/clusterroles",JSON.stringify(rbac));

rbac = {
    "kind": "ClusterRoleBinding",
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "metadata": {
      "name": "openunison-cluster-list-namespaces"
    },
    "subjects": [
      {
        "kind": "Group",
        "name": "users",
        "apiGroup": "rbac.authorization.k8s.io"
      }
    ],
    "roleRef": {
      "kind": "ClusterRole",
      "name": "list-namespaces",
      "apiGroup": "rbac.authorization.k8s.io"
    }
  };


k8s.postWS("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",JSON.stringify(rbac));

print("Create Ingress TLS Secret");

ingressSecret = {
    "apiVersion":"v1",
    "kind":"Secret",
    "type":"kubernetes.io/tls",
    "metadata": {
        "name":"ou-tls-certificate",
        "namespace":"openunison"
    },
    "data":{
        "tls.crt": java.util.Base64.getEncoder().encodeToString(CertUtils.exportCert(ingressX509data.getCertificate()).getBytes("UTF-8")),
        "tls.key": java.util.Base64.getEncoder().encodeToString(CertUtils.exportKey(ingressX509data.getKeyData().getPrivate()).getBytes("UTF-8"))
    }
};

k8s.postWS('/api/v1/namespaces/openunison/secrets',JSON.stringify(ingressSecret));


//load quartz sql
print("pulling quartz sql");
quartzSQL = com.tremolosecurity.kubernetes.artifacts.util.NetUtil.downloadFile("file:///etc/input-maps/quartz.sql");
print("parsing quartz sql");
parsedSQL = com.tremolosecurity.kubernetes.artifacts.util.DbUtils.parseSQL(quartzSQL);
print("runnins quartz sql");
com.tremolosecurity.kubernetes.artifacts.util.DbUtils.runSQL(parsedSQL,inProp["OU_JDBC_DRIVER"],inProp["OU_JDBC_URL"],inProp["OU_JDBC_USER"],inProp["OU_JDBC_PASSWORD"]);

//create the ip mask
myIp = com.tremolosecurity.kubernetes.artifacts.util.NetUtil.whatsMyIP();
mask = myIp.substring(0,myIp.indexOf("."));
inProp["OU_QUARTZ_MASK"] = mask;

print("Create activemq config secret");
amqFileSecrets = {
  "apiVersion":"v1",
    "kind":"Secret",
    "type":"Opaque",
    "metadata": {
        "name":"amq-secrets",
        "namespace":"openunison"
    },
    "data":{
      "activemq.xml":"PCEtLQogICAgTGljZW5zZWQgdG8gdGhlIEFwYWNoZSBTb2Z0d2FyZSBGb3VuZGF0aW9uIChBU0YpIHVuZGVyIG9uZSBvciBtb3JlCiAgICBjb250cmlidXRvciBsaWNlbnNlIGFncmVlbWVudHMuICBTZWUgdGhlIE5PVElDRSBmaWxlIGRpc3RyaWJ1dGVkIHdpdGgKICAgIHRoaXMgd29yayBmb3IgYWRkaXRpb25hbCBpbmZvcm1hdGlvbiByZWdhcmRpbmcgY29weXJpZ2h0IG93bmVyc2hpcC4KICAgIFRoZSBBU0YgbGljZW5zZXMgdGhpcyBmaWxlIHRvIFlvdSB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wCiAgICAodGhlICJMaWNlbnNlIik7IHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aAogICAgdGhlIExpY2Vuc2UuICBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXQKCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjAKCiAgICBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlCiAgICBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLAogICAgV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuCiAgICBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kCiAgICBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KLS0+CjwhLS0gU1RBUlQgU05JUFBFVDogZXhhbXBsZSAtLT4KPGJlYW5zCiAgeG1sbnM9Imh0dHA6Ly93d3cuc3ByaW5nZnJhbWV3b3JrLm9yZy9zY2hlbWEvYmVhbnMiCiAgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIKICB4c2k6c2NoZW1hTG9jYXRpb249Imh0dHA6Ly93d3cuc3ByaW5nZnJhbWV3b3JrLm9yZy9zY2hlbWEvYmVhbnMgaHR0cDovL3d3dy5zcHJpbmdmcmFtZXdvcmsub3JnL3NjaGVtYS9iZWFucy9zcHJpbmctYmVhbnMueHNkCiAgaHR0cDovL2FjdGl2ZW1xLmFwYWNoZS5vcmcvc2NoZW1hL2NvcmUgaHR0cDovL2FjdGl2ZW1xLmFwYWNoZS5vcmcvc2NoZW1hL2NvcmUvYWN0aXZlbXEtY29yZS54c2QiPgoKICAgIDwhLS0gQWxsb3dzIHVzIHRvIHVzZSBzeXN0ZW0gcHJvcGVydGllcyBhcyB2YXJpYWJsZXMgaW4gdGhpcyBjb25maWd1cmF0aW9uIGZpbGUgLS0+CiAgICA8YmVhbiBjbGFzcz0ib3JnLnNwcmluZ2ZyYW1ld29yay5iZWFucy5mYWN0b3J5LmNvbmZpZy5Qcm9wZXJ0eVBsYWNlaG9sZGVyQ29uZmlndXJlciI+CiAgICAgICAgPHByb3BlcnR5IG5hbWU9ImxvY2F0aW9ucyI+CiAgICAgICAgICAgIDx2YWx1ZT5maWxlOiR7YWN0aXZlbXEuY29uZn0vY3JlZGVudGlhbHMucHJvcGVydGllczwvdmFsdWU+CiAgICAgICAgPC9wcm9wZXJ0eT4KICAgIDwvYmVhbj4KCgoKICAgPCEtLSBBbGxvd3MgYWNjZXNzaW5nIHRoZSBzZXJ2ZXIgbG9nIC0tPgogICAgPGJlYW4gaWQ9ImxvZ1F1ZXJ5IiBjbGFzcz0iaW8uZmFicmljOC5pbnNpZ2h0LmxvZy5sb2c0ai5Mb2c0akxvZ1F1ZXJ5IgogICAgICAgICAgbGF6eS1pbml0PSJmYWxzZSIgc2NvcGU9InNpbmdsZXRvbiIKICAgICAgICAgIGluaXQtbWV0aG9kPSJzdGFydCIgZGVzdHJveS1tZXRob2Q9InN0b3AiPgogICAgPC9iZWFuPgoKICAgIDwhLS0KICAgICAgICBUaGUgPGJyb2tlcj4gZWxlbWVudCBpcyB1c2VkIHRvIGNvbmZpZ3VyZSB0aGUgQWN0aXZlTVEgYnJva2VyLgogICAgLS0+CiAgICA8YnJva2VyIHhtbG5zPSJodHRwOi8vYWN0aXZlbXEuYXBhY2hlLm9yZy9zY2hlbWEvY29yZSIgYnJva2VyTmFtZT0ibG9jYWxob3N0IiBkYXRhRGlyZWN0b3J5PSIke2FjdGl2ZW1xLmRhdGF9Ij4KCiAgICAgICAgPGRlc3RpbmF0aW9uUG9saWN5PgogICAgICAgICAgICA8cG9saWN5TWFwPgogICAgICAgICAgICAgIDxwb2xpY3lFbnRyaWVzPgogICAgICAgICAgICAgICAgPHBvbGljeUVudHJ5IHRvcGljPSI+IiA+CiAgICAgICAgICAgICAgICAgICAgPCEtLSBUaGUgY29uc3RhbnRQZW5kaW5nTWVzc2FnZUxpbWl0U3RyYXRlZ3kgaXMgdXNlZCB0byBwcmV2ZW50CiAgICAgICAgICAgICAgICAgICAgICAgICBzbG93IHRvcGljIGNvbnN1bWVycyB0byBibG9jayBwcm9kdWNlcnMgYW5kIGFmZmVjdCBvdGhlciBjb25zdW1lcnMKICAgICAgICAgICAgICAgICAgICAgICAgIGJ5IGxpbWl0aW5nIHRoZSBudW1iZXIgb2YgbWVzc2FnZXMgdGhhdCBhcmUgcmV0YWluZWQKICAgICAgICAgICAgICAgICAgICAgICAgIEZvciBtb3JlIGluZm9ybWF0aW9uLCBzZWU6CgogICAgICAgICAgICAgICAgICAgICAgICAgaHR0cDovL2FjdGl2ZW1xLmFwYWNoZS5vcmcvc2xvdy1jb25zdW1lci1oYW5kbGluZy5odG1sCgogICAgICAgICAgICAgICAgICAgIC0tPgogICAgICAgICAgICAgICAgICA8cGVuZGluZ01lc3NhZ2VMaW1pdFN0cmF0ZWd5PgogICAgICAgICAgICAgICAgICAgIDxjb25zdGFudFBlbmRpbmdNZXNzYWdlTGltaXRTdHJhdGVneSBsaW1pdD0iMTAwMCIvPgogICAgICAgICAgICAgICAgICA8L3BlbmRpbmdNZXNzYWdlTGltaXRTdHJhdGVneT4KICAgICAgICAgICAgICAgIDwvcG9saWN5RW50cnk+CiAgICAgICAgICAgICAgPC9wb2xpY3lFbnRyaWVzPgogICAgICAgICAgICA8L3BvbGljeU1hcD4KICAgICAgICA8L2Rlc3RpbmF0aW9uUG9saWN5PgoKCiAgICAgICAgPCEtLQogICAgICAgICAgICBUaGUgbWFuYWdlbWVudENvbnRleHQgaXMgdXNlZCB0byBjb25maWd1cmUgaG93IEFjdGl2ZU1RIGlzIGV4cG9zZWQgaW4KICAgICAgICAgICAgSk1YLiBCeSBkZWZhdWx0LCBBY3RpdmVNUSB1c2VzIHRoZSBNQmVhbiBzZXJ2ZXIgdGhhdCBpcyBzdGFydGVkIGJ5CiAgICAgICAgICAgIHRoZSBKVk0uIEZvciBtb3JlIGluZm9ybWF0aW9uLCBzZWU6CgogICAgICAgICAgICBodHRwOi8vYWN0aXZlbXEuYXBhY2hlLm9yZy9qbXguaHRtbAogICAgICAgIC0tPgogICAgICAgIDxtYW5hZ2VtZW50Q29udGV4dD4KICAgICAgICAgICAgPG1hbmFnZW1lbnRDb250ZXh0IGNyZWF0ZUNvbm5lY3Rvcj0iZmFsc2UiLz4KICAgICAgICA8L21hbmFnZW1lbnRDb250ZXh0PgoKICAgICAgICA8IS0tCiAgICAgICAgICAgIENvbmZpZ3VyZSBtZXNzYWdlIHBlcnNpc3RlbmNlIGZvciB0aGUgYnJva2VyLiBUaGUgZGVmYXVsdCBwZXJzaXN0ZW5jZQogICAgICAgICAgICBtZWNoYW5pc20gaXMgdGhlIEthaGFEQiBzdG9yZSAoaWRlbnRpZmllZCBieSB0aGUga2FoYURCIHRhZykuCiAgICAgICAgICAgIEZvciBtb3JlIGluZm9ybWF0aW9uLCBzZWU6CgogICAgICAgICAgICBodHRwOi8vYWN0aXZlbXEuYXBhY2hlLm9yZy9wZXJzaXN0ZW5jZS5odG1sCiAgICAgICAgLS0+CiAgICAgICAgPHBlcnNpc3RlbmNlQWRhcHRlcj4KICAgICAgIDxqZGJjUGVyc2lzdGVuY2VBZGFwdGVyCiAgICAgICAgICAgIGRhdGFEaXJlY3Rvcnk9IiR7YWN0aXZlbXEuYmFzZX0vZGF0YSIKICAgICAgICAgICAgZGF0YVNvdXJjZT0iI215c3FsLWRzIj4KICAgICAgICAgICAgPHN0YXRlbWVudHM+CiAgICAgICAgICAgICAgICA8c3RhdGVtZW50cyBiaW5hcnlEYXRhVHlwZT0iTUVESVVNQkxPQiIvPgogICAgICAgICAgICA8L3N0YXRlbWVudHM+CiAgICAgICAgPC9qZGJjUGVyc2lzdGVuY2VBZGFwdGVyPgogICAgPC9wZXJzaXN0ZW5jZUFkYXB0ZXI+CgogICAgICAgCgoKICAgICAgICAgIDwhLS0KICAgICAgICAgICAgVGhlIHN5c3RlbVVzYWdlIGNvbnRyb2xzIHRoZSBtYXhpbXVtIGFtb3VudCBvZiBzcGFjZSB0aGUgYnJva2VyIHdpbGwKICAgICAgICAgICAgdXNlIGJlZm9yZSBkaXNhYmxpbmcgY2FjaGluZyBhbmQvb3Igc2xvd2luZyBkb3duIHByb2R1Y2Vycy4gRm9yIG1vcmUgaW5mb3JtYXRpb24sIHNlZToKICAgICAgICAgICAgaHR0cDovL2FjdGl2ZW1xLmFwYWNoZS5vcmcvcHJvZHVjZXItZmxvdy1jb250cm9sLmh0bWwKICAgICAgICAgIC0tPgogICAgICAgICAgPHN5c3RlbVVzYWdlPgogICAgICAgICAgICA8c3lzdGVtVXNhZ2U+CiAgICAgICAgICAgICAgICA8bWVtb3J5VXNhZ2U+CiAgICAgICAgICAgICAgICAgICAgPG1lbW9yeVVzYWdlIHBlcmNlbnRPZkp2bUhlYXA9IjcwIiAvPgogICAgICAgICAgICAgICAgPC9tZW1vcnlVc2FnZT4KICAgICAgICAgICAgICAgIDxzdG9yZVVzYWdlPgogICAgICAgICAgICAgICAgICAgIDxzdG9yZVVzYWdlIGxpbWl0PSIyNTYgbWIiLz4KICAgICAgICAgICAgICAgIDwvc3RvcmVVc2FnZT4KICAgICAgICAgICAgICAgIDx0ZW1wVXNhZ2U+CiAgICAgICAgICAgICAgICAgICAgPHRlbXBVc2FnZSBsaW1pdD0iMjU2IG1iIi8+CiAgICAgICAgICAgICAgICA8L3RlbXBVc2FnZT4KICAgICAgICAgICAgPC9zeXN0ZW1Vc2FnZT4KICAgICAgICA8L3N5c3RlbVVzYWdlPgoKICAgICAgICA8IS0tCiAgICAgICAgICAgIFRoZSB0cmFuc3BvcnQgY29ubmVjdG9ycyBleHBvc2UgQWN0aXZlTVEgb3ZlciBhIGdpdmVuIHByb3RvY29sIHRvCiAgICAgICAgICAgIGNsaWVudHMgYW5kIG90aGVyIGJyb2tlcnMuIEZvciBtb3JlIGluZm9ybWF0aW9uLCBzZWU6CgogICAgICAgICAgICBodHRwOi8vYWN0aXZlbXEuYXBhY2hlLm9yZy9jb25maWd1cmluZy10cmFuc3BvcnRzLmh0bWwKICAgICAgICAtLT4KICAgICAgICAgPHNzbENvbnRleHQ+CiAgICAgICAgICAgIDxzc2xDb250ZXh0CiAgICAgICAgICAgICAgICAgICAga2V5U3RvcmU9Ii9ldGMvYWN0aXZlbXEvYW1xLnAxMiIga2V5U3RvcmVQYXNzd29yZD0iJHtUTFNfS1NfUFdEfSIKICAgICAgICAgICAgICAgICAgICB0cnVzdFN0b3JlPSIvZXRjL2FjdGl2ZW1xL2FtcS5wMTIiIHRydXN0U3RvcmVQYXNzd29yZD0iJHtUTFNfS1NfUFdEfSIgdHJ1c3RTdG9yZVR5cGU9InBrY3MxMiIga2V5U3RvcmVUeXBlPSJwa2NzMTIiLz4KICAgICAgICAgICAgPC9zc2xDb250ZXh0PgogICAgICAgIDx0cmFuc3BvcnRDb25uZWN0b3JzPgogICAgICAgICAgICA8IS0tIERPUyBwcm90ZWN0aW9uLCBsaW1pdCBjb25jdXJyZW50IGNvbm5lY3Rpb25zIHRvIDEwMDAgYW5kIGZyYW1lIHNpemUgdG8gMTAwTUIgLS0+CiAgICAgICAgICAgIDx0cmFuc3BvcnRDb25uZWN0b3IgbmFtZT0ib3BlbndpcmUiIHVyaT0ic3NsOi8vMC4wLjAuMDo2MTYxNj9tYXhpbXVtQ29ubmVjdGlvbnM9MTAwMCZhbXA7d2lyZUZvcm1hdC5tYXhGcmFtZVNpemU9MTA0ODU3NjAwJmFtcDtuZWVkQ2xpZW50QXV0aD10cnVlIi8+CiAgICAgICAgPC90cmFuc3BvcnRDb25uZWN0b3JzPgoKICAgICAgICA8IS0tIGRlc3Ryb3kgdGhlIHNwcmluZyBjb250ZXh0IG9uIHNodXRkb3duIHRvIHN0b3AgamV0dHkgLS0+CiAgICAgICAgPHNodXRkb3duSG9va3M+CiAgICAgICAgICAgIDxiZWFuIHhtbG5zPSJodHRwOi8vd3d3LnNwcmluZ2ZyYW1ld29yay5vcmcvc2NoZW1hL2JlYW5zIiBjbGFzcz0ib3JnLmFwYWNoZS5hY3RpdmVtcS5ob29rcy5TcHJpbmdDb250ZXh0SG9vayIgLz4KICAgICAgICA8L3NodXRkb3duSG9va3M+CgogICAgPC9icm9rZXI+CgogICAgPCEtLQogICAgICAgIEVuYWJsZSB3ZWIgY29uc29sZXMsIFJFU1QgYW5kIEFqYXggQVBJcyBhbmQgZGVtb3MKICAgICAgICBUaGUgd2ViIGNvbnNvbGVzIHJlcXVpcmVzIGJ5IGRlZmF1bHQgbG9naW4sIHlvdSBjYW4gZGlzYWJsZSB0aGlzIGluIHRoZSBqZXR0eS54bWwgZmlsZQoKICAgICAgICBUYWtlIGEgbG9vayBhdCAke0FDVElWRU1RX0hPTUV9L2NvbmYvamV0dHkueG1sIGZvciBtb3JlIGRldGFpbHMKICAgIC0tPgogICAgPCEtLSA8aW1wb3J0IHJlc291cmNlPSJmaWxlOi8vL3Vzci9sb2NhbC9hY3RpdmVtcS9jb25mL2pldHR5LnhtbCIvPiAtLT4KICAgIDxiZWFuIGlkPSJzZWN1cml0eUxvZ2luU2VydmljZSIgY2xhc3M9Im9yZy5lY2xpcHNlLmpldHR5LnNlY3VyaXR5Lkhhc2hMb2dpblNlcnZpY2UiPgogICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJuYW1lIiB2YWx1ZT0iQWN0aXZlTVFSZWFsbSIgLz4KICAgICAgICA8cHJvcGVydHkgbmFtZT0iY29uZmlnIiB2YWx1ZT0iJHthY3RpdmVtcS5jb25mfS9qZXR0eS1yZWFsbS5wcm9wZXJ0aWVzIiAvPgogICAgPC9iZWFuPgoKICAgIDxiZWFuIGlkPSJzZWN1cml0eUNvbnN0cmFpbnQiIGNsYXNzPSJvcmcuZWNsaXBzZS5qZXR0eS51dGlsLnNlY3VyaXR5LkNvbnN0cmFpbnQiPgogICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJuYW1lIiB2YWx1ZT0iQkFTSUMiIC8+CiAgICAgICAgPHByb3BlcnR5IG5hbWU9InJvbGVzIiB2YWx1ZT0idXNlcixhZG1pbiIgLz4KICAgICAgICA8IS0tIHNldCBhdXRoZW50aWNhdGU9ZmFsc2UgdG8gZGlzYWJsZSBsb2dpbiAtLT4KICAgICAgICA8cHJvcGVydHkgbmFtZT0iYXV0aGVudGljYXRlIiB2YWx1ZT0iZmFsc2UiIC8+CiAgICA8L2JlYW4+CiAgICA8YmVhbiBpZD0iYWRtaW5TZWN1cml0eUNvbnN0cmFpbnQiIGNsYXNzPSJvcmcuZWNsaXBzZS5qZXR0eS51dGlsLnNlY3VyaXR5LkNvbnN0cmFpbnQiPgogICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJuYW1lIiB2YWx1ZT0iQkFTSUMiIC8+CiAgICAgICAgPHByb3BlcnR5IG5hbWU9InJvbGVzIiB2YWx1ZT0iYWRtaW4iIC8+CiAgICAgICAgIDwhLS0gc2V0IGF1dGhlbnRpY2F0ZT1mYWxzZSB0byBkaXNhYmxlIGxvZ2luIC0tPgogICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJhdXRoZW50aWNhdGUiIHZhbHVlPSJmYWxzZSIgLz4KICAgIDwvYmVhbj4KICAgIDxiZWFuIGlkPSJzZWN1cml0eUNvbnN0cmFpbnRNYXBwaW5nIiBjbGFzcz0ib3JnLmVjbGlwc2UuamV0dHkuc2VjdXJpdHkuQ29uc3RyYWludE1hcHBpbmciPgogICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJjb25zdHJhaW50IiByZWY9InNlY3VyaXR5Q29uc3RyYWludCIgLz4KICAgICAgICA8cHJvcGVydHkgbmFtZT0icGF0aFNwZWMiIHZhbHVlPSIvYXBpLyosL2FkbWluLyosKi5qc3AiIC8+CiAgICA8L2JlYW4+CiAgICA8YmVhbiBpZD0iYWRtaW5TZWN1cml0eUNvbnN0cmFpbnRNYXBwaW5nIiBjbGFzcz0ib3JnLmVjbGlwc2UuamV0dHkuc2VjdXJpdHkuQ29uc3RyYWludE1hcHBpbmciPgogICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJjb25zdHJhaW50IiByZWY9ImFkbWluU2VjdXJpdHlDb25zdHJhaW50IiAvPgogICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJwYXRoU3BlYyIgdmFsdWU9IiouYWN0aW9uIiAvPgogICAgPC9iZWFuPgogICAgCiAgICA8YmVhbiBpZD0icmV3cml0ZUhhbmRsZXIiIGNsYXNzPSJvcmcuZWNsaXBzZS5qZXR0eS5yZXdyaXRlLmhhbmRsZXIuUmV3cml0ZUhhbmRsZXIiPgogICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJydWxlcyI+CiAgICAgICAgICAgIDxsaXN0PgogICAgICAgICAgICAgICAgPGJlYW4gaWQ9ImhlYWRlciIgY2xhc3M9Im9yZy5lY2xpcHNlLmpldHR5LnJld3JpdGUuaGFuZGxlci5IZWFkZXJQYXR0ZXJuUnVsZSI+CiAgICAgICAgICAgICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJwYXR0ZXJuIiB2YWx1ZT0iKiIvPgogICAgICAgICAgICAgICAgICA8cHJvcGVydHkgbmFtZT0ibmFtZSIgdmFsdWU9IlgtRlJBTUUtT1BUSU9OUyIvPgogICAgICAgICAgICAgICAgICA8cHJvcGVydHkgbmFtZT0idmFsdWUiIHZhbHVlPSJTQU1FT1JJR0lOIi8+CiAgICAgICAgICAgICAgICA8L2JlYW4+CiAgICAgICAgICAgIDwvbGlzdD4KICAgICAgICA8L3Byb3BlcnR5PgogICAgPC9iZWFuPgogICAgCgk8YmVhbiBpZD0ic2VjSGFuZGxlckNvbGxlY3Rpb24iIGNsYXNzPSJvcmcuZWNsaXBzZS5qZXR0eS5zZXJ2ZXIuaGFuZGxlci5IYW5kbGVyQ29sbGVjdGlvbiI+CgkJPHByb3BlcnR5IG5hbWU9ImhhbmRsZXJzIj4KCQkJPGxpc3Q+CiAgIAkgICAgICAgICAgICA8cmVmIGJlYW49InJld3JpdGVIYW5kbGVyIi8+CgkJCQk8YmVhbiBjbGFzcz0ib3JnLmVjbGlwc2UuamV0dHkud2ViYXBwLldlYkFwcENvbnRleHQiPgoJCQkJCTxwcm9wZXJ0eSBuYW1lPSJjb250ZXh0UGF0aCIgdmFsdWU9Ii9hZG1pbiIgLz4KCQkJCQk8cHJvcGVydHkgbmFtZT0icmVzb3VyY2VCYXNlIiB2YWx1ZT0iJHthY3RpdmVtcS5ob21lfS93ZWJhcHBzL2FkbWluIiAvPgoJCQkJCTxwcm9wZXJ0eSBuYW1lPSJsb2dVcmxPblN0YXJ0IiB2YWx1ZT0idHJ1ZSIgLz4KCQkJCTwvYmVhbj4KCQkJCTxiZWFuIGNsYXNzPSJvcmcuZWNsaXBzZS5qZXR0eS53ZWJhcHAuV2ViQXBwQ29udGV4dCI+CgkJCQkJPHByb3BlcnR5IG5hbWU9ImNvbnRleHRQYXRoIiB2YWx1ZT0iL2FwaSIgLz4KCQkJCQk8cHJvcGVydHkgbmFtZT0icmVzb3VyY2VCYXNlIiB2YWx1ZT0iJHthY3RpdmVtcS5ob21lfS93ZWJhcHBzL2FwaSIgLz4KCQkJCQk8cHJvcGVydHkgbmFtZT0ibG9nVXJsT25TdGFydCIgdmFsdWU9InRydWUiIC8+CgkJCQk8L2JlYW4+CgkJCQk8YmVhbiBjbGFzcz0ib3JnLmVjbGlwc2UuamV0dHkuc2VydmVyLmhhbmRsZXIuUmVzb3VyY2VIYW5kbGVyIj4KCQkJCQk8cHJvcGVydHkgbmFtZT0iZGlyZWN0b3JpZXNMaXN0ZWQiIHZhbHVlPSJmYWxzZSIgLz4KCQkJCQk8cHJvcGVydHkgbmFtZT0id2VsY29tZUZpbGVzIj4KCQkJCQkJPGxpc3Q+CgkJCQkJCQk8dmFsdWU+aW5kZXguaHRtbDwvdmFsdWU+CgkJCQkJCTwvbGlzdD4KCQkJCQk8L3Byb3BlcnR5PgoJCQkJCTxwcm9wZXJ0eSBuYW1lPSJyZXNvdXJjZUJhc2UiIHZhbHVlPSIke2FjdGl2ZW1xLmhvbWV9L3dlYmFwcHMvIiAvPgoJCQkJPC9iZWFuPgoJCQkJPGJlYW4gaWQ9ImRlZmF1bHRIYW5kbGVyIiBjbGFzcz0ib3JnLmVjbGlwc2UuamV0dHkuc2VydmVyLmhhbmRsZXIuRGVmYXVsdEhhbmRsZXIiPgoJCQkJCTxwcm9wZXJ0eSBuYW1lPSJzZXJ2ZUljb24iIHZhbHVlPSJmYWxzZSIgLz4KCQkJCTwvYmVhbj4KCQkJPC9saXN0PgoJCTwvcHJvcGVydHk+Cgk8L2JlYW4+ICAgIAogICAgPGJlYW4gaWQ9InNlY3VyaXR5SGFuZGxlciIgY2xhc3M9Im9yZy5lY2xpcHNlLmpldHR5LnNlY3VyaXR5LkNvbnN0cmFpbnRTZWN1cml0eUhhbmRsZXIiPgogICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJsb2dpblNlcnZpY2UiIHJlZj0ic2VjdXJpdHlMb2dpblNlcnZpY2UiIC8+CiAgICAgICAgPHByb3BlcnR5IG5hbWU9ImF1dGhlbnRpY2F0b3IiPgogICAgICAgICAgICA8YmVhbiBjbGFzcz0ib3JnLmVjbGlwc2UuamV0dHkuc2VjdXJpdHkuYXV0aGVudGljYXRpb24uQmFzaWNBdXRoZW50aWNhdG9yIiAvPgogICAgICAgIDwvcHJvcGVydHk+CiAgICAgICAgPHByb3BlcnR5IG5hbWU9ImNvbnN0cmFpbnRNYXBwaW5ncyI+CiAgICAgICAgICAgIDxsaXN0PgogICAgICAgICAgICAgICAgPHJlZiBiZWFuPSJhZG1pblNlY3VyaXR5Q29uc3RyYWludE1hcHBpbmciIC8+CiAgICAgICAgICAgICAgICA8cmVmIGJlYW49InNlY3VyaXR5Q29uc3RyYWludE1hcHBpbmciIC8+CiAgICAgICAgICAgIDwvbGlzdD4KICAgICAgICA8L3Byb3BlcnR5PgogICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJoYW5kbGVyIiByZWY9InNlY0hhbmRsZXJDb2xsZWN0aW9uIiAvPgogICAgPC9iZWFuPgoKICAgIDxiZWFuIGlkPSJjb250ZXh0cyIgY2xhc3M9Im9yZy5lY2xpcHNlLmpldHR5LnNlcnZlci5oYW5kbGVyLkNvbnRleHRIYW5kbGVyQ29sbGVjdGlvbiI+CiAgICA8L2JlYW4+CgogIDwhLS0gIDxiZWFuIGlkPSJqZXR0eVBvcnQiIGNsYXNzPSJvcmcuYXBhY2hlLmFjdGl2ZW1xLndlYi5XZWJDb25zb2xlUG9ydCIgaW5pdC1tZXRob2Q9InN0YXJ0Ij4KICAgICAgICAgICAgCiAgICAgICAgPHByb3BlcnR5IG5hbWU9Imhvc3QiIHZhbHVlPSIwLjAuMC4wIi8+CiAgICAgICAgPHByb3BlcnR5IG5hbWU9InBvcnQiIHZhbHVlPSI4MTYxIi8+CiAgICA8L2JlYW4gLS0+CgogICAgPGJlYW4gaWQ9IlNlcnZlciIgY2xhc3M9Im9yZy5lY2xpcHNlLmpldHR5LnNlcnZlci5TZXJ2ZXIiCiAgICAgICAgZGVzdHJveS1tZXRob2Q9InN0b3AiPgoKICAgICAgICA8cHJvcGVydHkgbmFtZT0iaGFuZGxlciI+CiAgICAgICAgICAgIDxiZWFuIGlkPSJoYW5kbGVycyIgY2xhc3M9Im9yZy5lY2xpcHNlLmpldHR5LnNlcnZlci5oYW5kbGVyLkhhbmRsZXJDb2xsZWN0aW9uIj4KICAgICAgICAgICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJoYW5kbGVycyI+CiAgICAgICAgICAgICAgICAgICAgPGxpc3Q+CiAgICAgICAgICAgICAgICAgICAgICAgIDxyZWYgYmVhbj0iY29udGV4dHMiIC8+CiAgICAgICAgICAgICAgICAgICAgICAgIDxyZWYgYmVhbj0ic2VjdXJpdHlIYW5kbGVyIiAvPgogICAgICAgICAgICAgICAgICAgIDwvbGlzdD4KICAgICAgICAgICAgICAgIDwvcHJvcGVydHk+CiAgICAgICAgICAgIDwvYmVhbj4KICAgICAgICA8L3Byb3BlcnR5PgoKICAgIDwvYmVhbj4KCiAgICAKCiAgICA8YmVhbiBpZD0iaW52b2tlQ29ubmVjdG9ycyIgY2xhc3M9Im9yZy5zcHJpbmdmcmFtZXdvcmsuYmVhbnMuZmFjdG9yeS5jb25maWcuTWV0aG9kSW52b2tpbmdGYWN0b3J5QmVhbiI+CiAgICAJPHByb3BlcnR5IG5hbWU9InRhcmdldE9iamVjdCIgcmVmPSJTZXJ2ZXIiIC8+CiAgICAJPHByb3BlcnR5IG5hbWU9InRhcmdldE1ldGhvZCIgdmFsdWU9InNldENvbm5lY3RvcnMiIC8+CiAgICAJPHByb3BlcnR5IG5hbWU9ImFyZ3VtZW50cyI+CiAgICAJPGxpc3Q+CiAgICAgICAgICAgCTxiZWFuIGlkPSJDb25uZWN0b3IiIGNsYXNzPSJvcmcuZWNsaXBzZS5qZXR0eS5zZXJ2ZXIuU2VydmVyQ29ubmVjdG9yIj4KICAgICAgICAgICAJCTxjb25zdHJ1Y3Rvci1hcmcgcmVmPSJTZXJ2ZXIiIC8+CiAgICAgICAgICAgICAgICAgICAgPCEtLSBzZWUgdGhlIGpldHR5UG9ydCBiZWFuIC0tPgogICAgICAgICAgICAgICAgICAgPHByb3BlcnR5IG5hbWU9Imhvc3QiIHZhbHVlPSIxMjcuMC4wLjEiIC8+CiAgICAgICAgICAgICAgICAgICA8cHJvcGVydHkgbmFtZT0icG9ydCIgdmFsdWU9IjgxNjEiIC8+CiAgICAgICAgICAgICAgIDwvYmVhbj4KICAgICAgICAgICAgICAgIDwhLS0KICAgICAgICAgICAgICAgICAgICBFbmFibGUgdGhpcyBjb25uZWN0b3IgaWYgeW91IHdpc2ggdG8gdXNlIGh0dHBzIHdpdGggd2ViIGNvbnNvbGUKICAgICAgICAgICAgICAgIC0tPgogICAgICAgICAgICAgICAgPGJlYW4gaWQ9IlNlY3VyZUNvbm5lY3RvciIgY2xhc3M9Im9yZy5lY2xpcHNlLmpldHR5LnNlcnZlci5TZXJ2ZXJDb25uZWN0b3IiPgoJCQkJCTxjb25zdHJ1Y3Rvci1hcmcgcmVmPSJTZXJ2ZXIiIC8+CgkJCQkJPGNvbnN0cnVjdG9yLWFyZz4KCQkJCQkJPGJlYW4gaWQ9ImhhbmRsZXJzIiBjbGFzcz0ib3JnLmVjbGlwc2UuamV0dHkudXRpbC5zc2wuU3NsQ29udGV4dEZhY3RvcnkiPgoJCQkJCQkKCQkJCQkJCTxwcm9wZXJ0eSBuYW1lPSJrZXlTdG9yZVBhdGgiIHZhbHVlPSIvZXRjL2FjdGl2ZW1xL2FtcS5wMTIiIC8+CgkJCQkJCQk8cHJvcGVydHkgbmFtZT0ia2V5U3RvcmVQYXNzd29yZCIgdmFsdWU9IiR7VExTX0tTX1BXRH0iIC8+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8cHJvcGVydHkgbmFtZT0ia2V5U3RvcmVUeXBlIiB2YWx1ZT0icGtjczEyIiAvPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJ0cnVzdFN0b3JlUGF0aCIgdmFsdWU9Ii9ldGMvYWN0aXZlbXEvYW1xLnAxMiIgLz4KCQkJCQkJCTxwcm9wZXJ0eSBuYW1lPSJ0cnVzdFN0b3JlUGFzc3dvcmQiIHZhbHVlPSIke1RMU19LU19QV0R9IiAvPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPHByb3BlcnR5IG5hbWU9InRydXN0U3RvcmVUeXBlIiB2YWx1ZT0icGtjczEyIiAvPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPHByb3BlcnR5IG5hbWU9Im5lZWRDbGllbnRBdXRoIiB2YWx1ZT0idHJ1ZSIgLz4KCgkJCQkJCTwvYmVhbj4KCQkJCQk8L2NvbnN0cnVjdG9yLWFyZz4KCQkJCQk8cHJvcGVydHkgbmFtZT0icG9ydCIgdmFsdWU9IjgxNjIiIC8+CgkJCQk8L2JlYW4+CiAgICAgICAgICAgIDwvbGlzdD4KICAgIAk8L3Byb3BlcnR5PgogICAgPC9iZWFuPgoKCTxiZWFuIGlkPSJjb25maWd1cmVKZXR0eSIgY2xhc3M9Im9yZy5zcHJpbmdmcmFtZXdvcmsuYmVhbnMuZmFjdG9yeS5jb25maWcuTWV0aG9kSW52b2tpbmdGYWN0b3J5QmVhbiI+CgkJPHByb3BlcnR5IG5hbWU9InN0YXRpY01ldGhvZCIgdmFsdWU9Im9yZy5hcGFjaGUuYWN0aXZlbXEud2ViLmNvbmZpZy5Kc3BDb25maWd1cmVyLmNvbmZpZ3VyZUpldHR5IiAvPgoJCTxwcm9wZXJ0eSBuYW1lPSJhcmd1bWVudHMiPgoJCQk8bGlzdD4KCQkJCTxyZWYgYmVhbj0iU2VydmVyIiAvPgoJCQkJPHJlZiBiZWFuPSJzZWNIYW5kbGVyQ29sbGVjdGlvbiIgLz4KCQkJPC9saXN0PgoJCTwvcHJvcGVydHk+Cgk8L2JlYW4+CiAgICAKICAgIDxiZWFuIGlkPSJpbnZva2VTdGFydCIgY2xhc3M9Im9yZy5zcHJpbmdmcmFtZXdvcmsuYmVhbnMuZmFjdG9yeS5jb25maWcuTWV0aG9kSW52b2tpbmdGYWN0b3J5QmVhbiIgCiAgICAJZGVwZW5kcy1vbj0iY29uZmlndXJlSmV0dHksIGludm9rZUNvbm5lY3RvcnMiPgogICAgCTxwcm9wZXJ0eSBuYW1lPSJ0YXJnZXRPYmplY3QiIHJlZj0iU2VydmVyIiAvPgogICAgCTxwcm9wZXJ0eSBuYW1lPSJ0YXJnZXRNZXRob2QiIHZhbHVlPSJzdGFydCIgLz4gIAkKICAgIDwvYmVhbj4KCiAgICAgICAgPCEtLSBzZXR1cCBteXNxbCBhY2Nlc3MgLS0+CiAgICA8YmVhbiBpZD0ibXlzcWwtZHMiIGNsYXNzPSJvcmcuYXBhY2hlLmNvbW1vbnMuZGJjcC5CYXNpY0RhdGFTb3VyY2UiIGRlc3Ryb3ktbWV0aG9kPSJjbG9zZSI+CiAgICAgICAgPHByb3BlcnR5IG5hbWU9ImRyaXZlckNsYXNzTmFtZSIgdmFsdWU9IiN7c3lzdGVtRW52aXJvbm1lbnRbJ0pEQkNfRFJJVkVSJ119Ii8+CiAgICAgICAgPHByb3BlcnR5IG5hbWU9InVybCIgdmFsdWU9IiR7SkRCQ19VUkx9Ii8+CiAgICAgICAgPHByb3BlcnR5IG5hbWU9InVzZXJuYW1lIiB2YWx1ZT0iI3tzeXN0ZW1FbnZpcm9ubWVudFsnSkRCQ19VU0VSJ119Ii8+CiAgICAgICAgPHByb3BlcnR5IG5hbWU9InBhc3N3b3JkIiB2YWx1ZT0iI3tzeXN0ZW1FbnZpcm9ubWVudFsnSkRCQ19QQVNTV09SRCddfSIvPgogICAgICAgIDxwcm9wZXJ0eSBuYW1lPSJwb29sUHJlcGFyZWRTdGF0ZW1lbnRzIiB2YWx1ZT0idHJ1ZSIvPgogICAgPC9iZWFuPgoKPC9iZWFucz4KPCEtLSBFTkQgU05JUFBFVDogZXhhbXBsZSAtLT4=",
      "amq.p12":CertUtils.encodeKeyStore(amqKS,ksPassword)
    }
}

k8s.postWS('/api/v1/namespaces/openunison/secrets',JSON.stringify(amqFileSecrets));

print("Create activemq env var secret");

amqEnvSecrets = {
  "apiVersion":"v1",
    "kind":"Secret",
    "type":"Opaque",
    "metadata": {
        "name":"amq-env-secrets",
        "namespace":"openunison"
    },
    "data":{
      "JDBC_DRIVER":java.util.Base64.getEncoder().encodeToString(inProp['OU_JDBC_DRIVER'].getBytes("UTF-8")),
      "JDBC_URL":java.util.Base64.getEncoder().encodeToString(inProp['OU_JDBC_URL'].getBytes("UTF-8")),
      "JDBC_USER":java.util.Base64.getEncoder().encodeToString(inProp['OU_JDBC_USER'].getBytes("UTF-8")),
      "JDBC_PASSWORD":java.util.Base64.getEncoder().encodeToString(inProp['OU_JDBC_PASSWORD'].getBytes("UTF-8")),
      "TLS_KS_PWD":java.util.Base64.getEncoder().encodeToString(ksPassword.getBytes("UTF-8"))
    }
}

k8s.postWS('/api/v1/namespaces/openunison/secrets',JSON.stringify(amqEnvSecrets));

print("Create OpenUnison Secret");


ouSecrets = {
    "apiVersion":"v1",
    "kind":"Secret",
    "type":"Opaque",
    "metadata": {
        "name":"openunison-secrets",
        "namespace":"openunison"
    },
    "data":{
      "openunison.yaml":"LS0tCm9wZW5fcG9ydDogODA4MApvcGVuX2V4dGVybmFsX3BvcnQ6IDgwCnNlY3VyZV9wb3J0OiA4NDQzCnNlY3VyZV9leHRlcm5hbF9wb3J0OiA0NDMKc2VjdXJlX2tleV9hbGlhczogInVuaXNvbi10bHMiCmZvcmNlX3RvX3NlY3VyZTogdHJ1ZQphY3RpdmVtcV9kaXI6ICIvdG1wL2FtcSIKcXVhcnR6X2RpcjogIi90bXAvcXVhcnR6IgpjbGllbnRfYXV0aDogbm9uZQpkaXNhYmxlX2h0dHAyOiB0cnVlCmFsbG93ZWRfY2xpZW50X25hbWVzOiBbXQpjaXBoZXJzOgotIFRMU19FQ0RIRV9SU0FfV0lUSF9BRVNfMTI4X0dDTV9TSEEyNTYKLSBUTFNfRUNESEVfUlNBX1dJVEhfQUVTXzEyOF9DQkNfU0hBMjU2Ci0gVExTX0VDREhFX1JTQV9XSVRIX0FFU18xMjhfQ0JDX1NIQQotIFRMU19FQ0RIRV9SU0FfV0lUSF9BRVNfMjU2X0dDTV9TSEEzODQKLSBUTFNfRUNESEVfUlNBX1dJVEhfQUVTXzI1Nl9DQkNfU0hBMzg0Ci0gVExTX0VDREhFX1JTQV9XSVRIX0FFU18yNTZfQ0JDX1NIQQphbGxvd2VkX3Rsc19wcm90b2NvbHM6Ci0gVExTdjEuMgpwYXRoX3RvX2RlcGxveW1lbnQ6ICIvdXNyL2xvY2FsL29wZW51bmlzb24vd29yayIKcGF0aF90b19lbnZfZmlsZTogIi9ldGMvb3BlbnVuaXNvbi9vdS5lbnYiCgo=",
      "ou.env":k8s.encodeMap(inProp),
      "unisonKeyStore.p12":CertUtils.encodeKeyStore(ouKs,ksPassword)
    }
}

k8s.postWS('/api/v1/namespaces/openunison/secrets',JSON.stringify(ouSecrets));

print("Creating post deployment configmap");

oidcFlags = "--oidc-issuer-url=https://" + inProp["OU_HOST"] + "/auth/idp/k8sIdp\n" +
            "--oidc-client-id=kubernetes\n" +
            "--oidc-username-claim=sub\n" + 
            "--oidc-groups-claim=groups\n" +
            "--oidc-ca-file=/etc/kubernetes/pki/ou-ca.pem";

canonicalOidcFlags = "oidc-issuer-url=https://" + inProp["OU_HOST"] + "/auth/idp/k8sIdp " +
                      "oidc-client-id=kubernetes " +
                      "oidc-username-claim=sub " + 
                      "oidc-groups-claim=groups " +
                      "oidc-ca-file=/root/cdk/ou-ca.pem";

print("Runing kubectl create");
k8s.kubectlCreate(k8s.processTemplate(deploymentTemplate,inProp));
print("kubectl complete");





xmlMetaData =  '<EntityDescriptor ID="_10685acd-7df4-427e-b61e-68e4f6407c24" entityID="https://' + inProp['OU_HOST'] + '/auth/SAML2Auth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">\n';
xmlMetaData += '  <SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n';
xmlMetaData += '      <KeyDescriptor use="signing">\n';
xmlMetaData += '        <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">\n';
xmlMetaData += '              <X509Data>\n';
xmlMetaData += '                  <X509Certificate>\n' + new org.apache.commons.codec.binary.Base64(64).encodeToString(rp_sig_cert_bytes.getEncoded()) + '</X509Certificate>\n';
xmlMetaData += '              </X509Data>\n';
xmlMetaData += '          </KeyInfo>\n';
xmlMetaData += '      </KeyDescriptor>\n';
xmlMetaData += '      <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://' + inProp['OU_HOST'] + '/auth/SAML2Auth"/>\n';
xmlMetaData += '      <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>\n';
xmlMetaData += '      <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://' + inProp['OU_HOST'] + '/auth/SAML2Auth" index="0" isDefault="true"/>\n';
xmlMetaData += '      <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://' + inProp['OU_HOST'] + '/auth/SAML2Auth" index="1"/>\n';
xmlMetaData += '  </SPSSODescriptor>\n';
xmlMetaData += '</EntityDescriptor>';






cfgMap = {
    "apiVersion":"v1",
    "kind":"ConfigMap",
    "metadata":{
        "name":"api-server-config",
        "namespace":"openunison"
    },
    "data":{
        "oidc-api-server-flags":oidcFlags,
        "ou-ca.pem-base64-encoded":CertUtils.exportCert(ingressX509data.getCertificate()),
        "canonical-cdk-flags":canonicalOidcFlags,
        "oidc-issuer-url":"https://" + inProp["OU_HOST"] + "/auth/idp/k8sIdp",
        "oidc-client-id":"kubernetes",
        "oidc-username-claim":"sub",
        "oidc-groups-claim":"groups",
        "oidc-ca-file":"/etc/kubernetes/pki/ou-ca.pem",
        "saml2-rp-metadata":xmlMetaData
        
        //"deployment":java.util.Base64.getEncoder().encodeToString(k8s.processTemplate(deploymentTemplate,inProp).getBytes("UTF-8"))
    }
};

k8s.postWS('/api/v1/namespaces/openunison/configmaps',JSON.stringify(cfgMap));

print("Deleting cluster role binding");
k8s.deleteWS('/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/artifact-deployment');

print("Artifacts Created, to configure the API server run 'kubectl describe configmap api-server-config -n openunison'");