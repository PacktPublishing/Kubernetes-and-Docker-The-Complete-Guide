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

print("Loading CertUtils");
var CertUtils = Java.type("com.tremolosecurity.kubernetes.artifacts.util.CertUtils");
var NetUtil = Java.type("com.tremolosecurity.kubernetes.artifacts.util.NetUtil");

print("Creating openunison keystore");

k8sDashboardNamespace = "kube-system";

if (nonSecretInProp['K8S_DASHBOARD_NAMESPACE'] != null) {
    print("Getting k8s dashboard namespace from the configuration");
    k8sDashboardNamespace = nonSecretInProp['K8S_DASHBOARD_NAMESPACE'];
}


ksPassword = inProp['unisonKeystorePassword'];
ouKs = Java.type("java.security.KeyStore").getInstance("PKCS12");
ouKs.load(null,ksPassword.toCharArray());

use_k8s_cm = nonSecretInProp['USE_K8S_CM'] == "true";


inProp['K8S_DB_SECRET'] = java.util.UUID.randomUUID().toString();

var docker_image = 'docker.io/tremolosecurity/openunison-k8s-saml2:latest';

if (nonSecretInProp['image'] != null) {
  docker_image = nonSecretInProp['image'];
  delete nonSecretInProp['image'];
}

var amq_image = 'docker.io/tremolosecurity/activemq-docker:latest';

if (nonSecretInProp['amqimage'] != null) {
  amq_image = nonSecretInProp['amqimage'];
  delete nonSecretInProp['amqimage'];
}


print("Runing kubectl create");
k8s.kubectlCreate(deploymentTemplate);
print("kubectl complete");


print("pulling quartz sql");
quartzSQL = com.tremolosecurity.kubernetes.artifacts.util.NetUtil.downloadFile("file:///etc/input-maps/quartz.sql");



ou_cr = {
  "apiVersion": "openunison.tremolo.io/v1",
  "kind": "OpenUnison",
  "metadata": {
      "name": "orchestra"
  },
  "spec": {
      "dest_secret": "orchestra",
      "enable_activemq": true,
      "activemq_image": amq_image,
      "run_sql":quartzSQL,
      "hosts": [
          {
              "ingress_name": "openunison",
              "names": [
                  {
                      "env_var": "OU_HOST",
                      "name": nonSecretInProp['OU_HOST']
                  },
                  {
                    "env_var":"K8S_DASHBOARD_HOST",
                    "name": nonSecretInProp['K8S_DASHBOARD_HOST']
                  }
              ],
              "secret_name":"ou-tls-certificate"
          }
      ],
      "key_store": {
        "update_controller":{
          "image" : "docker.io/tremolosecurity/kubernetes-artifact-deployment:1.1.0",
          "schedule" : "0 2 * * *",
          "days_to_expire" : 10
        },
        "key_pairs" : {
          "create_keypair_template": [
            {
                "name": "ou",
                "value": nonSecretInProp['OU_CERT_OU']
            },
            {
                "name": "o",
                "value": nonSecretInProp['OU_CERT_O']
            },
            {
                "name": "l",
                "value": nonSecretInProp['OU_CERT_L']
            },
            {
                "name": "st",
                "value": nonSecretInProp['OU_CERT_ST']
            },
            {
                "name": "c",
                "value": nonSecretInProp['OU_CERT_C']
            }
          ],
          "keys" : []
        },
        "static_keys":[],
        "trusted_certificates":[]
      },
      "non_secret_data":[],
      "openunison_network_configuration": {
        "activemq_dir": "/tmp/amq",
        "allowed_client_names": [],
        "ciphers": [
            "TLS_RSA_WITH_RC4_128_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256"
        ],
        "client_auth": "none",
        "force_to_secure": true,
        "open_external_port": 80,
        "open_port": 8080,
        "path_to_deployment": "/usr/local/openunison/work",
        "path_to_env_file": "/etc/openunison/ou.env",
        "quartz_dir": "/tmp/quartz",
        "secure_external_port": 443,
        "secure_key_alias": "unison-tls",
        "secure_port": 8443
    },
    "replicas": 1,
    "secret_data": [],
    "source_secret": "orchestra-secrets-source",
    "image": docker_image
  }
};

ou_cr.spec['saml_remote_idp'] = [
  {
    "mapping": {
      "encryption_cert_alias": "idp-saml2-enc",
      "entity_id": "IDP_ENTITY_ID",
      "logout_url": "IDP_LOGOUT",
      "post_url": "IDP_POST",
      "redirect_url": "IDP_REDIR",
      "signing_cert_alias": "idp-saml2-sig"
    },
    "source": {
      
    }
  }
];

if (nonSecretInProp['SAML2_IDP_METADATA_URL'] != null) {
  ou_cr.spec.saml_remote_idp[0].source.url = nonSecretInProp['SAML2_IDP_METADATA_URL'];
  delete nonSecretInProp['SAML2_IDP_METADATA_URL'];
} else {
  xmlMetadata = NetUtil.downloadFile('file://' + configMapsDir + '/saml2-metadata.xml');
  ou_cr.spec.saml_remote_idp[0].source.xml = xmlMetadata;
}



print("Generating openunison tls certificate");

outls = {
  "create_data" : {
    "ca_cert":true,
    "key_size":2048,
    "server_name":"openunison.openunison.svc.cluster.local",
    "sign_by_k8s_ca":use_k8s_cm,
    "subject_alternative_names":[]
  },
  "import_into_ks" : "keypair",
  "name": "unison-tls"

};

ou_cr.spec.key_store.key_pairs.keys.push(outls);


outls = {
  "create_data" : {
    "ca_cert":true,
    "key_size":2048,
    "server_name":nonSecretInProp['OU_HOST'],
    "sign_by_k8s_ca":false,
    "subject_alternative_names":[
      nonSecretInProp['K8S_DASHBOARD_HOST']
    ]
  },
  "import_into_ks" : "certificate",
  "name": "unison-ca",
  "tls_secret_name":"ou-tls-certificate"

};

ou_cr.spec.key_store.key_pairs.keys.push(outls);

print("Generating the dashboard certificate");

outls = {
  "create_data" : {
    "ca_cert":(! use_k8s_cm),
    "key_size":2048,
    "server_name":"kubernetes-dashboard." + k8sDashboardNamespace + ".svc.cluster.local",
    "sign_by_k8s_ca":use_k8s_cm,
    "subject_alternative_names":[],
    "target_namespace": k8sDashboardNamespace,
    "secret_info":{
      "type_of_secret":"Opaque",
      "cert_name":"dashboard.crt",
      "key_name":"dashboard.key"
      
    },
    "delete_pods_labels" : ["k8s-app=kubernetes-dashboard"]
  },
  "import_into_ks" : (use_k8s_cm ? "none" : "certificate"),
  "name": "kubernetes-dashboard",
  "tls_secret_name":"kubernetes-dashboard-certs",
  "replace_if_exists": true
  

};

ou_cr.spec.key_store.key_pairs.keys.push(outls);

print("Generating the dashboard certificate");

outls = {
  "create_data" : {
    "ca_cert":(! use_k8s_cm),
    "key_size":2048,
    "server_name":"amq.openunison.svc.cluster.local",
    "sign_by_k8s_ca":use_k8s_cm,
    "subject_alternative_names":[]
  },
  "import_into_ks" : (use_k8s_cm ? "none" : "certificate"),
  "name": "amq-server",
  "tls_secret_name":"orchestra-amq-server",
  "replace_if_exists": true
  

};

ou_cr.spec.key_store.key_pairs.keys.push(outls);

print("Generating amq client tls certificate");

outls = {
  "create_data" : {
    "ca_cert":true,
    "key_size":2048,
    "server_name":"amq--client",
    "sign_by_k8s_ca":false,
    "subject_alternative_names":[]
  },
  "import_into_ks" : "keypair",
  "name": "amq-client",
  "tls_secret_name":"orchestra-amq-client"

};

ou_cr.spec.key_store.key_pairs.keys.push(outls);


print("Saving certificate to keystore");

ou_cr.spec.key_store.static_keys.push({
  "name":"session-unison",
  "version":1
});

ou_cr.spec.key_store.static_keys.push({
  "name":"lastmile-oidc",
  "version":1
});



print("Generating OIDC Certificate");

outls = {
  "create_data" : {
    "ca_cert":true,
    "key_size":2048,
    "server_name":"unison-saml2-rp-sig",
    "sign_by_k8s_ca":false,
    "subject_alternative_names":[]
  },
  "import_into_ks" : "keypair",
  "name": "unison-saml2-rp-sig"

};

ou_cr.spec.key_store.key_pairs.keys.push(outls);



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

print("Create operator rbac policies");

k8s_obj = {
  "apiVersion": "rbac.authorization.k8s.io/v1",
  "kind": "Role",
  "metadata": {
    "name": "openunison-operator-role"
  },
  "rules": [
    {
      "apiGroups": [
        "openunison.tremolo.io",
        "",
        "apps",
        "rbac.authorization.k8s.io",
        "extensions",
        "apps.openshift.io",
        "build.openshift.io",
        "image.openshift.io",
        "route.openshift.io",
        "user.openshift.io",
        "batch"
      ],
      "resources": [
        "routes/custom-host",
        "imagestreamimports",
        "users",
        "groups",
        "routes",
        "images",
        "imagestreams",
        "builds",
        "buildconfigs",
        "deploymentconfigs",
        "openunisons",
        "openunisons/status",
        "pods",
        "deployments",
        "secrets",
        "configmaps",
        "services",
        "serviceaccounts",
        "roles",
        "rolebindings",
        "ingresses",
        "cronjobs"
      ],
      "verbs": [
        "*"
      ]
    }
  ]
};



k8s.postWS('/apis/rbac.authorization.k8s.io/v1/namespaces/openunison/roles',JSON.stringify(k8s_obj));

print("Creating rbac binding");

k8s_obj = {
  "apiVersion": "rbac.authorization.k8s.io/v1",
  "kind": "RoleBinding",
  "metadata": {
    "name": "openunison-operator-rolebinding"
  },
  "roleRef": {
    "apiGroup": "rbac.authorization.k8s.io",
    "kind": "Role",
    "name": "openunison-operator-role"
  },
  "subjects": [
    {
      "kind": "ServiceAccount",
      "name": "openunison-operator",
      "namespace":"openunison"
    }
  ]
};

k8s.postWS('/apis/rbac.authorization.k8s.io/v1/namespaces/openunison/rolebindings',JSON.stringify(k8s_obj));

print("Creating the operator service account");

k8s_obj = {
  "apiVersion": "v1",
  "kind": "ServiceAccount",
  "metadata": {
    "name": "openunison-operator"
  }
};

k8s.postWS('/api/v1/namespaces/openunison/serviceaccounts',JSON.stringify(k8s_obj));



obj = {
    "kind": "Role",
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "metadata": {
        "namespace": k8sDashboardNamespace,
        "name": "orchestra-dashboard"
    },
    "rules": [
        {
            "apiGroups": [
                ""
            ],
            "resources": [
                "secrets",
                "pods"
            ],
            "verbs": [
                "*"
            ]
        }
    ]
};

k8s.postWS('/apis/rbac.authorization.k8s.io/v1/namespaces/' + k8sDashboardNamespace + '/roles',JSON.stringify(obj));

obj = {
    "kind": "RoleBinding",
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "metadata": {
        "name": "orchestra-dashboard",
        "namespace": k8sDashboardNamespace
    },
    "subjects": [
        {
            "kind": "ServiceAccount",
            "name": "openunison-operator",
            "namespace": "openunison"
        }
    ],
    "roleRef": {
        "kind": "Role",
        "name": "orchestra-dashboard",
        "apiGroup": "rbac.authorization.k8s.io"
    }
};

k8s.postWS('/apis/rbac.authorization.k8s.io/v1/namespaces/' + k8sDashboardNamespace + '/rolebindings',JSON.stringify(obj));


obj = {
  "kind": "ClusterRole",
  "apiVersion": "rbac.authorization.k8s.io/v1",
  "metadata": {
      "name": "orchestra-certs"
  },
  "rules": [
      {
          "apiGroups": [
              "certificates.k8s.io",
          ],
          "resources": [
              "certificatesigningrequests",
              "certificatesigningrequests/approval"

          ],
          "verbs": [
              "*"
          ]
      }
  ]
};

k8s.postWS('/apis/rbac.authorization.k8s.io/v1/clusterroles',JSON.stringify(obj));

obj = {
  "kind": "ClusterRoleBinding",
  "apiVersion": "rbac.authorization.k8s.io/v1",
  "metadata": {
      "name": "orchestra-certs"
  },
  "subjects": [
      {
          "kind": "ServiceAccount",
          "name": "openunison-operator",
          "namespace": "openunison"
      }
  ],
  "roleRef": {
      "kind": "ClusterRole",
      "name": "orchestra-certs",
      "apiGroup": "rbac.authorization.k8s.io"
  }
};

k8s.postWS('/apis/rbac.authorization.k8s.io/v1/clusterrolebindings',JSON.stringify(obj));



print("Creating the operator deployment");

k8s_obj = {
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {
    "labels": {
      "app": "openunison-operator"
    },
    "name": "openunison-operator"
  },
  "spec": {
    "progressDeadlineSeconds": 600,
    "replicas": 1,
    "revisionHistoryLimit": 10,
    "selector": {
      "matchLabels": {
        "app": "openunison-operator"
      }
    },
    "strategy": {
      "rollingUpdate": {
        "maxSurge": "25%",
        "maxUnavailable": "25%"
      },
      "type": "RollingUpdate"
    },
    "template": {
      "metadata": {
        "creationTimestamp": null,
        "labels": {
          "app": "openunison-operator"
        }
      },
      "spec": {
        "containers": [
          {
            "env": [
              {
                "name": "JAVA_OPTS",
                "value": "-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom"
              },
              {
                "name": "NAMESPACE",
                "valueFrom": {
                  "fieldRef": {
                    "fieldPath": "metadata.namespace"
                  }
                }
              },
              {
                "name":"EXTRA_JS",
                "value":"/usr/local/openunison/js-external"
              }
            ],
            "image": "docker.io/tremolosecurity/openunison-k8s-operator",
            "command": [
              "java",
              "-jar",
              "/usr/local/openunison/javascript-operator.jar",
              "-tokenPath",
              "/var/run/secrets/kubernetes.io/serviceaccount/token",
              "-rootCaPath",
              "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
              "-kubernetesURL",
              "https://kubernetes.default.svc.cluster.local",
              "-namespace",
              "NAMESPACE",
              "-apiGroup",
              "openunison.tremolo.io/v1",
              "-objectType",
              "openunisons",
              "-jsPath",
              "/usr/local/openunison/js",
              "-configMaps",
              "/etc/extraMaps"
            ],
            "imagePullPolicy": "Always",
            "name": "openunison-operator",
            "resources": {
            },
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "volumeMounts": [
              {
                "mountPath": "/etc/extraMaps",
                "name": "extra-maps",
                "readOnly": true
              }
            ]
          }
        ],
        "dnsPolicy": "ClusterFirst",
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "serviceAccount": "openunison-operator",
        "volumes": [
          {
            "name": "extra-maps",
            "emptyDir": {
            }
          }
        ]
      }
    }
  }
};

k8s.postWS('/apis/apps/v1/namespaces/openunison/deployments',JSON.stringify(k8s_obj));

//k8s.postWS('/apis/openunison.tremolo.io/v1/namespaces/openunison/openunisons',JSON.stringify(k8s_obj));


print("Create OpenUnison Source Secret");


ouSecrets = {
    "apiVersion":"v1",
    "kind":"Secret",
    "type":"Opaque",
    "metadata": {
        "name":"orchestra-secrets-source",
        "namespace":"openunison"
    },
    "data":{
      
    }
}

for each (var key in inProp.keySet()) {
  
    ouSecrets.data[key] =  java.util.Base64.getEncoder().encodeToString(inProp[key].getBytes("UTF-8"));
    ou_cr.spec.secret_data.push(key);
  
}

k8s.postWS('/api/v1/namespaces/openunison/secrets',JSON.stringify(ouSecrets));

print("Adding non-secret properties to CR");

for each (var key in nonSecretInProp.keySet()) {
  
    ou_cr.spec.non_secret_data.push( {
      "name": key,
      "value": nonSecretInProp[key]
    });
  
}

print("Adding trusted certs to the cr");

var trusted_certs = k8s.getExtraCerts();

for each (var key in trusted_certs.keySet()) {
  ou_cr.spec.key_store.trusted_certificates.push({
    "name" : key,
    "pem_data" : trusted_certs[key]
  });
}

print(JSON.stringify(ou_cr));


print("Creating post deployment configmap");

oidcFlags = "--oidc-issuer-url=https://" + nonSecretInProp["OU_HOST"] + "/auth/idp/k8sIdp\n" +
            "--oidc-client-id=kubernetes\n" +
            "--oidc-username-claim=sub\n" + 
            "--oidc-groups-claim=groups\n" +
            "--oidc-ca-file=/etc/kubernetes/pki/ou-ca.pem";

print("Runing kubectl create");
k8s.kubectlCreate(k8s.processTemplate(deploymentTemplate,inProp));
print("kubectl complete");

cfgMap = {
    "apiVersion":"v1",
    "kind":"ConfigMap",
    "metadata":{
        "name":"api-server-config",
        "namespace":"openunison"
    },
    "data":{
        "oidc-api-server-flags":oidcFlags
    }
};

k8s.postWS('/api/v1/namespaces/openunison/configmaps',JSON.stringify(cfgMap));


print("Waiting for the OpenUnison operator to be deployed");

k8s.callWS('/api/v1/namespaces/openunison/pods?labelSelector=app%3Dopenunison-operator&limit=500',"check_ws_response = (JSON.parse(ws_response_json).items[0].status.phase == 'Running') ",20);



print("Deploying the CR");

print(k8s.postWS('/apis/openunison.tremolo.io/v1/namespaces/openunison/openunisons',JSON.stringify(ou_cr))["data"]);


print("Deleting cluster role binding");
k8s.deleteWS('/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/artifact-deployment');

print("Artifacts Created, to configure the API server run 'kubectl describe configmap api-server-config -n openunison'");