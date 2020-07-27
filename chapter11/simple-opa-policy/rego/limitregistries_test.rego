package k8sallowedregistries

test_deployment_registry_allowed {
    not invalidRegistry with input as {"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","review":{"uid":"705ab4f5-6393-11e8-b7cc-42010a800002","kind":{"group":"autoscaling","version":"v1","kind":"Scale"},"resource":{"group":"apps","version":"v1","resource":"deployments"},"subResource":"scale","requestKind":{"group":"autoscaling","version":"v1","kind":"Scale"},"requestResource":{"group":"apps","version":"v1","resource":"deployments"},"requestSubResource":"scale","name":"my-deployment","namespace":"my-namespace","operation":"CREATE","userInfo":{"username":"admin","uid":"014fbff9a07c","groups":["system:authenticated","my-admin-group"],"extra":{"some-key":["some-value1","some-value2"]}},"object":{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"annotations":{"deployment.kubernetes.io/revision":"1"},"creationTimestamp":"2020-07-04T17:21:04Z","generation":1,"labels":{"app":"openunison-orchestra","operated-by":"openunison-operator"},"name":"openunison-orchestra","namespace":"openunison","resourceVersion":"5085","selfLink":"/apis/apps/v1/namespaces/openunison/deployments/openunison-orchestra","uid":"c25f2d22-4253-4509-9a21-f932c27fff87"},"spec":{"progressDeadlineSeconds":600,"replicas":1,"revisionHistoryLimit":10,"selector":{"matchLabels":{"application":"openunison-orchestra"}},"strategy":{"rollingUpdate":{"maxSurge":"25%","maxUnavailable":"25%"},"type":"RollingUpdate"},"template":{"metadata":{"creationTimestamp":null,"labels":{"application":"openunison-orchestra","operated-by":"openunison-operator"}},"spec":{"containers":[{"env":[{"name":"JAVA_OPTS","value":"-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom\n-DunisonEnvironmentFile=/etc/openunison/ou.env"},{"name":"fortriggerupdates","value":"changeme"}],"image":"quay.io/tremolosecurity/openunison-k8s-login-saml2:latest","imagePullPolicy":"Always","livenessProbe":{"exec":{"command":["/usr/local/openunison/bin/check_alive.py"]},"failureThreshold":10,"initialDelaySeconds":120,"periodSeconds":10,"successThreshold":1,"timeoutSeconds":10},"name":"openunison-orchestra","ports":[{"containerPort":8080,"name":"http","protocol":"TCP"},{"containerPort":8443,"name":"https","protocol":"TCP"}],"readinessProbe":{"exec":{"command":["/usr/local/openunison/bin/check_alive.py","https://127.0.0.1:8443/auth/idp/k8sIdp/.well-known/openid-configuration","issuer"]},"failureThreshold":3,"initialDelaySeconds":30,"periodSeconds":10,"successThreshold":1,"timeoutSeconds":10},"resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/etc/openunison","name":"secret-volume","readOnly":true}]}],"dnsPolicy":"ClusterFirst","restartPolicy":"Always","schedulerName":"default-scheduler","securityContext":{},"serviceAccount":"openunison-orchestra","serviceAccountName":"openunison-orchestra","terminationGracePeriodSeconds":30,"volumes":[{"name":"secret-volume","secret":{"defaultMode":420,"secretName":"orchestra"}}]}}}},"oldObject":null,"options":null,"dryRun":false}}
}

test_deployment_registry_not_allowed {
    invalidRegistry with input as {"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","review":{"uid":"705ab4f5-6393-11e8-b7cc-42010a800002","kind":{"group":"autoscaling","version":"v1","kind":"Scale"},"resource":{"group":"apps","version":"v1","resource":"deployments"},"subResource":"scale","requestKind":{"group":"autoscaling","version":"v1","kind":"Scale"},"requestResource":{"group":"apps","version":"v1","resource":"deployments"},"requestSubResource":"scale","name":"my-deployment","namespace":"my-namespace","operation":"CREATE","userInfo":{"username":"admin","uid":"014fbff9a07c","groups":["system:authenticated","my-admin-group"],"extra":{"some-key":["some-value1","some-value2"]}},"object":{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"annotations":{"deployment.kubernetes.io/revision":"1"},"creationTimestamp":"2020-07-04T17:21:04Z","generation":1,"labels":{"app":"openunison-orchestra","operated-by":"openunison-operator"},"name":"openunison-orchestra","namespace":"openunison","resourceVersion":"5085","selfLink":"/apis/apps/v1/namespaces/openunison/deployments/openunison-orchestra","uid":"c25f2d22-4253-4509-9a21-f932c27fff87"},"spec":{"progressDeadlineSeconds":600,"replicas":1,"revisionHistoryLimit":10,"selector":{"matchLabels":{"application":"openunison-orchestra"}},"strategy":{"rollingUpdate":{"maxSurge":"25%","maxUnavailable":"25%"},"type":"RollingUpdate"},"template":{"metadata":{"creationTimestamp":null,"labels":{"application":"openunison-orchestra","operated-by":"openunison-operator"}},"spec":{"containers":[{"env":[{"name":"JAVA_OPTS","value":"-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom\n-DunisonEnvironmentFile=/etc/openunison/ou.env"},{"name":"fortriggerupdates","value":"changeme"}],"image":"docker.io/tremolosecurity/openunison-k8s-login-saml2:latest","imagePullPolicy":"Always","livenessProbe":{"exec":{"command":["/usr/local/openunison/bin/check_alive.py"]},"failureThreshold":10,"initialDelaySeconds":120,"periodSeconds":10,"successThreshold":1,"timeoutSeconds":10},"name":"openunison-orchestra","ports":[{"containerPort":8080,"name":"http","protocol":"TCP"},{"containerPort":8443,"name":"https","protocol":"TCP"}],"readinessProbe":{"exec":{"command":["/usr/local/openunison/bin/check_alive.py","https://127.0.0.1:8443/auth/idp/k8sIdp/.well-known/openid-configuration","issuer"]},"failureThreshold":3,"initialDelaySeconds":30,"periodSeconds":10,"successThreshold":1,"timeoutSeconds":10},"resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/etc/openunison","name":"secret-volume","readOnly":true}]}],"dnsPolicy":"ClusterFirst","restartPolicy":"Always","schedulerName":"default-scheduler","securityContext":{},"serviceAccount":"openunison-orchestra","serviceAccountName":"openunison-orchestra","terminationGracePeriodSeconds":30,"volumes":[{"name":"secret-volume","secret":{"defaultMode":420,"secretName":"orchestra"}}]}}}},"oldObject":null,"options":null,"dryRun":false}}
}

test_pod_registry_allowed {
    not invalidRegistry with input as {"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","review":{"uid":"705ab4f5-6393-11e8-b7cc-42010a800002","kind":{"group":"autoscaling","version":"v1","kind":"Scale"},"resource":{"group":"apps","version":"v1","resource":"deployments"},"subResource":"scale","requestKind":{"group":"autoscaling","version":"v1","kind":"Scale"},"requestResource":{"group":"apps","version":"v1","resource":"deployments"},"requestSubResource":"scale","name":"my-deployment","namespace":"my-namespace","operation":"CREATE","userInfo":{"username":"admin","uid":"014fbff9a07c","groups":["system:authenticated","my-admin-group"],"extra":{"some-key":["some-value1","some-value2"]}},"object":{"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{"cni.projectcalico.org/podIP":"10.240.189.147/32","cni.projectcalico.org/podIPs":"10.240.189.147/32","kubernetes.io/psp":"pod-security-policy-default"},"creationTimestamp":"2020-07-05T02:00:04Z","generateName":"check-certs-orchestra-1593914400-","labels":{"controller-uid":"711dc21e-3bd2-4769-ba92-465fd057bded","job-name":"check-certs-orchestra-1593914400"},"name":"check-certs-orchestra-1593914400-pd5f5","namespace":"openunison","ownerReferences":[{"apiVersion":"batch/v1","blockOwnerDeletion":true,"controller":true,"kind":"Job","name":"check-certs-orchestra-1593914400","uid":"711dc21e-3bd2-4769-ba92-465fd057bded"}],"resourceVersion":"91886","selfLink":"/api/v1/namespaces/openunison/pods/check-certs-orchestra-1593914400-pd5f5","uid":"f72ff715-a9f5-462b-b1a7-892086dee3aa"},"spec":{"containers":[{"command":["java","-jar","/usr/local/artifactdeploy/artifact-deploy.jar","-extraCertsPath","/etc/extracerts","-installScriptURL","file:///etc/input-maps/cert-check.js","-kubernetesURL","https://kubernetes.default.svc.cluster.local","-rootCaPath","/var/run/secrets/kubernetes.io/serviceaccount/ca.crt","-secretsPath","/etc/input-maps/input.props","-tokenPath","/var/run/secrets/kubernetes.io/serviceaccount/token","-deploymentTemplate","file:///etc/input-maps/deployment.yaml"],"env":[{"name":"CERT_DAYS_EXPIRE","value":"10"}],"image":"quay.io/tremolosecurity/kubernetes-artifact-deployment:1.1.0","imagePullPolicy":"IfNotPresent","name":"check-certs-orchestra","resources":{},"securityContext":{"runAsUser":1},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/etc/extracerts","name":"extra-certs-dir","readOnly":true},{"mountPath":"/etc/input-maps","name":"input-maps","readOnly":true},{"mountPath":"/var/run/secrets/kubernetes.io/serviceaccount","name":"openunison-operator-token-6jtv2","readOnly":true}]}],"dnsPolicy":"ClusterFirst","enableServiceLinks":true,"nodeName":"cluster01-worker","priority":0,"restartPolicy":"Never","schedulerName":"default-scheduler","securityContext":{"fsGroup":1,"supplementalGroups":[1]},"serviceAccount":"openunison-operator","serviceAccountName":"openunison-operator","terminationGracePeriodSeconds":30,"tolerations":[{"effect":"NoExecute","key":"node.kubernetes.io/not-ready","operator":"Exists","tolerationSeconds":300},{"effect":"NoExecute","key":"node.kubernetes.io/unreachable","operator":"Exists","tolerationSeconds":300}],"volumes":[{"configMap":{"defaultMode":420,"name":"cert-controller-js-orchestra"},"name":"extra-certs-dir"},{"configMap":{"defaultMode":420,"name":"cert-controller-js-orchestra"},"name":"input-maps"},{"name":"openunison-operator-token-6jtv2","secret":{"defaultMode":420,"secretName":"openunison-operator-token-6jtv2"}}]}},"oldObject":null,"options":null,"dryRun":false}}
}

test_pod_registry_not_allowed {
    invalidRegistry with input as {"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","review":{"uid":"705ab4f5-6393-11e8-b7cc-42010a800002","kind":{"group":"autoscaling","version":"v1","kind":"Scale"},"resource":{"group":"apps","version":"v1","resource":"deployments"},"subResource":"scale","requestKind":{"group":"autoscaling","version":"v1","kind":"Scale"},"requestResource":{"group":"apps","version":"v1","resource":"deployments"},"requestSubResource":"scale","name":"my-deployment","namespace":"my-namespace","operation":"CREATE","userInfo":{"username":"admin","uid":"014fbff9a07c","groups":["system:authenticated","my-admin-group"],"extra":{"some-key":["some-value1","some-value2"]}},"object":{"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{"cni.projectcalico.org/podIP":"10.240.189.147/32","cni.projectcalico.org/podIPs":"10.240.189.147/32","kubernetes.io/psp":"pod-security-policy-default"},"creationTimestamp":"2020-07-05T02:00:04Z","generateName":"check-certs-orchestra-1593914400-","labels":{"controller-uid":"711dc21e-3bd2-4769-ba92-465fd057bded","job-name":"check-certs-orchestra-1593914400"},"name":"check-certs-orchestra-1593914400-pd5f5","namespace":"openunison","ownerReferences":[{"apiVersion":"batch/v1","blockOwnerDeletion":true,"controller":true,"kind":"Job","name":"check-certs-orchestra-1593914400","uid":"711dc21e-3bd2-4769-ba92-465fd057bded"}],"resourceVersion":"91886","selfLink":"/api/v1/namespaces/openunison/pods/check-certs-orchestra-1593914400-pd5f5","uid":"f72ff715-a9f5-462b-b1a7-892086dee3aa"},"spec":{"containers":[{"command":["java","-jar","/usr/local/artifactdeploy/artifact-deploy.jar","-extraCertsPath","/etc/extracerts","-installScriptURL","file:///etc/input-maps/cert-check.js","-kubernetesURL","https://kubernetes.default.svc.cluster.local","-rootCaPath","/var/run/secrets/kubernetes.io/serviceaccount/ca.crt","-secretsPath","/etc/input-maps/input.props","-tokenPath","/var/run/secrets/kubernetes.io/serviceaccount/token","-deploymentTemplate","file:///etc/input-maps/deployment.yaml"],"env":[{"name":"CERT_DAYS_EXPIRE","value":"10"}],"image":"docker.io/tremolosecurity/kubernetes-artifact-deployment:1.1.0","imagePullPolicy":"IfNotPresent","name":"check-certs-orchestra","resources":{},"securityContext":{"runAsUser":1},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/etc/extracerts","name":"extra-certs-dir","readOnly":true},{"mountPath":"/etc/input-maps","name":"input-maps","readOnly":true},{"mountPath":"/var/run/secrets/kubernetes.io/serviceaccount","name":"openunison-operator-token-6jtv2","readOnly":true}]}],"dnsPolicy":"ClusterFirst","enableServiceLinks":true,"nodeName":"cluster01-worker","priority":0,"restartPolicy":"Never","schedulerName":"default-scheduler","securityContext":{"fsGroup":1,"supplementalGroups":[1]},"serviceAccount":"openunison-operator","serviceAccountName":"openunison-operator","terminationGracePeriodSeconds":30,"tolerations":[{"effect":"NoExecute","key":"node.kubernetes.io/not-ready","operator":"Exists","tolerationSeconds":300},{"effect":"NoExecute","key":"node.kubernetes.io/unreachable","operator":"Exists","tolerationSeconds":300}],"volumes":[{"configMap":{"defaultMode":420,"name":"cert-controller-js-orchestra"},"name":"extra-certs-dir"},{"configMap":{"defaultMode":420,"name":"cert-controller-js-orchestra"},"name":"input-maps"},{"name":"openunison-operator-token-6jtv2","secret":{"defaultMode":420,"secretName":"openunison-operator-token-6jtv2"}}]}},"oldObject":null,"options":null,"dryRun":false}}
}


test_cronjob_registry_allowed {
    not invalidRegistry with input as {"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","review":{"uid":"705ab4f5-6393-11e8-b7cc-42010a800002","kind":{"group":"autoscaling","version":"v1","kind":"Scale"},"resource":{"group":"apps","version":"v1","resource":"deployments"},"subResource":"scale","requestKind":{"group":"autoscaling","version":"v1","kind":"Scale"},"requestResource":{"group":"apps","version":"v1","resource":"deployments"},"requestSubResource":"scale","name":"my-deployment","namespace":"my-namespace","operation":"CREATE","userInfo":{"username":"admin","uid":"014fbff9a07c","groups":["system:authenticated","my-admin-group"],"extra":{"some-key":["some-value1","some-value2"]}},"object":{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"creationTimestamp":"2020-07-04T17:21:04Z","labels":{"app":"openunison-orchestra","operated-by":"openunison-operator"},"name":"check-certs-orchestra","namespace":"openunison","resourceVersion":"91900","selfLink":"/apis/batch/v1beta1/namespaces/openunison/cronjobs/check-certs-orchestra","uid":"a1bbec0b-d7ec-4272-bddf-0b9497c4559f"},"spec":{"concurrencyPolicy":"Allow","failedJobsHistoryLimit":1,"jobTemplate":{"metadata":{"creationTimestamp":null},"spec":{"backoffLimit":1,"template":{"metadata":{"creationTimestamp":null},"spec":{"containers":[{"command":["java","-jar","/usr/local/artifactdeploy/artifact-deploy.jar","-extraCertsPath","/etc/extracerts","-installScriptURL","file:///etc/input-maps/cert-check.js","-kubernetesURL","https://kubernetes.default.svc.cluster.local","-rootCaPath","/var/run/secrets/kubernetes.io/serviceaccount/ca.crt","-secretsPath","/etc/input-maps/input.props","-tokenPath","/var/run/secrets/kubernetes.io/serviceaccount/token","-deploymentTemplate","file:///etc/input-maps/deployment.yaml"],"env":[{"name":"CERT_DAYS_EXPIRE","value":"10"}],"image":"quay.io/tremolosecurity/kubernetes-artifact-deployment:1.1.0","imagePullPolicy":"IfNotPresent","name":"check-certs-orchestra","resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/etc/extracerts","name":"extra-certs-dir","readOnly":true},{"mountPath":"/etc/input-maps","name":"input-maps","readOnly":true}]}],"dnsPolicy":"ClusterFirst","restartPolicy":"Never","schedulerName":"default-scheduler","securityContext":{},"serviceAccount":"openunison-operator","serviceAccountName":"openunison-operator","terminationGracePeriodSeconds":30,"volumes":[{"configMap":{"defaultMode":420,"name":"cert-controller-js-orchestra"},"name":"extra-certs-dir"},{"configMap":{"defaultMode":420,"name":"cert-controller-js-orchestra"},"name":"input-maps"}]}}}},"schedule":"0 2 * * *","successfulJobsHistoryLimit":3,"suspend":false},"status":{"lastScheduleTime":"2020-07-05T02:00:00Z"}},"oldObject":null,"options":null,"dryRun":false}}
}

test_cronjob_registry_not_allowed {
    invalidRegistry with input as {"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","review":{"uid":"705ab4f5-6393-11e8-b7cc-42010a800002","kind":{"group":"autoscaling","version":"v1","kind":"Scale"},"resource":{"group":"apps","version":"v1","resource":"deployments"},"subResource":"scale","requestKind":{"group":"autoscaling","version":"v1","kind":"Scale"},"requestResource":{"group":"apps","version":"v1","resource":"deployments"},"requestSubResource":"scale","name":"my-deployment","namespace":"my-namespace","operation":"CREATE","userInfo":{"username":"admin","uid":"014fbff9a07c","groups":["system:authenticated","my-admin-group"],"extra":{"some-key":["some-value1","some-value2"]}},"object":{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"creationTimestamp":"2020-07-04T17:21:04Z","labels":{"app":"openunison-orchestra","operated-by":"openunison-operator"},"name":"check-certs-orchestra","namespace":"openunison","resourceVersion":"91900","selfLink":"/apis/batch/v1beta1/namespaces/openunison/cronjobs/check-certs-orchestra","uid":"a1bbec0b-d7ec-4272-bddf-0b9497c4559f"},"spec":{"concurrencyPolicy":"Allow","failedJobsHistoryLimit":1,"jobTemplate":{"metadata":{"creationTimestamp":null},"spec":{"backoffLimit":1,"template":{"metadata":{"creationTimestamp":null},"spec":{"containers":[{"command":["java","-jar","/usr/local/artifactdeploy/artifact-deploy.jar","-extraCertsPath","/etc/extracerts","-installScriptURL","file:///etc/input-maps/cert-check.js","-kubernetesURL","https://kubernetes.default.svc.cluster.local","-rootCaPath","/var/run/secrets/kubernetes.io/serviceaccount/ca.crt","-secretsPath","/etc/input-maps/input.props","-tokenPath","/var/run/secrets/kubernetes.io/serviceaccount/token","-deploymentTemplate","file:///etc/input-maps/deployment.yaml"],"env":[{"name":"CERT_DAYS_EXPIRE","value":"10"}],"image":"docker.io/tremolosecurity/kubernetes-artifact-deployment:1.1.0","imagePullPolicy":"IfNotPresent","name":"check-certs-orchestra","resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/etc/extracerts","name":"extra-certs-dir","readOnly":true},{"mountPath":"/etc/input-maps","name":"input-maps","readOnly":true}]}],"dnsPolicy":"ClusterFirst","restartPolicy":"Never","schedulerName":"default-scheduler","securityContext":{},"serviceAccount":"openunison-operator","serviceAccountName":"openunison-operator","terminationGracePeriodSeconds":30,"volumes":[{"configMap":{"defaultMode":420,"name":"cert-controller-js-orchestra"},"name":"extra-certs-dir"},{"configMap":{"defaultMode":420,"name":"cert-controller-js-orchestra"},"name":"input-maps"}]}}}},"schedule":"0 2 * * *","successfulJobsHistoryLimit":3,"suspend":false},"status":{"lastScheduleTime":"2020-07-05T02:00:00Z"}},"oldObject":null,"options":null,"dryRun":false}}
}

test_error_message_not_allowed {
    control := {"msg":"Invalid registry","details":{}}
    result = violation with input as {"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","review":{"uid":"705ab4f5-6393-11e8-b7cc-42010a800002","kind":{"group":"autoscaling","version":"v1","kind":"Scale"},"resource":{"group":"apps","version":"v1","resource":"deployments"},"subResource":"scale","requestKind":{"group":"autoscaling","version":"v1","kind":"Scale"},"requestResource":{"group":"apps","version":"v1","resource":"deployments"},"requestSubResource":"scale","name":"my-deployment","namespace":"my-namespace","operation":"CREATE","userInfo":{"username":"admin","uid":"014fbff9a07c","groups":["system:authenticated","my-admin-group"],"extra":{"some-key":["some-value1","some-value2"]}},"object":{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"annotations":{"deployment.kubernetes.io/revision":"1"},"creationTimestamp":"2020-07-04T17:21:04Z","generation":1,"labels":{"app":"openunison-orchestra","operated-by":"openunison-operator"},"name":"openunison-orchestra","namespace":"openunison","resourceVersion":"5085","selfLink":"/apis/apps/v1/namespaces/openunison/deployments/openunison-orchestra","uid":"c25f2d22-4253-4509-9a21-f932c27fff87"},"spec":{"progressDeadlineSeconds":600,"replicas":1,"revisionHistoryLimit":10,"selector":{"matchLabels":{"application":"openunison-orchestra"}},"strategy":{"rollingUpdate":{"maxSurge":"25%","maxUnavailable":"25%"},"type":"RollingUpdate"},"template":{"metadata":{"creationTimestamp":null,"labels":{"application":"openunison-orchestra","operated-by":"openunison-operator"}},"spec":{"containers":[{"env":[{"name":"JAVA_OPTS","value":"-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom\n-DunisonEnvironmentFile=/etc/openunison/ou.env"},{"name":"fortriggerupdates","value":"changeme"}],"image":"docker.io/tremolosecurity/openunison-k8s-login-saml2:latest","imagePullPolicy":"Always","livenessProbe":{"exec":{"command":["/usr/local/openunison/bin/check_alive.py"]},"failureThreshold":10,"initialDelaySeconds":120,"periodSeconds":10,"successThreshold":1,"timeoutSeconds":10},"name":"openunison-orchestra","ports":[{"containerPort":8080,"name":"http","protocol":"TCP"},{"containerPort":8443,"name":"https","protocol":"TCP"}],"readinessProbe":{"exec":{"command":["/usr/local/openunison/bin/check_alive.py","https://127.0.0.1:8443/auth/idp/k8sIdp/.well-known/openid-configuration","issuer"]},"failureThreshold":3,"initialDelaySeconds":30,"periodSeconds":10,"successThreshold":1,"timeoutSeconds":10},"resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/etc/openunison","name":"secret-volume","readOnly":true}]}],"dnsPolicy":"ClusterFirst","restartPolicy":"Always","schedulerName":"default-scheduler","securityContext":{},"serviceAccount":"openunison-orchestra","serviceAccountName":"openunison-orchestra","terminationGracePeriodSeconds":30,"volumes":[{"name":"secret-volume","secret":{"defaultMode":420,"secretName":"orchestra"}}]}}}},"oldObject":null,"options":null,"dryRun":false}}
    result[_] == control
}

test_error_message_allowed {
    result = violation with input as {"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","review":{"uid":"705ab4f5-6393-11e8-b7cc-42010a800002","kind":{"group":"autoscaling","version":"v1","kind":"Scale"},"resource":{"group":"apps","version":"v1","resource":"deployments"},"subResource":"scale","requestKind":{"group":"autoscaling","version":"v1","kind":"Scale"},"requestResource":{"group":"apps","version":"v1","resource":"deployments"},"requestSubResource":"scale","name":"my-deployment","namespace":"my-namespace","operation":"CREATE","userInfo":{"username":"admin","uid":"014fbff9a07c","groups":["system:authenticated","my-admin-group"],"extra":{"some-key":["some-value1","some-value2"]}},"object":{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"annotations":{"deployment.kubernetes.io/revision":"1"},"creationTimestamp":"2020-07-04T17:21:04Z","generation":1,"labels":{"app":"openunison-orchestra","operated-by":"openunison-operator"},"name":"openunison-orchestra","namespace":"openunison","resourceVersion":"5085","selfLink":"/apis/apps/v1/namespaces/openunison/deployments/openunison-orchestra","uid":"c25f2d22-4253-4509-9a21-f932c27fff87"},"spec":{"progressDeadlineSeconds":600,"replicas":1,"revisionHistoryLimit":10,"selector":{"matchLabels":{"application":"openunison-orchestra"}},"strategy":{"rollingUpdate":{"maxSurge":"25%","maxUnavailable":"25%"},"type":"RollingUpdate"},"template":{"metadata":{"creationTimestamp":null,"labels":{"application":"openunison-orchestra","operated-by":"openunison-operator"}},"spec":{"containers":[{"env":[{"name":"JAVA_OPTS","value":"-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom\n-DunisonEnvironmentFile=/etc/openunison/ou.env"},{"name":"fortriggerupdates","value":"changeme"}],"image":"quay.io/tremolosecurity/openunison-k8s-login-saml2:latest","imagePullPolicy":"Always","livenessProbe":{"exec":{"command":["/usr/local/openunison/bin/check_alive.py"]},"failureThreshold":10,"initialDelaySeconds":120,"periodSeconds":10,"successThreshold":1,"timeoutSeconds":10},"name":"openunison-orchestra","ports":[{"containerPort":8080,"name":"http","protocol":"TCP"},{"containerPort":8443,"name":"https","protocol":"TCP"}],"readinessProbe":{"exec":{"command":["/usr/local/openunison/bin/check_alive.py","https://127.0.0.1:8443/auth/idp/k8sIdp/.well-known/openid-configuration","issuer"]},"failureThreshold":3,"initialDelaySeconds":30,"periodSeconds":10,"successThreshold":1,"timeoutSeconds":10},"resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/etc/openunison","name":"secret-volume","readOnly":true}]}],"dnsPolicy":"ClusterFirst","restartPolicy":"Always","schedulerName":"default-scheduler","securityContext":{},"serviceAccount":"openunison-orchestra","serviceAccountName":"openunison-orchestra","terminationGracePeriodSeconds":30,"volumes":[{"name":"secret-volume","secret":{"defaultMode":420,"secretName":"orchestra"}}]}}}},"oldObject":null,"options":null,"dryRun":false}}
    result == set()
}