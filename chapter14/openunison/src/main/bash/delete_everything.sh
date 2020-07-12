#!/bin/bash
kubectl delete namespace openunison
kubectl delete namespace openunison-deploy
kubectl delete certificatesigningrequest openunison.openunison.svc.cluster.local
kubectl delete certificatesigningrequest amq.openunison.svc.cluster.local
kubectl delete certificatesigningrequest kubernetes-dashboard.kube-system.svc.cluster.local
kubectl delete crd oidc-sessions.openunison.tremolo.io
kubectl delete crd openunisons.openunison.tremolo.io
kubectl delete crd users.openunison.tremolo.io
kubectl delete role orchestra-dashboard -n kube-system
kubectl delete rolebinding orchestra-dashboard -n kube-system
kubectl delete clusterrole orchestra-certs 
kubectl delete clusterrolebinding orchestra-certs 