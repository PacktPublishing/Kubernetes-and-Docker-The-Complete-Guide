#Script to Deploye ElasticSearch and Kibana

#First - We create a new namespace called logging
kubectl create ns logging

#Next, add Bitnami's Chart Repo
helm repo add bitnami https://charts.bitnami.com/bitnami

#Deploy ElasticSearch and set some values on data size and replicas to the logging namespace
helm install elasticsearch bitnami/elasticsearch --set master.persistence.size=1Gi,data.persistence.size=1Gi,data.replicas=2 --namespace logging

#Deploy Kibana with values to point to the ES server and port to the logging namespace
helm install kibana --set elasticsearch.hosts[0]=elasticsearch-elasticsearch-coordinating-only --set elasticsearch.port=9200,persistence.size=1Gi --namespace logging bitnami/kibana

#Deploy fluentd - the config has been edited to point to the correct ES Service created during the Helm installation of ES
#These will deploy to the kube-system namespace
kubectl create -f fluentd-config.yaml
kubectl create -f fluentd-ds.yaml

helm install falcosidekick -f ./falcosidekick/values.yaml ./falcosidekick --namespace logging
