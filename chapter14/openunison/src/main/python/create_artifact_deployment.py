import yaml
import base64


# pull in deploy javascript
with open('src/main/js/deploy.js','r') as jsdep:
    deploy_js = jsdep.read()

#deploy_js = base64.standard_b64encode(deploy_js)

with open('src/main/yaml/openunison.yaml','r') as oyaml:
    openunison_yaml = oyaml.read()

#openunison_yaml = base64.standard_b64encode(openunison_yaml)

with open('src/main/yaml/artifact-deployment-base.yaml','r') as artifact_deployment_src:
    artifact_deployment_yaml = artifact_deployment_src.read()

with open('src/main/sql/quartz_tables.sql') as quartz_sql_src:
    quartz_sql = quartz_sql_src.read();

config_map = {
    "apiVersion":"v1",
    "kind":"ConfigMap",
    "metadata":{
        "name":"deployment-scripts",
        "namespace":"openunison-deploy"
    },
    "data":{
        "deploy.js":deploy_js,
        "openunison.yaml":openunison_yaml,
        "quartz.sql":quartz_sql
    }
}

with open('src/main/yaml/artifact-deployment.yaml','w') as artifact_deployment:
    artifact_deployment.write("---\n")
    artifact_deployment.write(yaml.dump(config_map,default_flow_style=False))
    artifact_deployment.write("---\n")
    artifact_deployment.write(artifact_deployment_yaml)
    artifact_deployment.close()

