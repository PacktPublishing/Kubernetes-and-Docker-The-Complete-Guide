package k8sallowedregistries

violation[{"msg": msg, "details": {}}] {
  invalidRegistry
  msg := "Invalid registry"
}


# returns true if a valid registry is not specified
invalidRegistry {
  input_containers[container]
  not startswith(container.image, "quay.io/")
}

# load images from Pod objects
input_containers[container] {
  container := input.request.object.spec.containers[_]
}

# load images from Deployment and StatefulSet objects
input_containers[container] {
  container := input.request.object.spec.template.spec.containers[_]
}

# load images from CronJob objects
# Uncomment in chapter 11
#input_containers[container] {
#  container := input.request.object.spec.jobTemplate.spec.template.spec.containers[_]
#}