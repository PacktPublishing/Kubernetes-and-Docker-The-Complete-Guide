package k8sallowedregistries

violation[{"msg": msg, "details": {}}] {
  invalidRegistry
  msg := "Invalid registry"
}


# returns true if a valid registry is not specified
invalidRegistry {
  not validRegistry
}

# checks if the containers match any of the specified registries
validRegistry {
  input_containers[container]
  allowedRegistries := input.parameters.registries[_]
  startswith(container.image, allowedRegistries)
}

# load images from Pod objects
input_containers[container] {
  container := input.review.object.spec.containers[_]
}

# load images from Deployment and StatefulSet objects
input_containers[container] {
  container := input.review.object.spec.template.spec.containers[_]
}

# load images from CronJob objects
input_containers[container] {
  container := input.review.object.spec.jobTemplate.spec.template.spec.containers[_]
}