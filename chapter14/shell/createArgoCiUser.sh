#!/bin/bash

kubectl patch configmap argocd-cm -n argocd -p '{"data":{"accounts.openunison":"apiKey","accounts.openunison.enabled":"true"}}' 