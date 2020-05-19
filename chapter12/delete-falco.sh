#!/bin/bash
clear

tput setaf 6
echo -e "\n \n*******************************************************************************************************************"
echo -e "Removing Falco deployment from cluster"
echo -e "*******************************************************************************************************************"
tput setaf 2
kubectl delete configmap falco-config
kubectl delete -f falco/install
