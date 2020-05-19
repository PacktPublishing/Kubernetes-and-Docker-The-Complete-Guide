#!/bin/bash
clear

tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Installing Falco..."
echo -e "\nYou may be prompted to supply your sudo password during script execution"
echo -e "*******************************************************************************************************************"

tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Installing full Go - required to build the driverkit exe"
echo -e "*******************************************************************************************************************"
tput setaf 2
sudo add-apt-repository ppa:longsleep/golang-backports -y
sudo apt-update -y
sudo apt install golang-go -y

tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Pulling driverkit-builder image"
echo -e "*******************************************************************************************************************"
tput setaf 2
docker pull falcosecurity/driverkit-builder

tput setaf 5
echo -e "\n \n*******************************************************************************************************************"
echo -e "Downloading and building driverkit executable"
echo -e "*******************************************************************************************************************"
tput setaf 2
GO111MODULE="on" go get github.com/falcosecurity/driverkit

tput setaf 5
kernelversion=$(uname -v | cut -f1 -d'-' | cut -f2 -d'#')
kernelrelease=$(uname -r)
echo -e "\n \n*******************************************************************************************************************"
echo -e "Building Falco probe based on Host OS"
tput setaf 7
echo -e "Kernel version: $kernelversion"
echo -e "Kernel release: $kernelrelease"
tput setaf 5
echo -e "*******************************************************************************************************************"
tput setaf 2
driverkit docker --output-module /tmp/falco.ko --kernelversion=$kernelversion --kernelrelease=$kernelrelease --driverversion=dev --target=ubuntu-generic

tput setaf 6
echo -e "\n \n*******************************************************************************************************************"
echo -e "Copying Falco module to modules/kernelrelease/ and adding to Host"
echo -e "*******************************************************************************************************************"
tput setaf 2
sudo cp /tmp/falco.ko /lib/modules/$kernelrelease/falco.ko
sudo depmod
sudo modprobe falco

tput setaf 7
echo -e "\n \n*******************************************************************************************************************"
echo -e "Since Docker only loads the filesystem when it starts, we need to restart Docker so KinD will see the new Falco"
echo -e" modules in /dev"
echo -e "\nRestarting Docker..."
echo -e "*******************************************************************************************************************"

tput setaf 6
echo -e "\n \n*******************************************************************************************************************"
echo -e "Creting Falco namespace"
echo -e "*******************************************************************************************************************"
tput setaf 2
kubectl create ns falco


tput setaf 6
echo -e "\n \n*******************************************************************************************************************"
echo -e "Deploying Falco manifests to Cluster"
echo -e "*******************************************************************************************************************"
tput setaf 2
kubectl create configmap falco-config --from-file=falco/falco-config -n falco
kubectl apply -f falco/install -n falco

tput setaf 3
echo -e "\n \n*******************************************************************************************************************"
echo -e "Falco deployment complete - Verify that the Falco pod has been created in the Falco namespace and that its running"
echo -e "*******************************************************************************************************************"
tput setaf 2

echo -e "\n\n"
