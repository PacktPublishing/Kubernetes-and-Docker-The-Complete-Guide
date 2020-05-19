#!/bin/bash
clear

tput setaf 6
echo -e "\n \n*******************************************************************************************************************"
echo -e "Docker Installation started..."
echo -e "*******************************************************************************************************************"

tput setaf 6
echo -e "\n \n*******************************************************************************************************************"
echo -e "Updating Repo and adding Doker repo apt-key"
echo -e "*******************************************************************************************************************"
tput setaf 2
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg-agent  software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

tput setaf 6
echo -e "\n \n*******************************************************************************************************************"
echo -e "Adding Docker repo"
echo -e "*******************************************************************************************************************"
tput setaf 2
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update

tput setaf 6
echo -e "\n \n*******************************************************************************************************************"
echo -e "Installing Docker"
echo -e "*******************************************************************************************************************"
tput setaf 2
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

tput setaf 6
echo -e "\n \n*******************************************************************************************************************"
echo -e "Adding current user to Docker group"
echo -e "*******************************************************************************************************************"
tput setaf 2
sudo groupadd docker
sudo usermod -aG docker $USER

tput setaf 6
echo -e "\n \n*******************************************************************************************************************"
echo -e "Enabling and Starting Docker - Will require you to enter your sudo password"
echo -e "*******************************************************************************************************************"
tput setaf 2
sudo systemctl enable docker && systemctl start docker

tput setaf 3
echo -e "\n \n*******************************************************************************************************************"
echo -e "Installation complete\n\n"
echo -e "Respawning shell for new groups - you will need to enter your password"
echo -e "*******************************************************************************************************************"
tput setaf 2
exec su -l $USER
