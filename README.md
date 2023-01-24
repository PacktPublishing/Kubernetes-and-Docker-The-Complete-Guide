


# Kubernetes and Docker: An Enterprise Guide, published by Packt
  
Note:  Not all Chapters have code in the repo. Chapters 2, 3, and 5 do not have any exercises and therefore, you will not find any code or scripts in the repo for those chapters.  

Updated information and book errata can be found in the repo wiki https://github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/wiki/_new  
  
Welcome to the repository for the Packt book, Kubernetes and Docker: An Enterprise Guide by Scott Surovich and Marc Boorshtein.  
  
This repo contains the scripts that are references in the book exercises.  You should clone this repo to the host you will use for the exercises included with the chapters.
Each chapter will explain the important portions of the scripts so you will have an understanding of what the scripts are executing.  While the scripts are not required, it will save you time over typing manifests manually.  
  
Exercises are included in chapters 1, 5-14.  
Chapters 2 and 3 contain Docker examples which can be followed on your own host, but they are not required.  
  
# Required Experience  
You should have a basic understanding of Docker and Kubernetes before reading the book.  The book is already packed with a lot of content, and we didn't have any space to cover the details of installing a new cluster or diving into Kubernetes objects in depth.  
  
Chapters 1-3 will provide a refresh on Docker and the main features that we feel are important to understand, including how Docker uses the host filesystem and the hosts networking. Chapter 4 will provide a crash course of Kubernetes objects, but to explain each object in depth would fill an entire book, and there are many books on K8s objects already, but it will provide a "pocket guide" to objects for new readers, or as a refresher to readers with some experience. 

# System Requirements  
Ubuntu 18.04  
4GB for most exercises, 8GB preferred  
5-10GB of free disk space on the Docker host system    

Note: The exercises in the book were designed to be run on an Ubuntu 18.04, but all exercises have been tested with both Ubuntu 16 and 18.  
While the majority of the exercises can be executed on any system running Linux, the exercises in Chapter 12 may not execute correctly on a non-Ubuntu system.  
All other exercise should execute on CentOS or Ubuntu.

WSL2 and Docker was tested and most exercises will work correctly, however since Chapter 12 requires building modules for the Kernel, the exercises will not run on WSL2 at this time.  
  
# Book Overview  
There are a total of 14 chapters in the book that cover topics ranging from Docker to provisioning a platform.  We created the book with the intention of helping readers go beyond a basic Kubernetes cluster, with a focus on enterprise features like adding a layer 4 load-balancer for services with dynamic service name registration, integrating a cluster with Active Directory (or LDAP), securing the K8s dashboard using RBAC and a reverse proxy, how NOT to secure the K8s dashboard, K8s impersonation, PSP's and OPA policies to secure a cluster, auditing pod actions using Falco integrated with EFK, backing up workloads using Velero, and provisioning a platform using Tekton and CI/CD tools.
### Download a free PDF

 <i>If you have already purchased a print or Kindle version of this book, you can get a DRM-free PDF version at no cost.<br>Simply click on the link to claim your free PDF.</i>
<p align="center"> <a href="https://packt.link/free-ebook/9781839213403">https://packt.link/free-ebook/9781839213403 </a> </p>