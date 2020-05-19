ingressip=$(hostname  -I | cut -f1 -d' ')
ingress=`cat "kibana-ingress.yaml" | sed "s/{hostip}/$ingressip/g"` 

echo "$ingress" | kubectl apply -f -

tput setaf 3
echo -e "\n\nYou can access your Kibana dashboard in any browser on your local network using http://kibana.$ingressip.nip.io\n\n"
tput setaf 2

