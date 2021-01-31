#!/usr/bin/env bash
set -e

## clean up
echo ">>>> Deleting cluster"
minikube delete

# start cluster
echo ">>>> Starting cluster"
minikube start --driver hyperkit

# add falcosecurity charts to the repo
echo ">>>> Adding helm repo"
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# install falco
echo ">>>> Installing falco"
helm install falco falcosecurity/falco
FALCO_POD=$(kubectl get pods --selector app=falco -ojsonpath='{range .items[*]}{.metadata.name}{"\n"}')
echo ">>>> Waiting for pod $FALCO_POD to become ready"
kubectl wait --for=condition=Ready pod/$FALCO_POD --timeout=300s

# install nginx
echo ">>>> Installing nginx"
kubectl run nginx --image=nginx
echo ">>>> Waiting for pod nginx to become ready"
kubectl wait --for=condition=Ready pod/nginx --timeout=60s

# accessing sensitive files on the nginx container
echo ">>>> Accessing sensitive files on the nginx container"
kubectl exec -it nginx -- cat /etc/shadow

# check the logs of the falco
echo ">>>> Checking the logs of the falco"
kubectl logs -f $FALCO_POD
