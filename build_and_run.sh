#!/bin/bash

# Function to check if a Docker container exists
container_exists() {
    docker ps -a --format '{{.Names}}' | grep -q "^$1$"
}

# Function to check if a Docker image exists
image_exists() {
    docker image inspect "$1" &> /dev/null
}

# Function to stop and remove a Docker container if it exists
remove_container_if_exists() {
    if container_exists "$1"; then
        docker stop "$1"
        docker rm "$1"
    else
        echo "Container $1 does not exist."
    fi
}

# Function to remove a Docker image if it exists
remove_image_if_exists() {
    if image_exists "$1"; then
        docker rmi "$1"
    else0
        echo "Image $1 does not exist."
    fi
}

remove_container_if_exists srsc_tp2-fserver-auth-service-1
remove_container_if_exists srsc_tp2-fserver-access-control-service-1
remove_container_if_exists srsc_tp2-fserver-storage-service-1
remove_container_if_exists srsc_tp2-fserver-service-1

remove_image_if_exists srsc_tp2-fserver-auth-service
remove_image_if_exists srsc_tp2-fserver-access-control-service
remove_image_if_exists srsc_tp2-fserver-storage-service
remove_image_if_exists srsc_tp2-fserver-service

cd FServer
mvn clean package

cd ../FServerAccessControl
mvn clean package

cd ../FServerAuth
mvn clean package

cd ../FServerStorage
mvn clean package

cd ../CommandApp
mvn clean package
cp target/CommandApp-1.jar ../

cd ..
docker-compose up -d

java -jar CommandApp-1.jar
