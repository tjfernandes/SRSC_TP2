#!/bin/bash

docker rm -f $(docker ps -a -q)

docker rmi $(docker images -q)

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

docker network connect srsc_tp2-fserver-network srsc_tp2-fserver-auth-service-1
docker network connect srsc_tp2-fserver-network srsc_tp2-fserver-access-control-service-1
docker network connect srsc_tp2-fserver-network srsc_tp2-fserver-storage-service-1
docker network connect srsc_tp2-fserver-network srsc_tp2-fserver-service-1

java -jar CommandApp-1.jar
