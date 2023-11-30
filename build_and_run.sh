#!/bin/bash

docker stop srsc_tp2-fserver-auth-service-1
docker stop srsc_tp2-fserver-access-control-service-1
docker stop srsc_tp2-fserver-storage-service-1
docker stop srsc_tp2-fserver-service-1

docker rm srsc_tp2-fserver-auth-service-1
docker rm srsc_tp2-fserver-access-control-service-1
docker rm srsc_tp2-fserver-storage-service-1
docker rm srsc_tp2-fserver-service-1

docker rmi srsc_tp2-fserver-auth-service
docker rmi srsc_tp2-fserver-access-control-service
docker rmi srsc_tp2-fserver-storage-service
docker rmi srsc_tp2-fserver-service

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

java --module-path lib --add-modules javafx.controls,javafx.fxml -jar CommandApp-1.jar

