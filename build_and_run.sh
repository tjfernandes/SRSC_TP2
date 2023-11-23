#!/bin/bash

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

