#!/bin/bash

cd FServer
mvn clean package

cd ../FServerAccessControl
mvn clean package

cd ../FServerAuth
mvn clean package

cd ../FServerStorage
mvn clean package

cd ..
docker-compose up -d
