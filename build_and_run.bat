
docker rm -f $(docker ps -a -q)

docker rmi $(docker images -q)

cd FServer
call mvn clean package

cd ../FServerAccessControl
call mvn clean package

cd ../FServerAuth
call mvn clean package

cd ../FServerStorage
call mvn clean package

cd ../CommandApp
call mvn clean package

cd ..
docker-compose up -d

docker network connect srsc_tp2-fserver-network srsc_tp2-fserver-auth-service-1
docker network connect srsc_tp2-fserver-network srsc_tp2-fserver-access-control-service-1
docker network connect srsc_tp2-fserver-network srsc_tp2-fserver-storage-service-1
docker network connect srsc_tp2-fserver-network srsc_tp2-fserver-service-1

java -jar CommandApp/target/CommandApp-1.jar
