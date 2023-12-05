FROM openjdk:17

WORKDIR /app
COPY target/FServerStorage-1.jar app.jar
COPY src/main/resources/keystore.jks keystore.jks
COPY src/main/resources/truststore.jks truststore.jks
COPY src/main/resources/dispatcher.cer dispatcher.cer
COPY src/main/resources/storage.cer storage.cer
COPY src/main/resources/filesystem-config.properties filesystem-config.properties
COPY src/main/resources/dropbox-config.properties dropbox-config.properties
COPY src/main/resources/crypto-config.properties crypto-config.properties
COPY src/main/resources/ola.txt ola.txt

EXPOSE 8083

CMD ["java", "-jar", "app.jar"]