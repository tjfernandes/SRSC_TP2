FROM openjdk:17

WORKDIR /app
COPY target/FServerStorage-1.jar app.jar
COPY src/main/resources/keystore.jks keystore.jks
COPY src/main/resources/storage.cer storage.cer

EXPOSE 8083

CMD ["java", "-jar", "app.jar"]