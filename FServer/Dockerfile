FROM openjdk:17

WORKDIR /app
COPY target/FServer-1.jar app.jar
COPY src/main/resources/keystore.jks keystore.jks
COPY src/main/resources/truststore.jks truststore.jks
COPY src/main/resources/dispatcher.cer dispatcher.cer
COPY src/main/resources/authentication.cer authentication.cer
COPY src/main/resources/access_control.cer access_control.cer
COPY src/main/resources/storage.cer storage.cer

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]