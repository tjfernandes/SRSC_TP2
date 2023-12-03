FROM openjdk:17

WORKDIR /app
COPY target/FServerAuth-1.jar app.jar
COPY src/main/resources/keystore.jks keystore.jks
COPY src/main/resources/truststore.jks truststore.jks
COPY src/main/resources/dispatcher.cer dispatcher.cer
COPY src/main/resources/authentication.cer authentication.cer

EXPOSE 8081

CMD ["java", "-jar", "app.jar"]