FROM openjdk:17

WORKDIR /app
COPY target/FServerStorage-1.jar app.jar

EXPOSE 8083

CMD ["java", "-jar", "app.jar"]