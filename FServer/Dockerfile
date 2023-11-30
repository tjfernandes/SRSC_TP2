FROM openjdk:17

WORKDIR /app
COPY target/FServer-1.jar app.jar

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]