FROM openjdk:17

WORKDIR /app
COPY target/FServerAccessControl-1.jar app.jar

EXPOSE 8082

CMD ["java", "-jar", "app.jar"]