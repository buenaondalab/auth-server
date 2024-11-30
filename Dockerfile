FROM eclipse-temurin:21.0.5_11-jre-alpine
RUN addgroup -S spring && adduser -S spring -G spring && mkdir /opt/app
USER spring:spring
COPY target/*.jar /opt/app/app.jar
ENTRYPOINT ["java", "-jar", "/opt/app/app.jar"]