# syntax=docker/dockerfile:1
FROM maven:3.9.9-eclipse-temurin-21 AS builder
WORKDIR /workspace
COPY pom.xml ./
COPY .mvn .mvn
COPY mvnw .
COPY src src
RUN chmod +x mvnw && ./mvnw -q -DskipTests clean package

FROM gcr.io/distroless/java21-debian12:nonroot
WORKDIR /app
COPY --from=builder /workspace/target/eci-0.0.1-SNAPSHOT.jar /app/app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
