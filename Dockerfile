# syntax=docker/dockerfile:1
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /app
COPY . .
RUN ./gradlew clean bootJar --no-daemon

FROM eclipse-temurin:21-jdk-alpine
WORKDIR /
COPY --from=build /app/build/libs/*.jar app.jar
VOLUME /tmp
ENTRYPOINT ["java","-jar","/app.jar"] 