FROM maven:3.9.11-eclipse-temurin-21 AS build
WORKDIR /build
COPY backend/pom.xml ./pom.xml
RUN mvn -B -ntp dependency:go-offline
COPY backend/src ./src
RUN mvn -B -ntp -DskipTests package

FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=build /build/target/mail-admin-0.1.0.jar /app/mail-admin.jar
COPY deploy/backend-entrypoint.sh /app/entrypoint.sh
RUN chmod 0555 /app/entrypoint.sh && chmod 0444 /app/mail-admin.jar
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
