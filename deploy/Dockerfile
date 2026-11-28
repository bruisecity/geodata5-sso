# geodata5-sso runtime image
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY target/geodata5-sso.jar app.jar
# Non-root
USER 1000
EXPOSE 9000
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75"
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]
