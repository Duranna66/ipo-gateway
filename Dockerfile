FROM bellsoft/liberica-openjdk-alpine:17
WORKDIR /opt

COPY build/libs/*.jar ipo.jar

CMD ["java", "-jar", "ipo.jar"]