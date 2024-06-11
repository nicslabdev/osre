FROM openjdk:11-jre-slim

WORKDIR /app

COPY src/main/java/nics/crypto/osre/MainTLSHolder.java /app/MainTLSHolder.java

ENTRYPOINT ["java", "nics.crypto.osre.MainTLSHolder"]