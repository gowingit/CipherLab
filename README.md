CipherLab

A Spring Boot-based Java project for cipher and RSA encryption/decryption analysis.

Project Structure

cipherlab/
src/
  main/
    java/
      com/cipherlab/
        cipher/         - Cipher utilities
        rsa/            - RSA operations
        analysis/       - Analysis utilities
        controller/     - REST Controllers
        model/          - Data models
      CipherlabApplication.java
    resources/
      application.properties
  test/
    java/
pom.xml
.gitignore

Getting Started

Prerequisites
- Java 17 or higher
- Maven 3.6 or higher

Build and Run

Build the project:
mvn clean package

Run the application:
mvn spring-boot:run

The application will start on http://localhost:8080

Health Check

To check if the application is running:
curl http://localhost:8080/api/health

Technologies Used

- Spring Boot 3.1.0
- Java 17
- Maven
- JUnit 5

