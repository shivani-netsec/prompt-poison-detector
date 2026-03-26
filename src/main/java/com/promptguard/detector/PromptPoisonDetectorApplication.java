package com.promptguard.detector;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the AI Prompt Poisoning Detector application.
 *
 * <h2>Quick start</h2>
 * <pre>
 *   # Build
 *   mvn clean package -DskipTests
 *
 *   # Run (H2 in-memory database, no API key required)
 *   java -jar target/prompt-poison-detector-1.0.0.jar
 *
 *   # Run with OpenAI explanations
 *   OPENAI_API_KEY=sk-... java -jar target/prompt-poison-detector-1.0.0.jar
 * </pre>
 *
 * <h2>Useful URLs</h2>
 * <ul>
 *   <li>Frontend  : <a href="http://localhost:8080/">http://localhost:8080/</a></li>
 *   <li>Swagger UI: <a href="http://localhost:8080/swagger-ui.html">http://localhost:8080/swagger-ui.html</a></li>
 *   <li>H2 Console: <a href="http://localhost:8080/h2-console">http://localhost:8080/h2-console</a> (JDBC URL: jdbc:h2:mem:promptguarddb)</li>
 *   <li>API Docs  : <a href="http://localhost:8080/api-docs">http://localhost:8080/api-docs</a></li>
 * </ul>
 */
@SpringBootApplication
public class PromptPoisonDetectorApplication {

    public static void main(String[] args) {
        SpringApplication.run(PromptPoisonDetectorApplication.class, args);
    }
}
