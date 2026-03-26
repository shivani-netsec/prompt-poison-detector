package com.promptguard.detector.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * SpringDoc OpenAPI / Swagger UI configuration.
 *
 * <p>Swagger UI is available at: <a href="http://localhost:8080/swagger-ui.html">
 * http://localhost:8080/swagger-ui.html</a>
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI promptGuardOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("AI Prompt Poisoning Detector API")
                .version("1.0.0")
                .description("""
                    Production-ready REST API for detecting malicious prompt poisoning attempts
                    before they reach an AI system. Analyzes prompts for instruction overrides,
                    role escalation, prompt injection, hidden triggers, and data extraction intent.
                    """)
                .contact(new Contact()
                    .name("PromptGuard Security Team")
                    .email("security@promptguard.io"))
                .license(new License()
                    .name("MIT License")
                    .url("https://opensource.org/licenses/MIT")))
            .servers(List.of(
                new Server().url("http://localhost:8080").description("Local Development")
            ));
    }
}
