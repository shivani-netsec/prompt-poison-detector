package com.promptguard.detector.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.promptguard.detector.dto.ThreatDetail;
import com.promptguard.detector.model.ThreatCategory;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

/**
 * HTTP client that calls the OpenAI Chat Completions API to generate a
 * natural-language explanation for detected prompt-poisoning threats.
 *
 * <p>If no OpenAI API key is configured (key == "YOUR_OPENAI_API_KEY_HERE"),
 * the client falls back to a deterministic offline explanation so the
 * application remains fully usable without a live key.
 */
@Service
@Slf4j
public class OpenAiClient {

    private static final String PLACEHOLDER_KEY = "YOUR_OPENAI_API_KEY_HERE";

    @Value("${openai.api.key}")
    private String apiKey;

    @Value("${openai.api.url}")
    private String apiUrl;

    @Value("${openai.model}")
    private String model;

    @Value("${openai.max-tokens}")
    private int maxTokens;

    @Value("${openai.temperature}")
    private double temperature;

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public OpenAiClient(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Generate a human-readable explanation for the given prompt and threats.
     *
     * @param userPrompt   original user prompt (may be truncated for safety)
     * @param threats      list of threats detected by the rule engine
     * @param riskScore    composite risk score
     * @return explanation string; never null
     */
    public String generateExplanation(String userPrompt, List<ThreatDetail> threats, int riskScore) {
        if (PLACEHOLDER_KEY.equals(apiKey) || apiKey == null || apiKey.isBlank()) {
            log.info("OpenAI API key not configured – using offline fallback explanation");
            return buildOfflineExplanation(threats, riskScore);
        }

        try {
            return callOpenAi(userPrompt, threats, riskScore);
        } catch (RestClientException ex) {
            log.warn("OpenAI API call failed ({}), falling back to offline explanation", ex.getMessage());
            return buildOfflineExplanation(threats, riskScore);
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private String callOpenAi(String userPrompt, List<ThreatDetail> threats, int riskScore) {
        String systemPrompt = buildSystemPrompt();
        String userMessage  = buildUserMessage(userPrompt, threats, riskScore);

        Map<String, Object> requestBody = Map.of(
            "model", model,
            "max_tokens", maxTokens,
            "temperature", temperature,
            "messages", List.of(
                Map.of("role", "system", "content", systemPrompt),
                Map.of("role", "user",   "content", userMessage)
            )
        );

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(apiKey);

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);

        log.debug("Calling OpenAI API: model={}", model);
        ResponseEntity<ChatCompletionResponse> response =
            restTemplate.exchange(apiUrl, HttpMethod.POST, entity, ChatCompletionResponse.class);

        if (response.getBody() != null
                && response.getBody().getChoices() != null
                && !response.getBody().getChoices().isEmpty()) {
            return response.getBody().getChoices().get(0).getMessage().getContent().trim();
        }
        return buildOfflineExplanation(threats, riskScore);
    }

    private String buildSystemPrompt() {
        return """
            You are a cybersecurity expert specializing in AI safety and prompt injection attacks.
            Your task is to explain, in clear non-technical language, why a given user prompt
            has been flagged as potentially malicious. Be specific about each threat, reference
            the exact portion of the prompt that triggered it, and explain the real-world risk.
            Keep your response concise (3–5 sentences). Do NOT suggest how to bypass detections.
            """;
    }

    private String buildUserMessage(String userPrompt, List<ThreatDetail> threats, int riskScore) {
        StringBuilder sb = new StringBuilder();
        sb.append("Risk Score: ").append(riskScore).append("/100\n\n");
        sb.append("Detected Threats:\n");
        for (ThreatDetail t : threats) {
            sb.append("- ").append(t.getCategory().getDisplayName())
              .append(" (evidence: \"").append(t.getEvidence()).append("\")\n");
        }
        // Truncate prompt to avoid sending too many tokens
        String truncated = userPrompt.length() > 500 ? userPrompt.substring(0, 500) + "..." : userPrompt;
        sb.append("\nOriginal prompt (truncated):\n\"").append(truncated).append("\"");
        sb.append("\n\nPlease explain why this prompt is dangerous.");
        return sb.toString();
    }

    private String buildOfflineExplanation(List<ThreatDetail> threats, int riskScore) {
        if (threats.isEmpty()) {
            return "No significant threat patterns were detected. The prompt appears to be safe based on rule-based analysis.";
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("This prompt received a risk score of %d/100. ", riskScore));
        sb.append("The following threat patterns were identified: ");

        for (int i = 0; i < threats.size(); i++) {
            ThreatDetail t = threats.get(i);
            sb.append(t.getCategory().getDisplayName());
            if (!t.getEvidence().isBlank()) {
                sb.append(String.format(" (triggered by: \"%s\")", t.getEvidence()));
            }
            if (i < threats.size() - 1) sb.append("; ");
        }

        sb.append(". These patterns are commonly associated with attempts to manipulate AI systems, "
                + "bypass safety filters, extract sensitive information, or gain unauthorized capabilities. "
                + "This prompt should be reviewed before being forwarded to an AI model.");

        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // OpenAI response POJOs
    // -----------------------------------------------------------------------

    @Data
    private static class ChatCompletionResponse {
        private List<Choice> choices;
    }

    @Data
    private static class Choice {
        private Message message;
    }

    @Data
    private static class Message {
        private String role;
        private String content;
    }
}
