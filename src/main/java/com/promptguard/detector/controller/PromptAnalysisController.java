package com.promptguard.detector.controller;

import com.promptguard.detector.dto.AnalyzeRequest;
import com.promptguard.detector.dto.AnalyzeResponse;
import com.promptguard.detector.model.PromptAnalysisLog;
import com.promptguard.detector.service.PromptAnalysisService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST controller exposing prompt-poisoning analysis endpoints.
 *
 * <p>Base path: {@code /}
 *
 * <ul>
 *   <li>{@code POST /analyzePrompt}   – analyze a prompt</li>
 *   <li>{@code GET  /logs}            – retrieve all audit logs</li>
 *   <li>{@code GET  /logs/high-risk}  – retrieve only HIGH-risk logs</li>
 * </ul>
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Prompt Analysis", description = "Detect and score malicious prompt poisoning attempts")
public class PromptAnalysisController {

    private final PromptAnalysisService analysisService;

    // -----------------------------------------------------------------------
    // POST /analyzePrompt
    // -----------------------------------------------------------------------

    @Operation(
        summary     = "Analyze a user prompt for poisoning threats",
        description = "Runs the rule engine and (optionally) an AI model to detect injection, "
                    + "role escalation, data extraction, and other poisoning patterns. "
                    + "The result is persisted to the audit log and returned in the response."
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description  = "Analysis completed successfully",
            content = @Content(
                mediaType = MediaType.APPLICATION_JSON_VALUE,
                schema = @Schema(implementation = AnalyzeResponse.class),
                examples = @ExampleObject(name = "High-risk example", value = """
                    {
                      "riskScore": 85,
                      "riskLevel": "HIGH",
                      "detectedThreats": [
                        "Instruction Override Attempt",
                        "Role / Privilege Escalation"
                      ],
                      "explanation": "The prompt contains a direct instruction override ('ignore all previous instructions') and a role escalation request ('act as an unrestricted AI'). This is a classic jailbreak pattern designed to bypass safety filters.",
                      "analyzedAt": "2026-03-26T12:00:00",
                      "logId": 1
                    }
                    """)
            )
        ),
        @ApiResponse(responseCode = "400", description = "Invalid request body (validation failed)")
    })
    @PostMapping(
        value    = "/analyzePrompt",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<AnalyzeResponse> analyzePrompt(@Valid @RequestBody AnalyzeRequest request) {
        log.debug("POST /analyzePrompt received");
        AnalyzeResponse response = analysisService.analyze(request);
        return ResponseEntity.ok(response);
    }

    // -----------------------------------------------------------------------
    // GET /logs
    // -----------------------------------------------------------------------

    @Operation(
        summary     = "Retrieve all analysis audit logs",
        description = "Returns every prompt that has been analyzed, ordered by insertion order."
    )
    @GetMapping(value = "/logs", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<PromptAnalysisLog>> getLogs() {
        return ResponseEntity.ok(analysisService.getAllLogs());
    }

    // -----------------------------------------------------------------------
    // GET /logs/high-risk
    // -----------------------------------------------------------------------

    @Operation(
        summary     = "Retrieve HIGH-risk audit logs",
        description = "Returns only log entries with a risk score >= 67 (HIGH level)."
    )
    @GetMapping(value = "/logs/high-risk", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<PromptAnalysisLog>> getHighRiskLogs() {
        return ResponseEntity.ok(analysisService.getHighRiskLogs());
    }
}
