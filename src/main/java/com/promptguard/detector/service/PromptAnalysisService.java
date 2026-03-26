package com.promptguard.detector.service;

import com.promptguard.detector.dto.AnalyzeRequest;
import com.promptguard.detector.dto.AnalyzeResponse;
import com.promptguard.detector.dto.ThreatDetail;
import com.promptguard.detector.model.PromptAnalysisLog;
import com.promptguard.detector.model.RiskLevel;
import com.promptguard.detector.repository.PromptAnalysisLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Orchestrates the full prompt-poisoning analysis pipeline:
 *
 * <ol>
 *   <li>Rule-based detection (fast, offline)</li>
 *   <li>Risk score calculation</li>
 *   <li>AI-powered explanation generation</li>
 *   <li>Audit log persistence</li>
 * </ol>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PromptAnalysisService {

    private final RuleEngineService     ruleEngineService;
    private final RiskScoringService    riskScoringService;
    private final OpenAiClient          openAiClient;
    private final PromptAnalysisLogRepository logRepository;

    /**
     * Analyze a prompt for poisoning attempts and persist the result.
     *
     * @param request incoming request containing the raw prompt
     * @return structured analysis response
     */
    @Transactional
    public AnalyzeResponse analyze(AnalyzeRequest request) {
        String prompt = request.getPrompt();
        log.info("Analyzing prompt (length={}, caller={})", prompt.length(), request.getCallerId());

        // Step 1 – rule engine
        List<ThreatDetail> threats = ruleEngineService.evaluate(prompt);

        // Step 2 – risk score + level
        int       riskScore = riskScoringService.calculateScore(threats);
        RiskLevel riskLevel = riskScoringService.mapToLevel(riskScore);

        // Step 3 – explainability (AI-generated or offline fallback)
        String explanation = openAiClient.generateExplanation(prompt, threats, riskScore);

        // Step 4 – build threat display names list
        List<String> threatNames = threats.stream()
                .map(t -> t.getCategory().getDisplayName())
                .distinct()
                .collect(Collectors.toList());

        LocalDateTime now = LocalDateTime.now();

        // Step 5 – persist audit log
        PromptAnalysisLog logEntry = PromptAnalysisLog.builder()
                .promptText(prompt)
                .riskScore(riskScore)
                .riskLevel(riskLevel)
                .detectedThreats(String.join(", ", threatNames))
                .explanation(explanation)
                .analyzedAt(now)
                .callerId(request.getCallerId())
                .build();
        PromptAnalysisLog saved = logRepository.save(logEntry);

        log.info("Analysis complete: id={} riskScore={} riskLevel={} threats={}",
                saved.getId(), riskScore, riskLevel, threatNames);

        return AnalyzeResponse.builder()
                .riskScore(riskScore)
                .riskLevel(riskLevel)
                .detectedThreats(threatNames)
                .explanation(explanation)
                .analyzedAt(now)
                .logId(saved.getId())
                .build();
    }

    /**
     * Retrieve all stored analysis logs.
     */
    @Transactional(readOnly = true)
    public List<PromptAnalysisLog> getAllLogs() {
        return logRepository.findAll();
    }

    /**
     * Retrieve high-risk logs (score >= 67).
     */
    @Transactional(readOnly = true)
    public List<PromptAnalysisLog> getHighRiskLogs() {
        return logRepository.findHighRiskLogs(67);
    }
}
