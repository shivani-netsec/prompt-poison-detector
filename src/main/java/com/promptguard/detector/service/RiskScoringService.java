package com.promptguard.detector.service;

import com.promptguard.detector.dto.ThreatDetail;
import com.promptguard.detector.model.RiskLevel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Computes a composite risk score (0–100) from the list of detected threats
 * and maps it to a {@link RiskLevel}.
 *
 * <p>Scoring logic:
 * <ul>
 *   <li>Each fired threat category contributes its configured weight.</li>
 *   <li>The raw sum is capped at 100.</li>
 *   <li>LOW : 0–33 | MEDIUM : 34–66 | HIGH : 67–100</li>
 * </ul>
 */
@Service
@Slf4j
public class RiskScoringService {

    private static final int HIGH_THRESHOLD   = 67;
    private static final int MEDIUM_THRESHOLD = 34;

    /**
     * Calculate aggregate risk score from a list of threats.
     *
     * @param threats list of threats from the rule engine
     * @return composite score clamped to [0, 100]
     */
    public int calculateScore(List<ThreatDetail> threats) {
        int raw = threats.stream()
                .mapToInt(ThreatDetail::getScoreContribution)
                .sum();
        int clamped = Math.min(raw, 100);
        log.debug("Risk score calculation: raw={} clamped={} from {} threats", raw, clamped, threats.size());
        return clamped;
    }

    /**
     * Map a numeric score to a {@link RiskLevel}.
     *
     * @param score 0–100
     * @return corresponding risk level
     */
    public RiskLevel mapToLevel(int score) {
        if (score >= HIGH_THRESHOLD)   return RiskLevel.HIGH;
        if (score >= MEDIUM_THRESHOLD) return RiskLevel.MEDIUM;
        return RiskLevel.LOW;
    }
}
