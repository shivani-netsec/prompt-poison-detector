package com.promptguard.detector.repository;

import com.promptguard.detector.model.PromptAnalysisLog;
import com.promptguard.detector.model.RiskLevel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Spring Data JPA repository for prompt analysis audit logs.
 */
@Repository
public interface PromptAnalysisLogRepository extends JpaRepository<PromptAnalysisLog, Long> {

    List<PromptAnalysisLog> findByRiskLevel(RiskLevel riskLevel);

    List<PromptAnalysisLog> findByAnalyzedAtBetween(LocalDateTime from, LocalDateTime to);

    List<PromptAnalysisLog> findByCallerIdOrderByAnalyzedAtDesc(String callerId);

    @Query("SELECT l FROM PromptAnalysisLog l WHERE l.riskScore >= :minScore ORDER BY l.analyzedAt DESC")
    List<PromptAnalysisLog> findHighRiskLogs(@Param("minScore") int minScore);

    long countByRiskLevel(RiskLevel riskLevel);
}
