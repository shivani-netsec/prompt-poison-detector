package com.promptguard.detector.dto;

import com.promptguard.detector.model.ThreatCategory;
import lombok.*;

/**
 * Internal transfer object representing a single detected threat and its weighted score contribution.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatDetail {
    private ThreatCategory category;
    private int scoreContribution;
    private String evidence;   // snippet or reason why the rule fired
}
