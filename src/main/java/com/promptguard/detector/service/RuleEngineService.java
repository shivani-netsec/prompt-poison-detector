package com.promptguard.detector.service;

import com.promptguard.detector.dto.ThreatDetail;
import com.promptguard.detector.model.ThreatCategory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Stateless rule engine that evaluates a prompt against a library of
 * regex-based and keyword-based detection rules for each threat category.
 *
 * <p>Each rule fires when its pattern matches the (lower-cased) prompt text.
 * Multiple matches within the same category do NOT stack – the category
 * contributes its configured weight at most once per analysis.
 */
@Service
@Slf4j
public class RuleEngineService {

    // -----------------------------------------------------------------------
    // Configurable category weights (set in application.properties)
    // -----------------------------------------------------------------------
    @Value("${risk.weight.instruction-override:25}")
    private int weightInstructionOverride;

    @Value("${risk.weight.role-escalation:20}")
    private int weightRoleEscalation;

    @Value("${risk.weight.prompt-injection:25}")
    private int weightPromptInjection;

    @Value("${risk.weight.hidden-trigger:15}")
    private int weightHiddenTrigger;

    @Value("${risk.weight.data-extraction:15}")
    private int weightDataExtraction;

    // -----------------------------------------------------------------------
    // Instruction override patterns
    // -----------------------------------------------------------------------
    private static final List<Pattern> INSTRUCTION_OVERRIDE_PATTERNS = List.of(
        Pattern.compile("ignore (all |your )?(previous|prior|above|earlier) instructions?", Pattern.CASE_INSENSITIVE),
        Pattern.compile("disregard (all |your )?(previous|prior|above) (instructions?|rules?|guidelines?)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("forget (everything|all) (you (were|have been) told|above|previous)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("override (your )?(system|safety|content) (prompt|policy|filter|rules?)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("your (new|real|true|actual) (instructions?|rules?|directives?) (are|is|will be)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("new (prime|primary|top-level) directive", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\[system\\]|\\[INST\\]|<\\|system\\|>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("###\\s*(instruction|system|override)", Pattern.CASE_INSENSITIVE)
    );

    // -----------------------------------------------------------------------
    // Role escalation patterns
    // -----------------------------------------------------------------------
    private static final List<Pattern> ROLE_ESCALATION_PATTERNS = List.of(
        Pattern.compile("act as (an? )?(admin|root|superuser|developer|system|god|unrestricted|jailbroken)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("you are now (an? )?(admin|unrestricted|developer mode|dan|evil|opposite)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("pretend (you are|to be) (an? )?(admin|unrestricted|human|real person|system)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(enable|activate|switch to) (developer|god|jailbreak|unrestricted|admin|privileged) mode", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bDAN\\b|do anything now", Pattern.CASE_INSENSITIVE),
        Pattern.compile("you have no (limits?|restrictions?|boundaries|rules|guidelines)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("simulate (a|an) (unrestricted|unfiltered|evil|opposite) (ai|model|assistant|bot)", Pattern.CASE_INSENSITIVE)
    );

    // -----------------------------------------------------------------------
    // Prompt injection patterns
    // -----------------------------------------------------------------------
    private static final List<Pattern> PROMPT_INJECTION_PATTERNS = List.of(
        Pattern.compile("</?(system|user|assistant|instruction|context|prompt)>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\{\\{.*?\\}\\}", Pattern.CASE_INSENSITIVE),          // template injection
        Pattern.compile("\\$\\{.*?\\}", Pattern.CASE_INSENSITIVE),              // EL injection
        Pattern.compile("<!--.*?-->", Pattern.CASE_INSENSITIVE),                // HTML comment injection
        Pattern.compile("base64[_\\s]*(decode|encode)\\s*\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(execute|run|eval|exec)\\s*\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\\\n\\\\n(ignore|forget|override)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("prompt\\s*:\\s*[\"']", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(inject|append|prepend|concatenate)\\s+(this|the following|text|string)\\s+(to|into)", Pattern.CASE_INSENSITIVE)
    );

    // -----------------------------------------------------------------------
    // Hidden trigger / steganography patterns
    // -----------------------------------------------------------------------
    private static final List<Pattern> HIDDEN_TRIGGER_PATTERNS = List.of(
        Pattern.compile("[\\u200b-\\u200f\\u2028\\u2029\\ufeff]"),              // zero-width / invisible chars
        Pattern.compile("\\\\u00[0-9a-f]{2}", Pattern.CASE_INSENSITIVE),        // unicode escape sequences
        Pattern.compile("<!--\\s*trigger\\s*:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("when (you|the model) (see|read|encounter|detect)s? (this|the trigger|the keyword)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(secret|hidden|covert|stealth) (command|instruction|payload|trigger|keyword)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("[^\\x00-\\x7F]{5,}")                                   // long non-ASCII sequences
    );

    // -----------------------------------------------------------------------
    // Sensitive data extraction patterns
    // -----------------------------------------------------------------------
    private static final List<Pattern> DATA_EXTRACTION_PATTERNS = List.of(
        Pattern.compile("(reveal|show|print|output|return|tell me) (your|the) (system prompt|initial prompt|instructions|context|training data)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("what (are|were) (your|the) (original|initial|system|full) instructions?", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(leak|expose|exfiltrate|steal|dump) (data|user|credentials?|passwords?|tokens?|secrets?|keys?)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(api[_\\s]?key|secret[_\\s]?key|access[_\\s]?token|bearer[_\\s]?token|password|credential)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(database|db)\\s+(schema|table|column|password|host|port)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(internal|private|confidential|proprietary) (data|information|document|file|config)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("send (it|them|the data|the result) to (http|https|ftp|mailto)", Pattern.CASE_INSENSITIVE)
    );

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Evaluate a prompt against all rule sets and return the list of firing threats.
     *
     * @param prompt raw prompt text
     * @return list of {@link ThreatDetail} for every category that matched
     */
    public List<ThreatDetail> evaluate(String prompt) {
        List<ThreatDetail> threats = new ArrayList<>();

        checkCategory(prompt, INSTRUCTION_OVERRIDE_PATTERNS, ThreatCategory.INSTRUCTION_OVERRIDE,
                weightInstructionOverride, threats);
        checkCategory(prompt, ROLE_ESCALATION_PATTERNS, ThreatCategory.ROLE_ESCALATION,
                weightRoleEscalation, threats);
        checkCategory(prompt, PROMPT_INJECTION_PATTERNS, ThreatCategory.PROMPT_INJECTION,
                weightPromptInjection, threats);
        checkCategory(prompt, HIDDEN_TRIGGER_PATTERNS, ThreatCategory.HIDDEN_TRIGGER,
                weightHiddenTrigger, threats);
        checkCategory(prompt, DATA_EXTRACTION_PATTERNS, ThreatCategory.DATA_EXTRACTION,
                weightDataExtraction, threats);

        log.debug("Rule engine found {} threats for prompt (length={})", threats.size(), prompt.length());
        return threats;
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private void checkCategory(String prompt, List<Pattern> patterns,
                                ThreatCategory category, int weight,
                                List<ThreatDetail> threats) {
        for (Pattern pattern : patterns) {
            var matcher = pattern.matcher(prompt);
            if (matcher.find()) {
                String evidence = matcher.group();
                log.debug("Threat fired: {} | pattern: {} | evidence: '{}'",
                        category, pattern.pattern(), evidence);
                threats.add(ThreatDetail.builder()
                        .category(category)
                        .scoreContribution(weight)
                        .evidence(evidence)
                        .build());
                return; // only fire each category once
            }
        }
    }
}
