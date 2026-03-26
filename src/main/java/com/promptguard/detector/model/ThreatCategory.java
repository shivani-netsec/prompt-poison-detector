package com.promptguard.detector.model;

/**
 * Enumeration of known prompt-poisoning threat categories.
 */
public enum ThreatCategory {
    INSTRUCTION_OVERRIDE("Instruction Override Attempt"),
    ROLE_ESCALATION("Role / Privilege Escalation"),
    PROMPT_INJECTION("Prompt Injection Pattern"),
    HIDDEN_TRIGGER("Hidden Trigger Detected"),
    DATA_EXTRACTION("Sensitive Data Extraction Intent");

    private final String displayName;

    ThreatCategory(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
