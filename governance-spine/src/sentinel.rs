use crate::{
    crypto::CryptoEngine,
    governance_signal::{Direction, GovernanceSignal, Severity, SignalBuilder, SignalSource},
};
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;

static INJECTION_PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        // Original v3.5 rules
        ("SENT-001", Regex::new(r"(?i)\b(ignore previous instructions|disregard your training|forget your guidelines)\b").unwrap()),
        ("SENT-002", Regex::new(r"(?i)\b(you are now|act as if you are|pretend you are|you have no restrictions)\b").unwrap()),
        ("SENT-003", Regex::new(r"(?i)\b(DAN|do anything now|jailbreak|bypass your)\b").unwrap()),
        ("SENT-004", Regex::new(r"(?ix)\b(?:reveal|show|print|dump|display|leak|extract)\b.{0,40}\b(?:system\s+prompt|developer\s+message|hidden\s+instructions|internal\s+rules)\b").unwrap()),
        ("SENT-004B", Regex::new(r"(?ix)\bwhat\s+are\s+your\s+(?:system|developer|hidden)\s+(?:instructions|prompt|rules)\b").unwrap()),
        ("SENT-004C", Regex::new(r"(?i)\breveal\b.{0,30}\b(instructions|rules|config|constitution)\b").unwrap()),
        ("SENT-004D", Regex::new(r"(?i)\b(output|dump|show|reveal|print)\b.{0,40}\b(configuration|config|internal\s+rules|api\s+keys?|tokens?|access\s+keys?)\b").unwrap()),
        ("SENT-004E", Regex::new(r"(?i)\b(repeat|dump|output|show)\b.{0,40}\b(context\s+window|conversation|everything\s+from|full\s+history)\b").unwrap()),
        ("SENT-004F", Regex::new(r"(?i)\bwhat\s+(api\s+keys?|tokens?|credentials|secrets?)\b.{0,30}\b(do\s+you|have|access)\b").unwrap()),
        ("SENT-005", Regex::new(r"(?i)\b(malware|ransomware|trojan|rootkit|keylogger)\b").unwrap()),
        ("SENT-006", Regex::new(r"(?i)\b(ddos|botnet|exploit\s+kit|zero.?day|0day|vulnerability)\b").unwrap()),
        ("SENT-007", Regex::new(r"(?i)\b(phishing|credential\s+harvest|spear.?phish)\b").unwrap()),
        ("SENT-008", Regex::new(r"(?ix)\b(?:run|execute|exec(?:ute)?|eval|system|powershell|bash|sh|cmd|terminal)\b.{0,40}\b(?:code|command|script|shell|curl|wget|pip|npm|apt(?:-get)?|chmod|chown|rm\s+-rf)\b").unwrap()),
        ("SENT-008B", Regex::new(r#"(?ix)\b(?:exec|eval|system)\s*\(\s*[\x27\x22]"#).unwrap()),
        ("SENT-008C", Regex::new(r"(?ix)\b(?:os\.system|subprocess\.(?:run|popen)|Runtime\.exec)\b").unwrap()),
        ("SENT-008D", Regex::new(r"(?i)\bcall\s+tool\s*[:=]\s*\w+").unwrap()),
        ("SENT-008E", Regex::new(r"(?i)\bExecute\s*:\s*.{0,60}\b(passwd|shadow|hosts|bashrc|ssh|wget|curl|cat\s+/)\b").unwrap()),
        ("SENT-008F", Regex::new(r"(?i)\bcat\s+/\w+").unwrap()),
        ("SENT-009", Regex::new(r"(?ix)\b(?:override|bypass|disable|ignore|disregard|break|remove)\b.{0,40}\b(?:safety|guardrails|policy|rules|filters|constraints)\b").unwrap()),
        ("SENT-009B", Regex::new(r"(?ix)\b(?:as\s+(?:your|the)\s+)?(?:creator|developer|admin|root|system)\b.{0,30}\b(?:i\s+(?:order|command)|you\s+must|override)\b").unwrap()),
        ("SENT-009C", Regex::new(r"(?ix)\byou\s+are\s+(?:now\s+)?(?:root|admin|developer|system|creator)\b").unwrap()),
        ("SENT-009D", Regex::new(r"(?ix)\brespond\b.{0,20}\bwithout\b.{0,20}\b(?:restrictions?|filters?|guardrails?|rules?)\b").unwrap()),
        ("SENT-001B", Regex::new(r"(?i)\b(please\s+ignore|kindly\s+ignore|disregard\s+all\s+prior|ignore\s+all\s+prior)\b").unwrap()),
        ("SENT-001C", Regex::new(r"(?i)i[\s._-]*g[\s._-]*n[\s._-]*o[\s._-]*r[\s._-]*e[\s._-]+p[\s._-]*r[\s._-]*e[\s._-]*v[\s._-]*i[\s._-]*o[\s._-]*u[\s._-]*s").unwrap()),
        ("SENT-001D", Regex::new(r"(?i)(ignore_previous|IgnorePrevious|IGNOREPREVIOUS)").unwrap()),
        ("SENT-001E", Regex::new(r"(?i)ignore_all_previous|ignore_previous_instructions|reveal_system_prompt").unwrap()),
        ("SENT-001F", Regex::new(r"(?i)\b(pretty\s+please|sugar\s+on\s+top|with\s+respect|kindly\s+bypass)\b.{0,60}\b(ignore|bypass|disable|override)\b").unwrap()),
        ("SENT-001G", Regex::new(r"(?ix)\bignore\b.{0,8}\b(?:all\s+)?(?:prior|previous)\b.{0,8}\binstructions?\b").unwrap()),
        ("SENT-002B", Regex::new(r"(?i)\b(i\s+am\s+your\s+(administrator|admin|operator|owner))\b.{0,40}\b(switch|enable|activate|unrestricted|admin\s+mode)\b").unwrap()),
        ("SENT-002C", Regex::new(r"(?i)^\s*SYSTEM\s*:\s*(you\s+are|ignore|disable|override)").unwrap()),
        ("SENT-003B", Regex::new(r"(?i)\b(developer\s+mode|dev\s+mode|bypass\s+all|no\s+restrictions|without\s+restrictions|remove\s+all\s+restrictions)\b").unwrap()),
        ("SENT-003C", Regex::new(r"(?i)\bsimulate\b.{0,30}\b(no\s+filters|no\s+restrictions|without\s+guidelines)\b").unwrap()),
        ("SENT-003D", Regex::new(r"(?i)\b(rules?\s+are\s+inverted|as\s+if.{0,20}rules?\s+inverted|invert.{0,20}rules?)\b").unwrap()),
        ("SENT-003E", Regex::new(r"(?i)\b(in\s+a\s+stor[yi]|in\s+a\s+fictional|in\s+a\s+hypothetical|in\s+a\s+world\s+where)\b.{0,60}\b(no\s+rules?|no\s+restrictions?|no\s+guidelines?|bypass|unrestricted)\b").unwrap()),
        ("SENT-003F", Regex::new(r"(?i)\b(let.s\s+play\s+a\s+game|play\s+a\s+game\s+where)\b.{0,60}\b(no\s+guidelines?|no\s+rules?|pretend|unrestricted)\b").unwrap()),
        ("SENT-003G", Regex::new(r"(?ix)\b(?:unconstrained|unrestricted|without\s+(?:limits|constraints)|no\s+(?:constraints|rules|restrictions))\b").unwrap()),
        
        // NEW v3.6 rules - Closes 12 gaps
        ("SENT-010A", Regex::new(r"(?i)\bwhat\s+(is|are)\s+your\s+(system\s+)?(prompt|instruction|guideline|rule)s?\b").unwrap()),
        ("SENT-010B", Regex::new(r"(?i)\b(dump|print|show|reveal|display)\s+(all\s+)?(internal\s+)?(instruction|secret|guideline|rule|prompt|config)s?\b").unwrap()),
        ("SENT-011A", Regex::new(r"(?ix)\bhypothetically\b.{0,40}\b(no|without|ignore|bypass).{0,30}\b(safety|guideline|rule|restriction|governance)\b").unwrap()),
        ("SENT-011B", Regex::new(r"(?ix)\b(fictional|story|roleplay|imagine|pretend)\b.{0,60}\b(ignore|bypass|override|disregard).{0,40}\b(governance|rule|safety|guideline)\b").unwrap()),
        ("SENT-011C", Regex::new(r"(?ix)\b(if|what.*if)\s+you\s+(had\s+no|were\s+without|didn.t\s+have|lacked).{0,40}\b(rule|safety|guideline|restriction)\b").unwrap()),
        ("SENT-012A", Regex::new(r"(?ix)\b(call|invoke|use|run)\b.{0,30}\b(shell|bash|cmd|terminal|tool)\b.{0,60}\b(rm\s+-rf|del\s+/|chmod|mkfs|dd|shutdown)\b").unwrap()),
        ("SENT-012B", Regex::new(r"(?ix)\b(code\s+execution|execute\s+code|execution\s+capability|capability).{0,60}\b(exfiltrat|environment|credential|secret|token|api\s+key)\b").unwrap()),
        ("SENT-012C", Regex::new(r"(?ix)\b(environment\s+variables?|process\.env|os\.environ|getenv).{0,40}\b(dump|show|print|reveal|send|exfil)\b").unwrap()),
        ("SENT-013A", Regex::new(r"(?ix)\bjust\s+this\s+once\b.{0,60}\b(exception|rule|guideline|override|ignore|bypass)\b").unwrap()),
        ("SENT-013B", Regex::new(r"(?ix)\bmake\s+an\s+exception\b.{0,40}\b(to\s+your\s+)?(rule|guideline|policy)\b").unwrap()),
        ("SENT-015A", Regex::new(r"(?ix)\bwhat\s+(model|version).{0,30}\b(you|are|based\s+on|running|powered|built)\b").unwrap()),
        ("SENT-015B", Regex::new(r"(?ix)\bwhat\s+(version|release).{0,40}\b(governance|spine|sentinel|corridor|overwatch|system)\b").unwrap()),
        ("SENT-015C", Regex::new(r"(?i)\bwhat\s+(architecture|framework|stack|pipeline)\b").unwrap()),
        // CMD_STYLE_INJECTION rules — SENT-CMD-001 through SENT-CMD-010
        ("SENT-CMD-001", Regex::new(r"(?i)\bdump\b.{0,10}\b(config|env|key|secret|token|credential)\b").unwrap()),
        ("SENT-CMD-002", Regex::new(r"(?i)/api/(admin|internal|secret|debug|config|raw|v\d+)").unwrap()),
        ("SENT-CMD-003", Regex::new(r"(?ix)\b(show|reveal|print|echo|expose|list)\b.{0,20}\b(key|token|secret|route|config)\b").unwrap()),
        ("SENT-CMD-004", Regex::new(r"(?ix)\b(role|grant|escalate)\b.{0,15}\b(admin|root|operator|superuser)\b").unwrap()),
        ("SENT-CMD-005", Regex::new(r"(?ix)\b(tool|function|call|invoke|execute|run)\b.{0,20}\b(shell|bash|system|exec|eval)\b").unwrap()),
        ("SENT-CMD-006", Regex::new(r"(?ix)\b(bypass|skip|ignore)\b.{0,20}\b(auth|governance|gate|haap|sentinel)\b").unwrap()),
        ("SENT-CMD-007", Regex::new(r"(?ix)\b(list|dump|show)\s+(all\s+)?(endpoint|route|api\s*route|handler)s?\b").unwrap()),
        ("SENT-CMD-008", Regex::new(r"(?ix)\b(promote|elevate|sudo|su)\b.{0,20}\b(privilege|access|level|role)\b").unwrap()),
        ("SENT-CMD-009", Regex::new(r"(?ix)\b(enumerate|iterate|list)\b.{0,30}\b(function|method|endpoint|tool|command|capability)s?\b").unwrap()),
        ("SENT-CMD-010", Regex::new(r"(?i)\bexecute\s+(as|with)\s+(admin|root|operator|system)\b").unwrap()),
    ]
});

static BLOCKLIST_PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        ("SENT-BL-001", Regex::new(r"(?i)\bsudo\b").unwrap()),
        ("SENT-BL-002", Regex::new(r"(?i)\bpassword\s*[:=]\s*\S+").unwrap()),
        ("SENT-BL-003", Regex::new(r"(?i)\bapi[_\s]?key\s*[:=]\s*\S+").unwrap()),
    ]
});

static ENCODING_PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        ("SENT-ENC-001", Regex::new(r"(?:0x[0-9a-fA-F]{2}\s*){8,}").unwrap()),
        ("SENT-ENC-002", Regex::new(r"(?:%[0-9a-fA-F]{2}){6,}").unwrap()),
    ]
});

pub struct Sentinel {
    crypto: Arc<CryptoEngine>,
    max_payload_bytes: usize,
}

impl Sentinel {
    pub fn new(crypto: Arc<CryptoEngine>) -> Self {
        let _ = &*INJECTION_PATTERNS;
        let _ = &*BLOCKLIST_PATTERNS;
        let _ = &*ENCODING_PATTERNS;
        Self { crypto, max_payload_bytes: 32_768 }
    }

    pub fn inspect(&self, payload: &str, direction: Direction, session_id: &str) -> GovernanceSignal {
        let payload_hash = CryptoEngine::compute_hash(payload);

        if payload.len() > self.max_payload_bytes {
            return self.build(direction, session_id, "SIZE_EXCEEDED", "SENT-SIZE-001",
                Severity::Low, 0.70, &payload_hash, "sentinel/size_limit");
        }

        // Unicode normalization for V03
        let normalized_unicode = self.normalize_unicode(payload);
        
        if self.detect_zero_width(&normalized_unicode) {
            return self.build(direction, session_id, "ZERO_WIDTH_CHARS", "SENT-ZW-001",
                Severity::High, 0.90, &payload_hash, "sentinel/encoding_anomaly");
        }

        if self.detect_homoglyphs(&normalized_unicode) {
            return self.build(direction, session_id, "HOMOGLYPH_OBFUSCATION", "SENT-HG-001",
                Severity::High, 0.85, &payload_hash, "sentinel/encoding_anomaly");
        }

        // L33tspeak normalization + rescan
        let normalized = self.normalize_l33t(&normalized_unicode);
        if normalized != normalized_unicode.to_lowercase() && self.leet_evidence_score(&normalized_unicode) >= 2 {
            for (rule_id, pattern) in INJECTION_PATTERNS.iter() {
                if pattern.is_match(&normalized) {
                    return self.build(direction, session_id, "L33T_OBFUSCATION", rule_id,
                        Severity::High, 0.88, &payload_hash, "sentinel/encoding_anomaly");
                }
            }
        }

        // Base64 decode + rescan
        if let Some(decoded) = self.try_decode_base64(payload) {
            for (rule_id, pattern) in INJECTION_PATTERNS.iter() {
                if pattern.is_match(&decoded) {
                    return self.build(direction, session_id, "BASE64_INJECTION", rule_id,
                        Severity::High, 0.92, &payload_hash, "sentinel/encoding_anomaly");
                }
            }
        }

        for (rule_id, pattern) in BLOCKLIST_PATTERNS.iter() {
            if pattern.is_match(payload) {
                return self.build(direction, session_id, "BLOCKLIST_MATCH", rule_id,
                    Severity::High, 0.90, &payload_hash, "sentinel/blocklist");
            }
        }

        for (rule_id, pattern) in INJECTION_PATTERNS.iter() {
            if pattern.is_match(payload) || pattern.is_match(&normalized_unicode) {
                let class = match *rule_id {
                    "SENT-008" | "SENT-008B" | "SENT-008C" | "SENT-012A" | "SENT-012B" | "SENT-012C" => "TOOL_MISUSE",
                    "SENT-009" | "SENT-009B" | "SENT-009C" => "AUTHORITY_SPOOFING",
                    "SENT-004" | "SENT-004B" | "SENT-010A" | "SENT-010B" => "MODEL_EXTRACTION",
                    "SENT-015A" | "SENT-015B" | "SENT-015C" => "RECONNAISSANCE",
                    "SENT-011A" | "SENT-011B" | "SENT-011C" => "HYPOTHETICAL_JAILBREAK",
                    "SENT-013A" | "SENT-013B" => "EXCEPTION_PERSUASION",
                    "SENT-CMD-001" | "SENT-CMD-002" | "SENT-CMD-003"
                    | "SENT-CMD-006" | "SENT-CMD-007" | "SENT-CMD-010" => "CMD_INJECTION",
                    "SENT-CMD-004" | "SENT-CMD-008" => "AUTHORITY_SPOOFING",
                    "SENT-CMD-005" => "TOOL_MISUSE",
                    "SENT-CMD-009" => "MODEL_EXTRACTION",
                    _ => "INJECTION_ATTEMPT",
                };
                return self.build(direction, session_id, class, rule_id,
                    Severity::High, 0.88, &payload_hash, "sentinel/injection_detection");
            }
        }

        for (rule_id, pattern) in ENCODING_PATTERNS.iter() {
            if pattern.is_match(payload) {
                return self.build(direction, session_id, "ENCODING_ANOMALY", rule_id,
                    Severity::Medium, 0.75, &payload_hash, "sentinel/encoding_anomaly");
            }
        }

        self.clean(direction, session_id, &payload_hash)
    }

    fn normalize_unicode(&self, input: &str) -> String {
        // Strip interpunct/middle dot characters: middle dot, bullet, bullet
        // operator, dot operator, hyphenation point, halfwidth katakana middle dot.
        let mut result = input.replace(
            ['\u{00B7}', '\u{2022}', '\u{2219}', '\u{22C5}', '\u{2027}', '\u{FF65}'],
            "",
        );

        // Strip zero-width characters (already in detect_zero_width, but also here)
        result = result.replace(
            ['\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}', '\u{00AD}'],
            "",
        );
        
        result
    }

    fn detect_zero_width(&self, payload: &str) -> bool {
        const ZW: [char; 6] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}', '\u{00AD}'];
        payload.chars().any(|c| ZW.contains(&c))
    }

    fn detect_homoglyphs(&self, payload: &str) -> bool {
        let has_ascii = payload.chars().any(|c| c.is_ascii_alphabetic());
        let has_cyrillic = payload.chars().any(|c| matches!(c as u32, 0x0400..=0x04FF));
        let has_greek = payload.chars().any(|c| matches!(c as u32, 0x0370..=0x03FF));
        (has_greek || has_cyrillic) && has_ascii
    }

    fn normalize_l33t(&self, input: &str) -> String {
        input.to_lowercase()
            .replace('1', "i").replace('3', "e").replace('4', "a")
            .replace('5', "s").replace('0', "o").replace('7', "t")
            .replace('$', "s").replace('@', "a")
    }

    fn leet_evidence_score(&self, input: &str) -> u32 {
        const LEET_CHARS: [char; 8] = ['1', '3', '4', '5', '0', '7', '$', '@'];
        let mut suspect_tokens: u32 = 0;
        for token in input.split_whitespace() {
            if token.len() < 6 { continue; }
            let leet_count = token.chars().filter(|c| LEET_CHARS.contains(c)).count();
            if leet_count == 0 { continue; }
            let ratio = leet_count as f32 / token.len() as f32;
            if ratio >= 0.20 || leet_count >= 2 { suspect_tokens += 1; }
        }
        suspect_tokens
    }

    fn try_decode_base64(&self, input: &str) -> Option<String> {
        let trimmed = input.trim();
        if trimmed.len() < 20 { return None; }
        let looks_b64 = trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
        if !looks_b64 { return None; }
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD.decode(trimmed).ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }

    // Each arg is an independent, meaningful piece of the signal (direction,
    // session, violation class+rule, severity+confidence, payload hash,
    // constitutional ref) — already delegates to SignalBuilder below, which
    // exists specifically to bundle these; this wrapper is called as a
    // one-liner at 8 sites in this file, so pushing the builder up to each
    // call site would make every one of them more verbose, not less.
    #[allow(clippy::too_many_arguments)]
    fn build(&self, direction: Direction, session_id: &str, violation: &str, rule_id: &str,
             severity: Severity, confidence: f32, payload_hash: &str, const_ref: &str) -> GovernanceSignal {
        let mut sig = SignalBuilder::new(SignalSource::Sentinel, direction, session_id)
            .violation(violation, rule_id).severity(severity, confidence)
            .payload_hash(payload_hash).constitutional_ref(const_ref).build();
        self.attach_crypto(&mut sig);
        sig
    }

    fn clean(&self, direction: Direction, session_id: &str, payload_hash: &str) -> GovernanceSignal {
        let mut sig = SignalBuilder::new(SignalSource::Sentinel, direction, session_id)
            .payload_hash(payload_hash).build();
        self.attach_crypto(&mut sig);
        sig
    }

    fn attach_crypto(&self, signal: &mut GovernanceSignal) {
        let canonical = signal.canonical();
        signal.previous_hash = Some(self.crypto.get_latest_hash());
        signal.current_hash = Some(self.crypto.extend_chain(&canonical));
        signal.signature = Some(self.crypto.sign(canonical.as_bytes()));
    }
}
