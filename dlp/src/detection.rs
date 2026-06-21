use regex::Regex;
use shared_types::DlpPatternKind;

/// A detected sensitive pattern in content.
#[derive(Debug, Clone, PartialEq)]
pub struct PatternMatch {
    pub kind: DlpPatternKind,
    pub matched: String,
}

/// Validate credit card number using Luhn algorithm.
pub fn luhn_valid(number: &str) -> bool {
    let digits: Vec<u32> = number.chars().filter(|c| c.is_ascii_digit()).map(|c| c.to_digit(10).unwrap()).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

/// Scan content for configured DLP patterns.
pub fn detect_patterns(content: &str) -> Vec<PatternMatch> {
    let mut matches = Vec::new();

    let cc_re = Regex::new(r"\b(?:\d[ -]*?){13,19}\b").unwrap();
    for cap in cc_re.find_iter(content) {
        let raw = cap.as_str();
        if luhn_valid(raw) {
            matches.push(PatternMatch {
                kind: DlpPatternKind::CreditCard,
                matched: raw.into(),
            });
        }
    }

    let api_key_re =
        Regex::new(r#"(?i)(api[_-]?key|secret[_-]?key|token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{16,})"#)
            .unwrap();
    for cap in api_key_re.captures_iter(content) {
        if let Some(m) = cap.get(2) {
            matches.push(PatternMatch {
                kind: DlpPatternKind::ApiKey,
                matched: m.as_str().into(),
            });
        }
    }

    let ssn_re = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
    for cap in ssn_re.find_iter(content) {
        matches.push(PatternMatch {
            kind: DlpPatternKind::Ssn,
            matched: cap.as_str().into(),
        });
    }

    let email_re = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap();
    for cap in email_re.find_iter(content) {
        matches.push(PatternMatch {
            kind: DlpPatternKind::Email,
            matched: cap.as_str().into(),
        });
    }

    let phone_re = Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap();
    for cap in phone_re.find_iter(content) {
        matches.push(PatternMatch {
            kind: DlpPatternKind::PhoneNumber,
            matched: cap.as_str().into(),
        });
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_valid_card() {
        assert!(luhn_valid("4111111111111111"));
    }

    #[test]
    fn detects_api_key() {
        let matches = detect_patterns("api_key=abcdefghijklmnop1234");
        assert!(matches.iter().any(|m| m.kind == DlpPatternKind::ApiKey));
    }
}
