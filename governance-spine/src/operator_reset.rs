//! Sentinel operator reset authority.
//!
//! `SENTINEL_OPERATOR_RESET_TOKEN` authorizes a destructive action (clearing
//! a session's security state) and is a distinct credential from
//! `SENTINEL_SERVICE_TOKEN`, which only authenticates the HTTP caller.
//! Neither substitutes for the other.
//!
//! The token is read from the environment exactly once, at process startup,
//! validated here, and then injected into `GovernancePipeline`/`Arbiter` as an
//! immutable `OperatorResetAuthority`. Nothing downstream re-reads the
//! environment on a per-request basis.

use subtle::ConstantTimeEq;

/// Minimum accepted length for `SENTINEL_OPERATOR_RESET_TOKEN`.
pub const MIN_OPERATOR_RESET_TOKEN_LENGTH: usize = 43;

const PLACEHOLDER_MARKERS: &[&str] = &[
    "PLACEHOLDER",
    "CHANGE_ME",
    "CHANGEME",
    "GENERATE_A_STRONG_RANDOM_TOKEN_HERE",
];

fn looks_like_placeholder(upper: &str) -> bool {
    PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| upper.contains(marker))
        || (upper.contains("YOUR_") && upper.contains("_HERE"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorResetConfigError {
    Missing,
    Empty,
    TooShort,
    Placeholder,
}

impl std::fmt::Display for OperatorResetConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "SENTINEL_OPERATOR_RESET_TOKEN is not set"),
            Self::Empty => write!(f, "SENTINEL_OPERATOR_RESET_TOKEN is empty or whitespace"),
            Self::TooShort => write!(
                f,
                "SENTINEL_OPERATOR_RESET_TOKEN must be at least {} characters",
                MIN_OPERATOR_RESET_TOKEN_LENGTH
            ),
            Self::Placeholder => write!(
                f,
                "SENTINEL_OPERATOR_RESET_TOKEN looks like an unfilled placeholder"
            ),
        }
    }
}

/// Validated, immutable operator-reset authority.
///
/// Constructed once from configuration (see [`Self::from_config`]) and then
/// injected into the pipeline. Verification is constant-time and never logs,
/// hashes, persists, or returns the submitted credential.
pub struct OperatorResetAuthority {
    token: String,
}

impl std::fmt::Debug for OperatorResetAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorResetAuthority")
            .field("token", &"<redacted>")
            .finish()
    }
}

impl OperatorResetAuthority {
    pub fn from_config(raw: Option<String>) -> Result<Self, OperatorResetConfigError> {
        let raw = raw.ok_or(OperatorResetConfigError::Missing)?;
        let trimmed = raw.trim();

        if trimmed.is_empty() {
            return Err(OperatorResetConfigError::Empty);
        }
        if trimmed.len() < MIN_OPERATOR_RESET_TOKEN_LENGTH {
            return Err(OperatorResetConfigError::TooShort);
        }
        if looks_like_placeholder(&trimmed.to_uppercase()) {
            return Err(OperatorResetConfigError::Placeholder);
        }

        Ok(Self {
            token: trimmed.to_string(),
        })
    }

    /// Constant-time comparison of a submitted reset credential against the
    /// configured authority.
    pub fn verify(&self, submitted: &str) -> bool {
        let expected = self.token.as_bytes();
        let provided = submitted.as_bytes();
        // Length is not secret-derived (it's a public config constraint), so
        // branching on it before the constant-time compare doesn't leak
        // anything about the configured token's content.
        if expected.len() != provided.len() {
            return false;
        }
        expected.ct_eq(provided).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strong_token() -> String {
        "Zx8qP2mN7vR4tK9wL3yH6jF1sD5gB0cE-strong-op-token".to_string()
    }

    #[test]
    fn operator_reset_rejects_empty_token() {
        let err = OperatorResetAuthority::from_config(Some(String::new()))
            .expect_err("empty token must be rejected");
        assert_eq!(err, OperatorResetConfigError::Empty);
    }

    #[test]
    fn operator_reset_rejects_whitespace_token() {
        let err = OperatorResetAuthority::from_config(Some("   \t\n  ".to_string()))
            .expect_err("whitespace-only token must be rejected");
        assert_eq!(err, OperatorResetConfigError::Empty);
    }

    #[test]
    fn operator_reset_rejects_short_token() {
        let short = "a".repeat(MIN_OPERATOR_RESET_TOKEN_LENGTH - 1);
        let err = OperatorResetAuthority::from_config(Some(short))
            .expect_err("token below minimum length must be rejected");
        assert_eq!(err, OperatorResetConfigError::TooShort);
    }

    #[test]
    fn operator_reset_rejects_placeholder_token() {
        let placeholders = [
            "PLACEHOLDER",
            "OPERATOR_TOKEN_PLACEHOLDER",
            "CHANGE_ME",
            "CHANGEME",
            "GENERATE_A_STRONG_RANDOM_TOKEN_HERE",
            "YOUR_OPERATOR_RESET_TOKEN_HERE",
        ];
        for placeholder in placeholders {
            // Pad so length alone never explains rejection — placeholder
            // detection must fire independently of the length check.
            let padded = format!("{}{}", placeholder, "-".repeat(60));
            let err = OperatorResetAuthority::from_config(Some(padded))
                .expect_err(&format!("placeholder '{}' must be rejected", placeholder));
            assert_eq!(
                err,
                OperatorResetConfigError::Placeholder,
                "for {}",
                placeholder
            );
        }
    }

    #[test]
    fn operator_reset_config_accepts_valid_strong_token() {
        let authority = OperatorResetAuthority::from_config(Some(strong_token()))
            .expect("strong non-placeholder token must be accepted");
        assert!(authority.verify(&strong_token()));
    }

    #[test]
    fn operator_reset_missing_config_rejected() {
        let err =
            OperatorResetAuthority::from_config(None).expect_err("missing token must be rejected");
        assert_eq!(err, OperatorResetConfigError::Missing);
    }
}
