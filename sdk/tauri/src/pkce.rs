use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

impl std::fmt::Debug for PkcePair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PkcePair")
            .field("verifier", &"[REDACTED]")
            .field("challenge", &self.challenge)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("操作系统安全随机源不可用: {0}")]
pub struct RandomError(String);

pub fn generate_pkce() -> Result<PkcePair, RandomError> {
    let verifier = secure_random_base64url()?;
    let challenge = challenge_for(&verifier);
    Ok(PkcePair {
        verifier,
        challenge,
    })
}

pub fn challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn generate_state() -> Result<String, RandomError> {
    secure_random_base64url()
}

fn secure_random_base64url() -> Result<String, RandomError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| RandomError(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::{challenge_for, generate_pkce, generate_state};

    #[test]
    fn computes_the_rfc_7636_s256_vector() {
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn verifier_and_state_are_independent_32_byte_base64url_values() {
        let first = generate_pkce().expect("安全随机源应可用");
        let second = generate_pkce().expect("安全随机源应可用");
        let state = generate_state().expect("安全随机源应可用");

        assert_base64url_32_bytes(&first.verifier);
        assert_base64url_32_bytes(&second.verifier);
        assert_base64url_32_bytes(&state);
        assert_ne!(first.verifier, second.verifier);
        assert_ne!(first.verifier, state);
        assert_eq!(first.challenge, challenge_for(&first.verifier));
    }

    #[test]
    fn pkce_debug_output_redacts_the_verifier() {
        let pair = super::PkcePair {
            verifier: "verifier-super-secret".to_owned(),
            challenge: "public-challenge".to_owned(),
        };

        let debug = format!("{pair:?}");

        assert!(!debug.contains("verifier-super-secret"));
        assert!(debug.contains("public-challenge"));
        assert!(debug.contains("[REDACTED]"));
    }

    fn assert_base64url_32_bytes(value: &str) {
        assert_eq!(value.len(), 43);
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        assert!(!value.contains('='));
    }
}
