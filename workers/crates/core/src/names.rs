//! Names (§3.6) and other fixed-form tokens.

/// `^[a-z0-9][a-z0-9_-]{0,63}$`
pub fn is_namespace_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && matches!(b[0], b'a'..=b'z' | b'0'..=b'9')
        && b[1..]
            .iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

/// `^[a-z0-9][a-z0-9._-]{0,127}$`
pub fn is_resource_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && matches!(b[0], b'a'..=b'z' | b'0'..=b'9')
        && b[1..]
            .iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

/// `^[a-z2-7]{26}$`: gesture ids (§7.2), fresh `$nonce`s (§C.7), blob nonces (§3.7).
pub fn is_base32_26(s: &str) -> bool {
    s.len() == 26 && s.bytes().all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(is_namespace_name("a"));
        assert!(is_namespace_name("cms-prod_1"));
        assert!(is_namespace_name(&"a".repeat(64)));
        assert!(!is_namespace_name(&"a".repeat(65)));
        assert!(!is_namespace_name("-a"));
        assert!(!is_namespace_name("a.b"));
        assert!(!is_namespace_name("A"));
        assert!(is_resource_name("photo-12.v2"));
        assert!(is_resource_name(&"a".repeat(128)));
        assert!(!is_resource_name(&"a".repeat(129)));
        assert!(!is_resource_name(".a"));
        assert!(!is_resource_name(""));
        assert!(is_base32_26("abcdefghijklmnopqrstuvwxyz"));
        assert!(!is_base32_26("abcdefghijklmnopqrstuvwxy1"));
    }
}
