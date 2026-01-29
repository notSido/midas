//! Pattern matching utilities (similar to Magicmida's FindDynamic/FindStatic)

/// Simple pattern matcher for byte sequences
pub struct PatternMatcher;

impl PatternMatcher {
    /// Find a pattern in data
    /// Pattern format: "48 8B ?? 89" where ?? is wildcard
    pub fn find(data: &[u8], pattern: &str) -> Option<usize> {
        let pattern_bytes = Self::parse_pattern(pattern);
        
        if pattern_bytes.is_empty() {
            return None;
        }
        
        for i in 0..=data.len().saturating_sub(pattern_bytes.len()) {
            if Self::matches_at(&data[i..], &pattern_bytes) {
                return Some(i);
            }
        }
        
        None
    }
    
    /// Parse pattern string into bytes (Some(byte) or None for wildcard)
    fn parse_pattern(pattern: &str) -> Vec<Option<u8>> {
        pattern
            .split_whitespace()
            .filter_map(|s| {
                if s == "??" {
                    Some(None)
                } else {
                    u8::from_str_radix(s, 16).ok().map(Some)
                }
            })
            .collect()
    }
    
    /// Check if pattern matches at position
    fn matches_at(data: &[u8], pattern: &[Option<u8>]) -> bool {
        if data.len() < pattern.len() {
            return false;
        }
        
        for (i, pat_byte) in pattern.iter().enumerate() {
            if let Some(expected) = pat_byte {
                if data[i] != *expected {
                    return false;
                }
            }
            // None means wildcard, always matches
        }
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pattern_exact_match() {
        let data = vec![0x48, 0x8B, 0x45, 0x89, 0x90];
        let pattern = "48 8B 45 89";
        assert_eq!(PatternMatcher::find(&data, pattern), Some(0));
    }
    
    #[test]
    fn test_pattern_with_wildcard() {
        let data = vec![0x48, 0x8B, 0x45, 0x89, 0x90];
        let pattern = "48 ?? 45";
        assert_eq!(PatternMatcher::find(&data, pattern), Some(0));
    }
    
    #[test]
    fn test_pattern_not_found() {
        let data = vec![0x48, 0x8B, 0x45, 0x89, 0x90];
        let pattern = "FF FF";
        assert_eq!(PatternMatcher::find(&data, pattern), None);
    }
}
