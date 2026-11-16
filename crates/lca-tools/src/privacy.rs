//! Name-based privacy boundary for workspace paths.
//!
//! The baseline names are always enforced. Extra patterns from configuration can only
//! add denials. Name matching is case-insensitive and happens before a path is opened.
//! A second hard link is refused by the read path; this module does not see file bytes.

use crate::fs_error::FsError;

const MAX_PATTERNS: usize = 32;
const MAX_PATTERN_CHARS: usize = 256;

const PROTECTED_DIRECTORIES: &[&str] = &[".git", ".ssh", ".aws", ".gnupg", ".kube"];

const EXACT_FILES: &[&str] = &[
    ".env",
    ".envrc",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".pgpass",
    ".htpasswd",
    "lca.toml",
    "opencode.json",
    "credentials.json",
    "credentials.yaml",
    "credentials.yml",
    "credentials.toml",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "secrets.toml",
];

const ENV_TEMPLATES: &[&str] = &[".env.example", ".env.sample", ".env.template", ".env.dist"];

const SECRET_EXTENSIONS: &[&str] = &["pem", "key", "p12", "pfx", "jks", "kdbx", "keystore"];

const PRIVATE_KEY_STEMS: &[&str] = &["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"];

/// Additional exclude patterns layered on top of the mandatory baseline.
///
/// The baseline is not stored here and cannot be removed through this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyPolicy {
    extra: Vec<String>,
}

/// Why a configured exclude pattern was rejected.
///
/// A rejected pattern is a configuration error. It is never treated as "match nothing".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivacyPatternError {
    /// The pattern list or one pattern failed a static check.
    #[error("{message}")]
    Invalid {
        /// Static explanation. A long pattern is capped.
        message: String,
    },
}

impl PrivacyPolicy {
    /// Baseline protections and no extra patterns.
    #[must_use]
    pub fn baseline() -> Self {
        Self { extra: Vec::new() }
    }

    /// Validates extra patterns and keeps the baseline.
    ///
    /// An empty list is the baseline. An invalid pattern fails the whole list.
    pub fn try_from_patterns(patterns: &[String]) -> Result<Self, PrivacyPatternError> {
        if patterns.len() > MAX_PATTERNS {
            return Err(PrivacyPatternError::Invalid {
                message: format!("at most {MAX_PATTERNS} privacy exclude patterns are accepted"),
            });
        }
        let mut extra = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            extra.push(validate_pattern(pattern)?);
        }
        Ok(Self { extra })
    }

    /// Configured patterns. The mandatory baseline is not included.
    #[must_use]
    pub fn extra_patterns(&self) -> &[String] {
        &self.extra
    }

    /// Whether a workspace-relative path using `/` is protected.
    ///
    /// `.` is the workspace root and is not itself a protected name. Matching is
    /// case-insensitive. This does not read the filesystem and does not resolve `..`.
    #[must_use]
    pub fn blocks(&self, relative: &str) -> bool {
        if relative.is_empty() || relative == "." {
            return false;
        }
        let parts: Vec<&str> = relative
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .collect();
        if parts.is_empty() {
            return false;
        }
        if parts.iter().any(|part| protected_component(part)) {
            return true;
        }
        let normalized = parts.join("/");
        self.extra
            .iter()
            .any(|pattern| pattern_matches(pattern, &normalized))
    }
}

/// Returns the first denial.
///
/// A later `Ok` does not cancel an earlier error. An empty list is not a denial.
pub fn deny_overrides(decisions: &[Result<(), FsError>]) -> Result<(), FsError> {
    for decision in decisions {
        if let Err(error) = decision {
            return Err(error.clone());
        }
    }
    Ok(())
}

/// Splits a simple relative path into `/` form.
///
/// Returns `None` when the path is absolute, contains `..`, or fails a static check.
/// Those paths are left to the sandbox, which rejects them before a file is opened.
pub(crate) fn lexical_relative(raw: &str) -> Option<String> {
    if raw.is_empty()
        || raw.chars().count() > 4096
        || raw.starts_with('/')
        || raw.starts_with('\\')
        || raw.contains(':')
        || raw.chars().any(|character| character.is_control())
    {
        return None;
    }
    let mut parts = Vec::new();
    for part in raw.split(['/', '\\']) {
        if part.is_empty() || part == ".." || part.ends_with('.') || part.ends_with(' ') {
            return None;
        }
        if part == "." {
            continue;
        }
        parts.push(part);
    }
    if parts.is_empty() {
        Some(".".to_owned())
    } else {
        Some(parts.join("/"))
    }
}

fn protected_component(name: &str) -> bool {
    if ENV_TEMPLATES
        .iter()
        .any(|template| name.eq_ignore_ascii_case(template))
    {
        return false;
    }
    if PROTECTED_DIRECTORIES
        .iter()
        .any(|directory| name.eq_ignore_ascii_case(directory))
    {
        return true;
    }
    if EXACT_FILES
        .iter()
        .any(|file| name.eq_ignore_ascii_case(file))
    {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    if lower.starts_with(".env.") || (lower.ends_with(".env") && lower != ".env") {
        return true;
    }
    if PRIVATE_KEY_STEMS
        .iter()
        .any(|stem| lower == *stem || lower.starts_with(&format!("{stem}.")))
    {
        return true;
    }
    secret_extension(&lower)
}

fn secret_extension(lower_name: &str) -> bool {
    let Some((_, extension)) = lower_name.rsplit_once('.') else {
        return false;
    };
    !extension.is_empty() && SECRET_EXTENSIONS.contains(&extension)
}

fn validate_pattern(pattern: &str) -> Result<String, PrivacyPatternError> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_PATTERN_CHARS {
        return Err(PrivacyPatternError::Invalid {
            message: "a privacy exclude pattern must be from 1 through 256 characters".to_owned(),
        });
    }
    if trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || trimmed.contains('\\')
        || trimmed.contains(':')
        || trimmed
            .chars()
            .any(|character| character.is_control() || matches!(character, '[' | ']' | '{' | '}'))
    {
        return Err(PrivacyPatternError::Invalid {
            message: format!(
                "privacy exclude pattern `{}` is not a relative glob",
                cap(trimmed)
            ),
        });
    }
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.iter().any(|part| part.is_empty() || *part == "..") {
        return Err(PrivacyPatternError::Invalid {
            message: format!(
                "privacy exclude pattern `{}` is not a relative glob",
                cap(trimmed)
            ),
        });
    }
    Ok(trimmed.to_owned())
}

fn pattern_matches(pattern: &str, relative: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('/').filter(|part| !part.is_empty()).collect();
    let path_parts: Vec<&str> = relative
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if !pattern.contains('/') {
        return path_parts
            .last()
            .is_some_and(|name| component_glob(pattern, name));
    }
    match_parts(&pattern_parts, &path_parts)
}

fn match_parts(pattern: &[&str], path: &[&str]) -> bool {
    let rows = pattern.len();
    let cols = path.len();
    let mut table = vec![vec![false; cols + 1]; rows + 1];
    table[rows][cols] = true;
    for row in (0..rows).rev() {
        for col in (0..=cols).rev() {
            if pattern[row] == "**" {
                let mut matched = table[row + 1][col];
                if col < cols {
                    matched = matched || table[row][col + 1];
                }
                table[row][col] = matched;
            } else if col < cols && component_glob(pattern[row], path[col]) {
                table[row][col] = table[row + 1][col + 1];
            }
        }
    }
    table[0][0]
}

fn component_glob(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern
        .chars()
        .flat_map(|character| character.to_lowercase())
        .collect();
    let name: Vec<char> = name
        .chars()
        .flat_map(|character| character.to_lowercase())
        .collect();
    let rows = pattern.len();
    let cols = name.len();
    let mut table = vec![vec![false; cols + 1]; rows + 1];
    table[rows][cols] = true;
    for row in (0..rows).rev() {
        for col in (0..=cols).rev() {
            if pattern[row] == '*' {
                let mut matched = table[row + 1][col];
                if col < cols {
                    matched = matched || table[row][col + 1];
                }
                table[row][col] = matched;
            } else if col < cols && (pattern[row] == '?' || pattern[row] == name[col]) {
                table[row][col] = table[row + 1][col + 1];
            }
        }
    }
    table[0][0]
}

fn cap(value: &str) -> String {
    let mut short: String = value.chars().take(80).collect();
    if value.chars().count() > 80 {
        short.push_str("...");
    }
    short
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_blocks_secret_names_and_allows_templates_and_source() {
        let policy = PrivacyPolicy::baseline();
        for blocked in [
            "lca.toml",
            "nested/LCA.TOML",
            "opencode.json",
            ".env",
            ".ENV.local",
            "config.env",
            "id_rsa",
            "ssh/id_ed25519.old",
            "certs/server.PEM",
            "credentials.json",
            "secrets.toml",
            ".git/config",
            ".ssh/id_rsa",
            "src/.aws/credentials",
        ] {
            assert!(policy.blocks(blocked), "{blocked}");
        }
        for allowed in [
            ".env.example",
            "templates/.env.sample",
            ".env.template",
            ".env.dist",
            "src/lib.rs",
            "keyboard.rs",
            "monkey.txt",
            "Cargo.toml",
            "notes.txt",
            "secret_plan.rs",
        ] {
            assert!(!policy.blocks(allowed), "{allowed}");
        }
    }

    #[test]
    fn extra_patterns_add_denials_and_invalid_patterns_fail_closed() {
        let policy = PrivacyPolicy::try_from_patterns(&[
            "  kept/*.secret  ".to_owned(),
            "private/**".to_owned(),
        ])
        .expect("patterns");
        assert!(policy.blocks("kept/local.secret"));
        assert!(policy.blocks("private/notes.md"));
        assert!(policy.blocks("private"));
        assert!(!policy.blocks("kept/lib.rs"));
        assert!(policy.blocks("lca.toml"));

        for pattern in ["../secrets", "/etc/passwd", "a\\b", "file[1].txt", ""] {
            assert!(
                PrivacyPolicy::try_from_patterns(&[pattern.to_owned()]).is_err(),
                "{pattern}"
            );
        }
        assert!(PrivacyPolicy::try_from_patterns(&["*".repeat(300)]).is_err());
    }

    #[test]
    fn a_later_allow_does_not_cancel_a_privacy_denial() {
        let decisions = [
            Ok(()),
            Ok(()),
            Ok(()),
            Ok(()),
            Err(FsError::PrivacyDenied),
            Ok(()),
            Ok(()),
        ];
        let error = deny_overrides(&decisions).expect_err("denied");
        assert_eq!(error.kind(), "privacy_denied");

        let earlier = [
            Err(FsError::OutsideWorkspace {
                path: "x".to_owned(),
            }),
            Ok(()),
        ];
        assert_eq!(
            deny_overrides(&earlier).expect_err("sandbox").kind(),
            "outside_workspace"
        );
        assert!(deny_overrides(&[Ok(())]).is_ok());
    }
}
