use serde::Deserialize;

/// Body of `GET /api/version`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VersionResponse {
    /// Ollama server version.
    pub version: String,
}

/// Body of `GET /api/tags`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TagsResponse {
    /// Models advertised by the local server.
    pub models: Vec<RemoteModel>,
}

/// One model entry from `/api/tags`. Unknown fields are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RemoteModel {
    /// Name advertised by Ollama, often `name:tag`.
    pub name: String,
    /// Content digest, when the server sent one.
    #[serde(default)]
    pub digest: Option<String>,
}

/// Version and digest recorded for a reliability report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelIdentity {
    /// Value of `/api/version`.
    pub version: String,
    /// Digest of the requested model, when `/api/tags` included one.
    pub digest: Option<String>,
}

/// Returns whether `requested` matches an advertised model name or its untagged base.
#[must_use]
pub fn model_is_present(requested: &str, models: &[RemoteModel]) -> bool {
    models
        .iter()
        .any(|model| names_match(requested, &model.name))
}

/// Matches `name` to `name` or `name:tag`. A different base never matches.
#[must_use]
pub fn names_match(requested: &str, advertised: &str) -> bool {
    if advertised == requested {
        return true;
    }
    match advertised.rsplit_once(':') {
        Some((base, tag)) if !base.is_empty() && !tag.is_empty() => base == requested,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_matching_accepts_exact_and_tag_forms() {
        let cases = [
            ("lca-30b-agent", "lca-30b-agent:latest", true),
            ("lca-30b-agent", "lca-30b-agent", true),
            ("lca-30b-agent:latest", "lca-30b-agent:latest", true),
            ("lca-30b-agent", "other:latest", false),
            ("lca-30b-agent", "lca-30b-agent-extra:latest", false),
            ("lca", "lca-30b-agent:latest", false),
            ("lca-30b-agent", "lca-30b-agent:", false),
            ("library/model", "library/model:latest", true),
        ];
        for (requested, advertised, expected) in cases {
            assert_eq!(names_match(requested, advertised), expected, "{advertised}");
        }
    }

    #[test]
    fn responses_ignore_unknown_fields() {
        let version: VersionResponse =
            serde_json::from_str(r#"{"version":"0.13.5","extra":true}"#).expect("version");
        assert_eq!(version.version, "0.13.5");

        let tags: TagsResponse = serde_json::from_str(
            r#"{"models":[{"name":"lca-30b-agent:latest","size":1,"details":{"family":"qwen"}}]}"#,
        )
        .expect("tags");
        assert!(model_is_present("lca-30b-agent", &tags.models));
        assert!(!model_is_present("missing", &tags.models));
    }

    #[test]
    fn missing_required_fields_are_rejected() {
        assert!(serde_json::from_str::<VersionResponse>("{}").is_err());
        assert!(serde_json::from_str::<TagsResponse>(r#"{"models":[{"size":1}]}"#).is_err());
    }
}
