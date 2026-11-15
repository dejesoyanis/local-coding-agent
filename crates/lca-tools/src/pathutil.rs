use std::path::{Component, Path, PathBuf};

/// Removes a Windows verbatim prefix so later comparisons use an ordinary path.
pub(crate) fn simplify_verbatim(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(rest.to_owned());
    }
    path
}

/// Resolves `.` and `..` without touching the filesystem.
pub(crate) fn normalize_lexical(path: &Path) -> PathBuf {
    let mut stack = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(stack.last(), Some(Component::Normal(_))) {
                    stack.pop();
                } else {
                    stack.push(Component::ParentDir);
                }
            }
            other => stack.push(other),
        }
    }

    let mut normalized = PathBuf::new();
    for component in stack {
        append_component(&mut normalized, component);
    }
    normalized
}

fn append_component(path: &mut PathBuf, component: Component<'_>) {
    match component {
        Component::Prefix(prefix) => {
            *path = PathBuf::from(prefix.as_os_str());
        }
        Component::RootDir => {
            let mut text = path.as_os_str().to_os_string();
            let rendered = text.to_string_lossy();
            if !rendered.ends_with(['\\', '/']) {
                text.push(std::path::MAIN_SEPARATOR_STR);
            }
            *path = PathBuf::from(text);
        }
        Component::CurDir => {}
        Component::ParentDir => path.push(".."),
        Component::Normal(part) => path.push(part),
    }
}

pub(crate) fn is_within(root: &Path, candidate: &Path) -> bool {
    let root_parts: Vec<_> = root.components().collect();
    let candidate_parts: Vec<_> = candidate.components().collect();
    if candidate_parts.len() < root_parts.len() {
        return false;
    }
    root_parts
        .iter()
        .zip(candidate_parts.iter())
        .all(|(left, right)| component_eq(left, right))
}

fn component_eq(left: &Component<'_>, right: &Component<'_>) -> bool {
    #[cfg(windows)]
    {
        left.as_os_str().eq_ignore_ascii_case(right.as_os_str())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_verbatim_prefixes() {
        assert_eq!(
            simplify_verbatim(PathBuf::from(r"\\?\C:\workspace")),
            PathBuf::from(r"C:\workspace")
        );
        assert_eq!(
            simplify_verbatim(PathBuf::from(r"\\?\UNC\server\share")),
            PathBuf::from(r"\\server\share")
        );
    }

    #[test]
    fn normalizes_dot_and_parent_segments() {
        assert_eq!(
            normalize_lexical(Path::new(r"foo\.\bar")),
            PathBuf::from(r"foo\bar")
        );
        assert_eq!(
            normalize_lexical(Path::new(r"C:\ws\foo\..\bar")),
            PathBuf::from(r"C:\ws\bar")
        );
        assert_eq!(
            normalize_lexical(Path::new(r"C:\ws\..\outside")),
            PathBuf::from(r"C:\outside")
        );
    }

    #[test]
    fn within_rejects_sibling_prefixes() {
        let root = Path::new(r"C:\ws");
        assert!(is_within(root, Path::new(r"C:\ws")));
        assert!(is_within(root, Path::new(r"C:\ws\src\main.rs")));
        assert!(!is_within(root, Path::new(r"C:\ws-evil\file")));
        assert!(!is_within(root, Path::new(r"C:\outside")));
    }
}
