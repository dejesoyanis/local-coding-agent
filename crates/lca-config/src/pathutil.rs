use std::path::PathBuf;

/// Removes the Windows verbatim prefix so comparisons and display use an ordinary path.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_verbatim_disk_prefix() {
        let path = PathBuf::from(r"\\?\C:\workspace");
        assert_eq!(simplify_verbatim(path), PathBuf::from(r"C:\workspace"));
    }

    #[test]
    fn strips_verbatim_unc_prefix() {
        let path = PathBuf::from(r"\\?\UNC\server\share");
        assert_eq!(simplify_verbatim(path), PathBuf::from(r"\\server\share"));
    }

    #[test]
    fn leaves_ordinary_paths_unchanged() {
        let path = PathBuf::from(r"C:\workspace");
        assert_eq!(simplify_verbatim(path.clone()), path);
    }
}
