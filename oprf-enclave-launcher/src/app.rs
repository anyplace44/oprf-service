//! `/etc/enclave/app`, the program the launcher runs.
//!
//! The file holds a single absolute path; a trailing newline is allowed. The
//! Dockerfile writes it into the rootfs, so it is measured into the EIF's PCRs.

const APP_PATH: &str = "/etc/enclave/app";

/// The program named in [`APP_PATH`].
pub(crate) fn path() -> Result<String, String> {
    let text = std::fs::read_to_string(APP_PATH).map_err(|e| format!("{APP_PATH}: {e}"))?;
    parse_app(&text).map_err(|e| format!("{APP_PATH}: {e}"))
}

/// Returns the path in `s`.
fn parse_app(s: &str) -> Result<String, String> {
    let path = s.strip_suffix('\n').unwrap_or(s);
    if !path.starts_with('/') {
        return Err(format!("not an absolute path: {path:?}"));
    }
    if path.chars().any(char::is_whitespace) {
        return Err(format!("path contains whitespace: {path:?}"));
    }
    Ok(path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_absolute_path_with_or_without_newline() {
        assert_eq!(
            parse_app("/app/taceo-oprf-node\n"),
            Ok("/app/taceo-oprf-node".to_owned()),
            "trailing newline is stripped"
        );
        assert_eq!(
            parse_app("/app/taceo-oprf-key-gen"),
            Ok("/app/taceo-oprf-key-gen".to_owned()),
            "no newline is fine too"
        );
    }

    #[test]
    fn rejects_relative_empty_or_multi_line() {
        for bad in [
            "",
            "\n",
            "app/node",
            "/app/a\n/app/b",
            "/app/node\n\n",
            " /app/node",
        ] {
            assert!(parse_app(bad).is_err(), "{bad:?} must be rejected");
        }
    }
}
