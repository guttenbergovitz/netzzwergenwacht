//! Untrusted content sanitisation and redaction for terminal presentation.
//!
//! All data originating from external web applications (URLs, HTTP headers,
//! runtime console errors, DOM attributes, accessible names, and LLM text)
//! must be filtered through this module before rendering in Ratatui widgets.

use url::Url;

/// Maximum default character length for single-line terminal labels.
pub const DEFAULT_MAX_CELL_CHARS: usize = 240;

/// Maximum default character length for multi-line detail paragraphs.
pub const DEFAULT_MAX_DETAIL_CHARS: usize = 4_096;

/// Sensitive URL query parameter names whose values must be redacted before display.
const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "authorization",
    "session",
    "session_id",
    "sessionid",
    "sig",
    "signature",
];

/// Returns `true` if `ch` is a Unicode bidirectional override, embedding,
/// isolate, or mark character that could spoof visual ordering in a terminal.
#[must_use]
pub const fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// Sanitises an untrusted string into a single bounded terminal line.
///
/// Strips ANSI CSI (`ESC [`), OSC (`ESC ]`), DCS/APC/PM/SOS sequences, single-character
/// ESC sequences, C0 and C1 control characters (including carriage return, backspace,
/// bell, and newline), and Unicode bidirectional control characters. Collapses tabs
/// and line breaks into single spaces and truncates at `max_chars`.
#[must_use]
pub fn sanitize_line(input: &str, max_chars: usize) -> String {
    sanitize_internal(input, max_chars, false)
}

/// Sanitises an untrusted string into bounded multi-line text suitable for detail panels.
///
/// Preserves `\n` line feeds (while stripping `\r` carriage returns and all ANSI/OSC/BiDi
/// and C0/C1 control sequences) and truncates at `max_chars`.
#[must_use]
pub fn sanitize_multiline(input: &str, max_chars: usize) -> String {
    sanitize_internal(input, max_chars, true)
}

/// Redacts credentials and sensitive query parameters from a URL string and
/// sanitises it for single-line terminal display.
#[must_use]
pub fn sanitize_url_for_display(raw_url: &str, max_chars: usize) -> String {
    let cleaned = sanitize_line(raw_url, max_chars.saturating_mul(2).max(256));
    let Ok(mut parsed) = Url::parse(&cleaned) else {
        return truncate_chars(&cleaned, max_chars);
    };
    if !parsed.username().is_empty() {
        let _ = parsed.set_username("REDACTED");
    }
    if parsed.password().is_some() {
        let _ = parsed.set_password(Some("REDACTED"));
    }
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| {
            let lower = k.to_ascii_lowercase();
            let is_sensitive = SENSITIVE_QUERY_KEYS.iter().any(|needle| lower == *needle)
                || lower.ends_with("_token")
                || lower.ends_with("_key")
                || lower.ends_with("_secret");
            if is_sensitive {
                (k.into_owned(), "REDACTED".to_owned())
            } else {
                (k.into_owned(), v.into_owned())
            }
        })
        .collect();
    if !pairs.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in &pairs {
            serializer.append_pair(k, v);
        }
        let encoded = serializer.finish();
        parsed.set_query(Some(&encoded));
    }
    truncate_chars(parsed.as_str(), max_chars)
}

fn sanitize_internal(input: &str, max_chars: usize, allow_newlines: bool) -> String {
    if max_chars == 0 || input.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(input.len().min(max_chars));
    let mut chars = input.chars().peekable();
    let mut emitted = 0usize;
    let mut truncated = false;

    while let Some(ch) = chars.next() {
        if ch == '\x1b' || ch == '\u{009b}' {
            skip_escape_sequence(ch, &mut chars);
            continue;
        }

        if is_bidi_control(ch) {
            continue;
        }

        if ch == '\n' {
            if allow_newlines {
                if !push_bounded(&mut out, '\n', &mut emitted, max_chars) {
                    truncated = true;
                    break;
                }
            } else if !push_bounded(&mut out, ' ', &mut emitted, max_chars) {
                truncated = true;
                break;
            }
            continue;
        }

        if ch == '\t' {
            if !push_bounded(&mut out, ' ', &mut emitted, max_chars) {
                truncated = true;
                break;
            }
            continue;
        }

        if ch.is_control() {
            continue;
        }

        if !push_bounded(&mut out, ch, &mut emitted, max_chars) {
            truncated = true;
            break;
        }
    }

    if truncated {
        out.push_str("...");
    }
    out
}

fn push_bounded(out: &mut String, ch: char, emitted: &mut usize, max_chars: usize) -> bool {
    if *emitted >= max_chars {
        return false;
    }
    out.push(ch);
    *emitted += 1;
    true
}

fn skip_escape_sequence(starter: char, chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    if starter == '\u{009b}' {
        skip_csi_body(chars);
        return;
    }
    let Some(&next) = chars.peek() else {
        return;
    };
    match next {
        '[' => {
            let _ = chars.next();
            skip_csi_body(chars);
        }
        ']' | 'P' | 'X' | '^' | '_' => {
            let _ = chars.next();
            skip_st_terminated_sequence(chars);
        }
        _ => {
            // Intermediate bytes (0x20..=0x2F) followed by final byte (0x30..=0x7E)
            while let Some(&c) = chars.peek() {
                let code = u32::from(c);
                let _ = chars.next();
                if !(0x20..=0x2F).contains(&code) {
                    break;
                }
            }
        }
    }
}

fn skip_csi_body(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(&c) = chars.peek() {
        let code = u32::from(c);
        let _ = chars.next();
        if (0x40..=0x7E).contains(&code) {
            break;
        }
    }
}

fn skip_st_terminated_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(c) = chars.next() {
        if c == '\x07' || c == '\u{009c}' {
            break;
        }
        if c == '\x1b' && chars.peek() == Some(&'\\') {
            let _ = chars.next();
            break;
        }
    }
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (idx, ch) in input.chars().enumerate() {
        if idx >= max_chars {
            out.push_str("...");
            break;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ansi_csi_and_osc_escape_sequences() {
        let hostile = "Normal \x1b[31;1mRed\x1b[0m and \x1b]0;Pwned Title\x07 and \x1b]52;c;SGVsbG8=\x1b\\ end";
        let cleaned = sanitize_line(hostile, 200);
        assert_eq!(cleaned, "Normal Red and  and  end");
        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\x07'));
    }

    #[test]
    fn strips_carriage_returns_backspaces_and_bidi_overrides() {
        let hostile = "safe\rFAKE\x08\x08\u{202E}txt.exe\u{202C}\u{2066}isolated\u{2069}";
        let cleaned = sanitize_line(hostile, 200);
        assert_eq!(cleaned, "safeFAKEtxt.exeisolated");
        assert!(!cleaned.chars().any(is_bidi_control));
        assert!(!cleaned.chars().any(char::is_control));
    }

    #[test]
    fn enforces_max_character_bounds() {
        let oversized = "a".repeat(1_000);
        let cleaned = sanitize_line(&oversized, 32);
        assert_eq!(cleaned.len(), 35);
        assert!(cleaned.ends_with("..."));
    }

    #[test]
    fn redacts_sensitive_url_credentials_and_query_parameters() {
        let url = "https://admin:supersecret@example.org/callback?access_token=abc123&page=2&api_key=xyz987";
        let display = sanitize_url_for_display(url, 200);
        assert!(!display.contains("supersecret"));
        assert!(!display.contains("abc123"));
        assert!(!display.contains("xyz987"));
        assert!(display.contains("access_token=REDACTED"));
        assert!(display.contains("api_key=REDACTED"));
        assert!(display.contains("page=2"));
    }
}
