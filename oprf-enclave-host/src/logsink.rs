//! Log sink: copies the enclave's log lines to a writer, prefixed.

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// Longest line kept; the enclave caps at 16 KiB, the rest of a longer line is dropped.
const MAX_LINE: usize = 16 * 1024;
const PREFIX: &[u8] = b"enclave: ";
const TRUNCATED: &[u8] = b" [truncated]";

/// Copies `r` to `w` line by line as `enclave: <line>`. Memory use is bounded
/// by [`MAX_LINE`] whatever the peer sends; control characters other than tab
/// are replaced so a peer cannot forge terminal output.
pub async fn copy_lines<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
) -> std::io::Result<()> {
    let mut line = Vec::with_capacity(256);
    let mut truncated = false;
    loop {
        let buf = r.fill_buf().await?;
        if buf.is_empty() {
            if !line.is_empty() || truncated {
                emit(&mut w, &line, truncated).await?;
            }
            return Ok(());
        }
        let (chunk, newline) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (&buf[..i], true),
            None => (buf, false),
        };
        let take = chunk.len().min(MAX_LINE - line.len());
        truncated |= take < chunk.len();
        line.extend_from_slice(&chunk[..take]);
        let consumed = chunk.len() + usize::from(newline);
        r.consume(consumed);
        if newline {
            emit(&mut w, &line, truncated).await?;
            line.clear();
            truncated = false;
        }
    }
}

async fn emit<W: AsyncWrite + Unpin>(
    w: &mut W,
    line: &[u8],
    truncated: bool,
) -> std::io::Result<()> {
    let text: String = String::from_utf8_lossy(line)
        .chars()
        .map(|c| if c.is_control() && c != '\t' { '?' } else { c })
        .collect();
    let mut out = Vec::with_capacity(PREFIX.len() + text.len() + TRUNCATED.len() + 1);
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(text.as_bytes());
    if truncated {
        out.extend_from_slice(TRUNCATED);
    }
    out.push(b'\n');
    w.write_all(&out).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncWriteExt, BufReader};

    async fn run(input: Vec<u8>) -> Vec<u8> {
        let (mut tx, rx) = tokio::io::duplex(64);
        let feeder = tokio::spawn(async move {
            tx.write_all(&input).await.expect("feed");
        });
        let mut out = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            copy_lines(BufReader::new(rx), &mut out),
        )
        .await
        .expect("test deadline")
        .expect("copy");
        feeder.await.expect("feeder");
        out
    }

    #[tokio::test]
    async fn log_lines_prefixed() {
        assert_eq!(run(b"a\nb\n".to_vec()).await, b"enclave: a\nenclave: b\n");
    }

    #[tokio::test]
    async fn unterminated_last_line_kept_and_controls_replaced() {
        assert_eq!(
            run(b"x\x1b[2Jy\nz".to_vec()).await,
            b"enclave: x?[2Jy\nenclave: z\n"
        );
    }

    #[tokio::test]
    async fn overlong_line_is_cut_and_the_next_one_survives() {
        let mut input = vec![b'a'; 3 * MAX_LINE];
        input.extend_from_slice(b"\nok\n");
        let out = run(input).await;
        let mut expected = PREFIX.to_vec();
        expected.extend(std::iter::repeat_n(b'a', MAX_LINE));
        expected.extend_from_slice(TRUNCATED);
        expected.extend_from_slice(b"\nenclave: ok\n");
        assert_eq!(out, expected);
    }
}
