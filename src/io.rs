use std::io::{self, Read};

use crate::error::BashtionError;

pub fn read_stdin_limited(limit: usize) -> Result<String, BashtionError> {
    let mut buffer = Vec::new();
    let stdin = io::stdin().lock();
    let mut limited = stdin.take((limit + 1) as u64);
    limited.read_to_end(&mut buffer)?;
    if buffer.len() > limit {
        return Err(BashtionError::Other("Input exceeds buffer limit".into()));
    }

    String::from_utf8(buffer)
        .map_err(|e| BashtionError::Other(format!("Input is not valid UTF-8: {e}")))
}
