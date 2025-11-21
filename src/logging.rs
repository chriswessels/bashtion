use std::io::{self, Write};

use crate::error::BashtionError;

pub fn log_stderr(message: impl AsRef<str>) -> Result<(), BashtionError> {
    let mut stderr = io::stderr();
    stderr
        .write_all(message.as_ref().as_bytes())
        .and_then(|_| stderr.write_all(b"\n"))
        .map_err(BashtionError::Io)
}
