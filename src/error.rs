/// Errors that can occur while parsing a TCG event log.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The input data was too short to contain a valid log.
    #[error("unexpected end of data: needed {needed} more bytes at offset {offset}")]
    UnexpectedEof {
        /// Number of bytes needed.
        needed: usize,
        /// Byte offset in the input where the short read occurred.
        offset: usize,
    },

    /// A string field contained invalid UTF-8 or UTF-16 data.
    #[error("invalid string data at offset {offset}: {message}")]
    InvalidString {
        /// Byte offset in the input.
        offset: usize,
        /// Human-readable description.
        message: String,
    },

    /// The SpecID event signature did not match the expected value.
    #[error("invalid SpecID signature: expected 'Spec ID Event03\\0', found {found:?}")]
    InvalidSpecIdSignature {
        /// The actual signature bytes found.
        found: Vec<u8>,
    },

    /// A numeric field had an unexpected or unsupported value.
    #[error("unsupported value {value} for field '{field}' at offset {offset}")]
    UnsupportedValue {
        /// The field name.
        field: &'static str,
        /// The actual value.
        value: u64,
        /// Byte offset in the input.
        offset: usize,
    },

    /// A custom [`EventDataParser`](crate::EventDataParser) returned an error.
    #[error("custom parser error for event type {event_type:#010x}: {message}")]
    CustomParser {
        /// The event type value.
        event_type: u32,
        /// Description from the custom parser.
        message: String,
    },

    /// The event log exceeds the configured maximum event count.
    #[error("Event log exceeds maximum event count ({limit})")]
    TooManyEvents {
        /// The configured limit that was exceeded.
        limit: usize,
    },
}

impl ParseError {
    /// Creates an [`UnexpectedEof`](ParseError::UnexpectedEof) error.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::ParseError;
    ///
    /// let err = ParseError::eof(10, 0);
    /// assert!(matches!(err, ParseError::UnexpectedEof { needed: 10, offset: 0 }));
    /// ```
    pub fn eof(needed: usize, offset: usize) -> Self {
        Self::UnexpectedEof { needed, offset }
    }

    /// Creates an [`InvalidString`](ParseError::InvalidString) error.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::ParseError;
    ///
    /// let err = ParseError::invalid_string(4, "bad utf-8");
    /// assert!(matches!(err, ParseError::InvalidString { .. }));
    /// ```
    pub fn invalid_string(offset: usize, message: impl Into<String>) -> Self {
        Self::InvalidString {
            offset,
            message: message.into(),
        }
    }
}

/// A helper for reading bytes from a slice, tracking the current position.
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Creates a new cursor at position 0.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Returns the current byte offset.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Returns `true` if there are no more bytes to read.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Reads exactly `n` bytes, advancing the cursor.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self.pos + n;
        if end > self.data.len() {
            return Err(ParseError::eof(end - self.data.len(), self.pos));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Reads a `u8`.
    pub fn read_u8(&mut self) -> Result<u8, ParseError> {
        let b = self.read_bytes(1)?;
        Ok(b[0])
    }

    /// Reads a little-endian `u16`.
    pub fn read_u16_le(&mut self) -> Result<u16, ParseError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Reads a little-endian `u32`.
    pub fn read_u32_le(&mut self) -> Result<u32, ParseError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a little-endian `u64`.
    pub fn read_u64_le(&mut self) -> Result<u64, ParseError> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_read_u8() {
        let mut c = Cursor::new(&[0x42]);
        assert_eq!(c.read_u8().unwrap(), 0x42);
        assert!(c.is_empty());
    }

    #[test]
    fn cursor_read_u16_le() {
        let mut c = Cursor::new(&[0x01, 0x02]);
        assert_eq!(c.read_u16_le().unwrap(), 0x0201);
    }

    #[test]
    fn cursor_read_u32_le() {
        let mut c = Cursor::new(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(c.read_u32_le().unwrap(), 0x04030201);
    }

    #[test]
    fn cursor_read_u64_le() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut c = Cursor::new(&data);
        assert_eq!(c.read_u64_le().unwrap(), 0x0807060504030201);
    }

    #[test]
    fn cursor_eof_error() {
        let mut c = Cursor::new(&[0x01]);
        assert!(c.read_u32_le().is_err());
    }

    #[test]
    fn cursor_position_tracks_reads() {
        let mut c = Cursor::new(&[1, 2, 3, 4]);
        assert_eq!(c.position(), 0);
        c.read_u8().unwrap();
        assert_eq!(c.position(), 1);
        c.read_u16_le().unwrap();
        assert_eq!(c.position(), 3);
    }
}
