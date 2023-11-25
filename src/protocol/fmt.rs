//! Utilities for formatting ACME request and response data in a human
//! readable style, similar to that used in RFC8885
//!

use std::fmt;

pub use fmt::Result;
pub use fmt::Write;

pub use jaws::JWTFormat;

/// Trait for case-folding items which implement [`fmt::Display`] according
/// to HTTP/1.1 casefolding rules.
pub trait HttpCase {
    /// Format in HTTP/1.1 header title case.
    ///
    /// Provides a formatting proxy for formatting according to HTTP/1.1
    /// title case, where header values are formatted in title case using `-`
    /// as the word separator.
    fn titlecase(&self) -> TitleCase<'_, Self> {
        TitleCase(self)
    }

    /// Format in HTTP/1.1 header lower case.
    ///
    /// Provides a formatting proxy for formatting according to HTTP/1.1
    /// lower case, where header values are all ascii lowercase. This is
    /// also consistent with HTTP/2 and HTTP/3.
    fn lowercase(&self) -> LowerCase<'_, Self> {
        LowerCase(self)
    }
}

impl<T> HttpCase for T where T: fmt::Display {}

/// Writer implementation which always writes in HTTP/1.1 header
/// title case, using `-` as word delimiters.
#[derive(Debug)]
struct TitleCaseWriter<W> {
    writer: W,
    prev: char,
}

impl<W> fmt::Write for TitleCaseWriter<W>
where
    W: fmt::Write,
{
    fn write_str(&mut self, s: &str) -> Result {
        for c in s.chars() {
            if self.prev == '-' {
                self.writer.write_char(c.to_ascii_uppercase())?;
            } else {
                self.writer.write_char(c.to_ascii_lowercase())?;
            }

            if c.is_ascii_whitespace() {
                self.prev = '-'
            } else {
                self.prev = c;
            }
        }
        Ok(())
    }
}

impl<W> TitleCaseWriter<W> {
    fn new(writer: W) -> Self {
        TitleCaseWriter { writer, prev: '-' }
    }
}

/// Format in HTTP/1.1 header title case.
///
/// A formatting proxy for formatting according to HTTP/1.1
/// title case, where header values are formatted in title case using `-`
/// as the word separator.
pub struct TitleCase<'a, T: ?Sized>(&'a T);

impl<'a, T: fmt::Display + ?Sized> fmt::Display for TitleCase<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result {
        let mut writer = TitleCaseWriter::new(f);
        write!(&mut writer, "{}", self.0)
    }
}

/// Writer implementation which always writes in ascii lowercase.
#[derive(Debug)]
struct LowerCaseWriter<W> {
    writer: W,
}

impl<W> fmt::Write for LowerCaseWriter<W>
where
    W: fmt::Write,
{
    fn write_str(&mut self, s: &str) -> Result {
        self.writer.write_str(&s.to_ascii_lowercase())
    }
}

impl<W> LowerCaseWriter<W> {
    fn new(writer: W) -> Self {
        LowerCaseWriter { writer }
    }
}

/// Format in HTTP/1.1 header lower case.
///
/// A formatting proxy for formatting according to HTTP/1.1
/// lower case, where header values are all ascii lowercase. This is
/// also consistent with HTTP/2 and HTTP/3.
pub struct LowerCase<'a, T: ?Sized>(&'a T);

impl<'a, T: fmt::Display + ?Sized> fmt::Display for LowerCase<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result {
        let mut writer = LowerCaseWriter::new(f);
        write!(&mut writer, "{}", self.0)
    }
}
