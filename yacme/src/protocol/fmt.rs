//! Utilities for formatting ACME request and response data in a human
//! readable style, similar to that used in RFC8885
//!

use std::fmt;

pub use fmt::Result;
pub use fmt::Write;
use serde::Serialize;

/// A [`fmt::Write`] writer with indentation memory useful for formatting
/// structured data.
pub struct IndentWriter<'i, W> {
    writer: W,
    indent: &'i str,
    level: usize,
    need_indent: bool,
}

impl<'i, W> fmt::Debug for IndentWriter<'i, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result {
        f.debug_struct("IndentWriter")
            .field("writer", &"W")
            .field("indent", &self.indent)
            .field("level", &self.level)
            .field("need_indent", &self.need_indent)
            .finish()
    }
}

impl<'i, W> IndentWriter<'i, W>
where
    W: fmt::Write,
{
    fn write_indent(&mut self) -> fmt::Result {
        if self.level > 0 {
            self.writer.write_str(self.indent)?;
        }
        Ok(())
    }
}

impl<'i, W> IndentWriter<'i, W> {
    /// Create a new writer from an existing writer and a proposed indent
    /// string.
    ///
    /// The writer will start with no indent. Use [`IndentWriter::indent`]
    /// to create an indented writer at the next level. Drop the writer returned
    /// from [`IndentWriter::indent`] to return the current level.
    pub fn new(indent: &'i str, writer: W) -> Self {
        IndentWriter {
            writer,
            indent,
            level: 0,
            need_indent: true,
        }
    }

    /// Get the string used to indent each level.
    pub fn indent_str(&self) -> &str {
        self.indent
    }
}

impl<'i, W: fmt::Write> IndentWriter<'i, W> {
    /// Produce a new [`IndentWriter`] at one deeper indent level.
    pub fn indent(&mut self) -> IndentWriter<'i, &mut IndentWriter<'i, W>> {
        let indent = self.indent;
        let level = self.level + 1;
        IndentWriter {
            writer: self,
            indent,
            level,
            need_indent: true,
        }
    }

    /// Produce a new [`IndentWriter`] at one deeper indent level, but don't indent
    /// the current line.
    ///
    /// This produces a "hanging indent" where only the second line starts at the new
    /// indentation.
    pub fn indent_skip_first(&mut self) -> IndentWriter<'i, &mut IndentWriter<'i, W>> {
        let indent = self.indent;
        let level = self.level + 1;
        IndentWriter {
            writer: self,
            indent,
            level,
            need_indent: false,
        }
    }

    /// Write an object as prettified JSON
    ///
    /// This will use the specified indent string to pretty-format the JSON via
    /// [`serde_json::to_string_pretty`].
    pub fn write_json<T: Serialize>(&mut self, data: &T) -> fmt::Result {
        let mut writer = Vec::with_capacity(128);
        let fmt = serde_json::ser::PrettyFormatter::with_indent(self.indent_str().as_bytes());
        let mut ser = serde_json::ser::Serializer::with_formatter(&mut writer, fmt);
        data.serialize(&mut ser).unwrap();

        // SAFETY: serde-json does not emit invalid UTF-8
        let data = unsafe { String::from_utf8_unchecked(writer) };

        self.write_str(&data)
    }
}

impl<'i, W> fmt::Write for IndentWriter<'i, W>
where
    W: fmt::Write,
{
    fn write_str(&mut self, mut s: &str) -> fmt::Result {
        loop {
            match self.need_indent {
                // We don't need an indent. Scan for the end of the line
                false => match s.as_bytes().iter().position(|&b| b == b'\n') {
                    // No end of line in the input; write the entire string
                    None => break self.writer.write_str(s),

                    // We can see the end of the line. Write up to and including
                    // that newline, then request an indent
                    Some(len) => {
                        let (head, tail) = s.split_at(len + 1);
                        self.writer.write_str(head)?;
                        self.need_indent = true;
                        s = tail;
                    }
                },
                // We need an indent. Scan for the beginning of the next
                // non-empty line.
                true => match s.as_bytes().iter().position(|&b| b != b'\n') {
                    // No non-empty lines in input, write the entire string
                    None => break self.writer.write_str(s),

                    // We can see the next non-empty line. Write up to the
                    // beginning of that line, then insert an indent, then
                    // continue.
                    Some(len) => {
                        let (head, tail) = s.split_at(len);
                        self.writer.write_str(head)?;
                        self.write_indent()?;
                        self.need_indent = false;
                        s = tail;
                    }
                },
            }
        }
    }

    fn write_char(&mut self, c: char) -> fmt::Result {
        // We need an indent, and this is the start of a non-empty line.
        // Insert the indent.
        if self.need_indent && c != '\n' {
            self.write_indent()?;
            self.need_indent = false;
        }

        // This is the end of a non-empty line. Request an indent.
        if !self.need_indent && c == '\n' {
            self.need_indent = true;
        }

        self.writer.write_char(c)
    }
}

/// Format trait for showing data in the style of [RFC 8885][]
///
/// Data should be formatted as an HTTP request with a pretty-printed
/// JSON body, using `base64encode()` to represent base-64 encoded strings.
///
/// [RFC 8885]: https://datatracker.ietf.org/doc/html/rfc8555
pub trait AcmeFormat {
    /// Write this format at the current indentation.
    fn fmt<W: fmt::Write>(&self, f: &mut IndentWriter<'_, W>) -> fmt::Result;

    /// Write this format at an indented level one greater than the current level.
    ///
    /// After this method completes, the indentation level is left unchanged.
    fn fmt_indented<W: fmt::Write>(&self, f: &mut IndentWriter<'_, W>) -> fmt::Result {
        let mut f = f.indent();
        self.fmt(&mut f)
    }

    /// Write this format at an indented level one greater than the current level,
    /// but don't indent the first line.
    fn fmt_indented_skip_first<W: fmt::Write>(&self, f: &mut IndentWriter<'_, W>) -> fmt::Result {
        let mut f = f.indent_skip_first();
        self.fmt(&mut f)
    }

    /// Return a formatting proxy which will use the ACME format when used with [`std::fmt::Display`].
    fn formatted(&self) -> AcmeFormatted<'_, Self> {
        AcmeFormatted(self)
    }
}

/// Formatting proxy to cause [`fmt::Display`] to print in the [`AcmeFormat`] style.
pub struct AcmeFormatted<'a, T: AcmeFormat + ?Sized>(&'a T);

impl<'a, T> fmt::Display for AcmeFormatted<'a, T>
where
    T: AcmeFormat,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut formatter = IndentWriter::new("  ", f);
        <T as AcmeFormat>::fmt(self.0, &mut formatter)
    }
}

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