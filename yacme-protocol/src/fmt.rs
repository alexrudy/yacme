//! Utilities for formatting ACME request and response data in a human
//! readable style, similar to that used in RFC8885
//!

use std::fmt;

pub use fmt::Result;
pub use fmt::Write;
use serde::Serialize;

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
    pub fn new(indent: &'i str, writer: W) -> Self {
        IndentWriter {
            writer,
            indent,
            level: 0,
            need_indent: true,
        }
    }

    pub fn indent_str(&self) -> &str {
        self.indent
    }
}

impl<'i, W: fmt::Write> IndentWriter<'i, W> {
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

    pub fn write_json<T: Serialize>(&mut self, data: &T) -> fmt::Result {
        let mut writer = Vec::with_capacity(128);
        let fmt = serde_json::ser::PrettyFormatter::with_indent(self.indent_str().as_bytes());
        let mut ser = serde_json::ser::Serializer::with_formatter(&mut writer, fmt);
        data.serialize(&mut ser).unwrap();

        let data = unsafe { String::from_utf8_unchecked(writer) };

        write!(self, "{}", data)
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

pub type Formatter<'f> = IndentWriter<'f, &'f mut std::fmt::Formatter<'f>>;

pub trait AcmeFormat {
    fn fmt<W: fmt::Write>(&self, f: &mut IndentWriter<'_, W>) -> fmt::Result;

    fn fmt_indented<W: fmt::Write>(&self, f: &mut IndentWriter<'_, W>) -> fmt::Result {
        let mut f = f.indent();
        self.fmt(&mut f)
    }

    fn fmt_indented_skip_first<W: fmt::Write>(&self, f: &mut IndentWriter<'_, W>) -> fmt::Result {
        let mut f = f.indent_skip_first();
        self.fmt(&mut f)
    }

    fn formatted(&self) -> AcmeFormatted<'_, Self> {
        AcmeFormatted(self)
    }
}

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

pub trait HttpCase {
    fn titlecase(&self) -> TitleCase<'_, Self> {
        TitleCase(self)
    }
    fn lowercase(&self) -> LowerCase<'_, Self> {
        LowerCase(self)
    }
}

impl<T> HttpCase for T where T: fmt::Display {}

#[derive(Debug)]
struct TitleCaseWriter<W> {
    writer: W,
    prev: char,
}

impl<W> std::fmt::Write for TitleCaseWriter<W>
where
    W: std::fmt::Write,
{
    fn write_str(&mut self, s: &str) -> Result {
        for c in s.chars() {
            if self.prev == '-' {
                self.writer.write_char(c.to_ascii_uppercase())?;
            } else {
                self.writer.write_char(c.to_ascii_lowercase())?;
            }
            self.prev = c;
        }
        Ok(())
    }
}

impl<W> TitleCaseWriter<W> {
    fn new(writer: W) -> Self {
        TitleCaseWriter { writer, prev: '-' }
    }
}

pub struct TitleCase<'a, T: ?Sized>(&'a T);

impl<'a, T: std::fmt::Display + ?Sized> std::fmt::Display for TitleCase<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result {
        let mut writer = TitleCaseWriter::new(f);
        write!(&mut writer, "{}", self.0)
    }
}

#[derive(Debug)]
struct LowerCaseWriter<W> {
    writer: W,
}

impl<W> std::fmt::Write for LowerCaseWriter<W>
where
    W: std::fmt::Write,
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

pub struct LowerCase<'a, T: ?Sized>(&'a T);

impl<'a, T: std::fmt::Display + ?Sized> std::fmt::Display for LowerCase<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result {
        let mut writer = LowerCaseWriter::new(f);
        write!(&mut writer, "{}", self.0)
    }
}
