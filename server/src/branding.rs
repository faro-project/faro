//! Instance branding: an optional logo shown next to Faro's, and a few
//! customizations an admin can switch on or off (docs/SELF-HOSTING.md
//! "Branding your instance").
//!
//! An instance operator is not fully trusted (ARCHITECTURE.md §5.3), so
//! everything here is held to a few rules:
//!
//! * **Text is plain text.** The welcome line and the support contact are
//!   single lines with a length limit, no control characters, and none of
//!   the invisible characters that reorder or hide text
//!   ([`check_plain_text`]). The web app shows them as text, never as HTML
//!   or Markdown.
//! * **A support contact is an email address or an `https://` URL**, nothing
//!   else, so it can never become a `javascript:` or `data:` link.
//! * **The logo is never served as uploaded.** Only PNG, JPEG and WebP are
//!   accepted (never SVG, which can carry script); the server decodes the
//!   image within fixed limits and re-encodes it as a PNG of at most
//!   [`LOGO_MAX_SIDE`] pixels ([`reencode_logo`]). That drops metadata and
//!   anything else that isn't pixels.
//! * **Page chrome only.** The web app shows branding in the header, the
//!   footer and on the sign-in and setup pages, never in alerts, feeds,
//!   reports, safety codes, key fingerprints, tamper warnings or enrollment
//!   confirmation. `/.well-known/faro` and emails don't carry it.
//!
//! Changing the branding needs no notice to members or allies: it changes
//! nothing about what anyone can see or do.

use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::{ImageEncoder, ImageFormat, ImageReader, Limits};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

/// Longest welcome line, in characters.
pub const WELCOME_MAX_CHARS: usize = 200;
/// Longest support contact, in characters.
pub const SUPPORT_MAX_CHARS: usize = 200;

/// Largest logo upload accepted, in bytes.
pub const LOGO_MAX_UPLOAD_BYTES: usize = 1024 * 1024;
/// Largest width or height of an uploaded logo. Bigger images are refused
/// before their pixels are decoded.
pub const LOGO_MAX_INPUT_SIDE: u32 = 4096;
/// Largest width or height of the stored logo: bigger uploads are scaled
/// down. The header shows it about 26 px high, the sign-in page 56 px.
pub const LOGO_MAX_SIDE: u32 = 512;
/// Memory the decoder may allocate for one upload.
const LOGO_MAX_DECODE_BYTES: u64 = 96 * 1024 * 1024;

/// What an admin has set (stored as `branding.settings_json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BrandingSettings {
    /// Show the logo next to Faro's, when there is one.
    pub show_logo: bool,
    /// Show the instance name in the header.
    pub show_name: bool,
    /// Show `welcome` on the sign-in page.
    pub welcome_enabled: bool,
    pub welcome: String,
    /// Show `support` in the footer and on the sign-in page.
    pub support_enabled: bool,
    /// An email address or an `https://` URL.
    pub support: String,
}

impl Default for BrandingSettings {
    /// What every instance had before branding existed: the name in the
    /// header and nothing else. `show_logo` starts on, so a logo shows once
    /// it is uploaded.
    fn default() -> Self {
        BrandingSettings {
            show_logo: true,
            show_name: true,
            welcome_enabled: false,
            welcome: String::new(),
            support_enabled: false,
            support: String::new(),
        }
    }
}

/// `PATCH /admin/api/branding` body: any subset of fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrandingPatch {
    pub show_logo: Option<bool>,
    pub show_name: Option<bool>,
    pub welcome_enabled: Option<bool>,
    pub welcome: Option<String>,
    pub support_enabled: Option<bool>,
    pub support: Option<String>,
}

/// Why a branding change was refused. `code()` is the API error code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrandingError {
    #[error("{0}")]
    InvalidWelcome(String),
    #[error("{0}")]
    InvalidSupport(String),
}

impl BrandingError {
    pub fn code(&self) -> &'static str {
        match self {
            BrandingError::InvalidWelcome(_) => "invalid_welcome",
            BrandingError::InvalidSupport(_) => "invalid_support_contact",
        }
    }
}

impl BrandingSettings {
    /// Parse the stored JSON. Empty means the defaults.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        if s.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(s)
    }

    pub fn to_json(&self) -> String {
        // Serializing a struct of bools and strings cannot fail.
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_owned())
    }

    /// Fold a patch in and check the result. Text is trimmed. A text that is
    /// switched on must not be empty; one that is off may hold a draft, but
    /// is still checked, so nothing invalid is ever stored.
    pub fn apply(&self, p: &BrandingPatch) -> Result<Self, BrandingError> {
        let mut s = self.clone();
        if let Some(v) = p.show_logo {
            s.show_logo = v;
        }
        if let Some(v) = p.show_name {
            s.show_name = v;
        }
        if let Some(v) = p.welcome_enabled {
            s.welcome_enabled = v;
        }
        if let Some(v) = &p.welcome {
            v.trim().clone_into(&mut s.welcome);
        }
        if let Some(v) = p.support_enabled {
            s.support_enabled = v;
        }
        if let Some(v) = &p.support {
            v.trim().clone_into(&mut s.support);
        }
        s.validate()?;
        Ok(s)
    }

    pub fn validate(&self) -> Result<(), BrandingError> {
        check_plain_text(&self.welcome, WELCOME_MAX_CHARS)
            .map_err(|e| BrandingError::InvalidWelcome(format!("welcome line: {e}")))?;
        if self.welcome_enabled && self.welcome.is_empty() {
            return Err(BrandingError::InvalidWelcome(
                "write a welcome line, or turn it off".into(),
            ));
        }
        if !self.support.is_empty() {
            SupportContact::parse(&self.support).map_err(BrandingError::InvalidSupport)?;
        }
        if self.support_enabled && self.support.is_empty() {
            return Err(BrandingError::InvalidSupport(
                "enter a support contact, or turn it off".into(),
            ));
        }
        Ok(())
    }
}

/// Characters that are invisible or reorder the text around them: the
/// Unicode bidirectional controls, zero-width characters and other format
/// characters. They could make operator text read differently from what it
/// says, or hide part of it.
fn is_hidden_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'                // soft hyphen
        | '\u{034F}'              // combining grapheme joiner
        | '\u{061C}'              // Arabic letter mark
        | '\u{115F}' | '\u{1160}' // Hangul fillers
        | '\u{180E}'              // Mongolian vowel separator
        | '\u{200B}'..='\u{200F}' // zero-width space, joiners, LRM, RLM
        | '\u{2028}'..='\u{202E}' // line/paragraph separators, bidi embeddings
        | '\u{2060}'..='\u{206F}' // word joiner, invisible operators, bidi isolates
        | '\u{3164}'              // Hangul filler
        | '\u{FE00}'..='\u{FE0F}' // variation selectors
        | '\u{FEFF}'              // zero-width no-break space
        | '\u{FFA0}'              // halfwidth Hangul filler
        | '\u{FFF9}'..='\u{FFFB}' // interlinear annotations
        | '\u{E0000}'..='\u{E007F}' // tags
    )
}

/// Operator text: one line of at most `max_chars` characters, with no
/// control characters (so no line breaks) and no hidden format characters.
/// Characters like `<` are allowed: the web app shows them as they are.
pub fn check_plain_text(s: &str, max_chars: usize) -> Result<(), String> {
    if s.chars().count() > max_chars {
        return Err(format!("at most {max_chars} characters"));
    }
    if s.chars().any(char::is_control) {
        return Err("one line, with no control characters".into());
    }
    if s.chars().any(is_hidden_format_char) {
        return Err("no invisible or text-direction characters".into());
    }
    Ok(())
}

/// A validated support contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum SupportContact {
    Email(String),
    Url(String),
}

impl SupportContact {
    /// An email address (shown as a `mailto:` link) or an `https://` URL.
    /// Nothing else: no other scheme, no spaces, no control characters.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        check_plain_text(s, SUPPORT_MAX_CHARS).map_err(|e| format!("support contact: {e}"))?;
        let bad_char = |c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | '`');
        if s.is_empty() || s.chars().any(bad_char) {
            return Err("support contact: an email address or an https:// address".into());
        }
        if let Some(rest) = strip_prefix_ignore_case(s, "https://") {
            let host = rest.split(['/', '?', '#']).next().unwrap_or("");
            let host_ok = !host.is_empty()
                && !host.contains('@')
                && host
                    .chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
            if !host_ok {
                return Err("support contact: the web address has no valid host".into());
            }
            return Ok(SupportContact::Url(format!("https://{rest}")));
        }
        if s.contains(':') || s.contains('/') {
            return Err("support contact: web addresses must start with https://".into());
        }
        match s.split_once('@') {
            Some((local, domain))
                if !local.is_empty()
                    && domain.contains('.')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
                    && !domain.contains('@')
                    && !s.contains(['?', '#', '%', '\\']) =>
            {
                Ok(SupportContact::Email(s.to_owned()))
            }
            _ => Err("support contact: an email address or an https:// address".into()),
        }
    }
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// The logo as stored and served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logo {
    /// The re-encoded PNG.
    pub png: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// The first 128 bits of the PNG's BLAKE3 hash, in hex: part of the
    /// logo's URL, so the URL changes when the logo does.
    pub id: String,
}

/// Why an upload was refused. `code()` is the API error code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogoError {
    #[error("the logo must be at most 1 MB")]
    TooLarge,
    #[error("the logo must be a PNG, JPEG or WebP image (SVG is not accepted)")]
    UnsupportedFormat,
    #[error("the logo must be at most {LOGO_MAX_INPUT_SIDE} pixels wide and high")]
    TooManyPixels,
    #[error("the logo could not be read as an image")]
    Unreadable,
}

impl LogoError {
    pub fn code(&self) -> &'static str {
        match self {
            LogoError::TooLarge => "logo_too_large",
            LogoError::UnsupportedFormat => "unsupported_logo_format",
            LogoError::TooManyPixels => "logo_too_many_pixels",
            LogoError::Unreadable => "unreadable_logo",
        }
    }
}

/// The formats an upload may be in, by `Content-Type`.
pub fn upload_format(content_type: &str) -> Option<ImageFormat> {
    let mime = content_type.split(';').next()?.trim();
    if mime.eq_ignore_ascii_case("image/png") {
        Some(ImageFormat::Png)
    } else if mime.eq_ignore_ascii_case("image/jpeg") {
        Some(ImageFormat::Jpeg)
    } else if mime.eq_ignore_ascii_case("image/webp") {
        Some(ImageFormat::WebP)
    } else {
        None
    }
}

/// Decode an uploaded logo and re-encode it as a PNG of at most
/// [`LOGO_MAX_SIDE`] pixels. The format is read from the bytes themselves,
/// never from a name or a header, and must be PNG, JPEG or WebP. CPU-bound:
/// call it from a blocking task.
pub fn reencode_logo(bytes: &[u8]) -> Result<Logo, LogoError> {
    if bytes.len() > LOGO_MAX_UPLOAD_BYTES {
        return Err(LogoError::TooLarge);
    }
    let format = image::guess_format(bytes).map_err(|_| LogoError::UnsupportedFormat)?;
    if !matches!(
        format,
        ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP
    ) {
        return Err(LogoError::UnsupportedFormat);
    }
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(LOGO_MAX_INPUT_SIDE);
    limits.max_image_height = Some(LOGO_MAX_INPUT_SIDE);
    limits.max_alloc = Some(LOGO_MAX_DECODE_BYTES);
    reader.limits(limits);
    let img = reader.decode().map_err(|e| match e {
        image::ImageError::Limits(_) => LogoError::TooManyPixels,
        _ => LogoError::Unreadable,
    })?;
    if img.width() == 0 || img.height() == 0 {
        return Err(LogoError::Unreadable);
    }
    let img = if img.width() > LOGO_MAX_SIDE || img.height() > LOGO_MAX_SIDE {
        img.resize(
            LOGO_MAX_SIDE,
            LOGO_MAX_SIDE,
            image::imageops::FilterType::Lanczos3,
        )
    } else {
        img
    };
    // Plain 8-bit RGBA pixels: no colour profile, no text chunks, no EXIF.
    let rgba = img.to_rgba8();
    let (width, height) = rgba.dimensions();
    let mut png = Vec::new();
    PngEncoder::new_with_quality(&mut png, CompressionType::Best, FilterType::Adaptive)
        .write_image(
            rgba.as_raw(),
            width,
            height,
            image::ExtendedColorType::Rgba8,
        )
        .map_err(|_| LogoError::Unreadable)?;
    let hash = blake3::hash(&png);
    let id = hash.to_hex()[..32].to_owned();
    Ok(Logo {
        png,
        width,
        height,
        id,
    })
}

/// Whether `id` looks like a [`Logo::id`] (32 lowercase hex characters).
pub fn is_logo_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba, RgbaImage};

    fn encode(img: &RgbaImage, format: ImageFormat) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        match format {
            ImageFormat::Jpeg => image::DynamicImage::ImageRgba8(img.clone())
                .to_rgb8()
                .write_to(&mut out, format)
                .unwrap(),
            _ => img.write_to(&mut out, format).unwrap(),
        }
        out.into_inner()
    }

    fn logo(w: u32, h: u32) -> RgbaImage {
        ImageBuffer::from_fn(w, h, |x, y| {
            Rgba([(x % 256) as u8, (y % 256) as u8, 128, 255])
        })
    }

    #[test]
    fn png_is_reencoded_and_scaled_down() {
        let out = reencode_logo(&encode(&logo(1000, 250), ImageFormat::Png)).unwrap();
        assert_eq!((out.width, out.height), (512, 128));
        assert_eq!(image::guess_format(&out.png).unwrap(), ImageFormat::Png);
        let back = image::load_from_memory(&out.png).unwrap();
        assert_eq!((back.width(), back.height()), (512, 128));
        assert!(is_logo_id(&out.id));
        // Small logos keep their size.
        let small = reencode_logo(&encode(&logo(40, 20), ImageFormat::Png)).unwrap();
        assert_eq!((small.width, small.height), (40, 20));
    }

    #[test]
    fn jpeg_and_webp_are_accepted_and_become_png() {
        // image's WebP encoder writes lossless WebP; the decoder reads both.
        for format in [ImageFormat::Jpeg, ImageFormat::WebP] {
            let out = reencode_logo(&encode(&logo(64, 32), format)).unwrap();
            assert_eq!(image::guess_format(&out.png).unwrap(), ImageFormat::Png);
            assert_eq!((out.width, out.height), (64, 32), "{format:?}");
        }
    }

    #[test]
    fn svg_and_other_formats_are_refused() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
        let with_decl = br#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>"#;
        // Headers of formats this server has no decoder for.
        let gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;";
        let bmp = b"BM\x3a\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00";
        let html = b"<html><script></script></html>";
        for bad in [&svg[..], &with_decl[..], &gif[..], &bmp[..], &html[..]] {
            assert_eq!(reencode_logo(bad), Err(LogoError::UnsupportedFormat));
        }
        // And by Content-Type.
        for ct in [
            "image/svg+xml",
            "image/gif",
            "text/html",
            "application/octet-stream",
        ] {
            assert_eq!(upload_format(ct), None, "{ct}");
        }
        assert_eq!(upload_format("image/png"), Some(ImageFormat::Png));
        assert_eq!(upload_format("Image/JPEG; x=y"), Some(ImageFormat::Jpeg));
        assert_eq!(upload_format("image/webp"), Some(ImageFormat::WebP));
    }

    #[test]
    fn broken_huge_and_oversized_uploads_are_refused() {
        // A PNG signature followed by junk.
        let mut junk = b"\x89PNG\r\n\x1a\n".to_vec();
        junk.extend_from_slice(&[0u8; 64]);
        assert_eq!(reencode_logo(&junk), Err(LogoError::Unreadable));
        // Too many pixels: refused from the header, before decoding.
        let wide = encode(
            &ImageBuffer::from_pixel(5000, 1, Rgba([0, 0, 0, 0])),
            ImageFormat::Png,
        );
        assert!(wide.len() < LOGO_MAX_UPLOAD_BYTES);
        assert_eq!(reencode_logo(&wide), Err(LogoError::TooManyPixels));
        // Too many bytes.
        let mut big = encode(&logo(8, 8), ImageFormat::Png);
        big.resize(LOGO_MAX_UPLOAD_BYTES + 1, 0);
        assert_eq!(reencode_logo(&big), Err(LogoError::TooLarge));
    }

    #[test]
    fn metadata_and_trailing_data_are_dropped() {
        // A PNG with a text chunk before its image data and a script after
        // its end.
        let png = encode(&logo(16, 16), ImageFormat::Png);
        let marker = b"SECRET-METADATA";
        let mut chunk = Vec::new();
        let data = [b"Comment\0".as_slice(), marker].concat();
        chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let body = [b"tEXt".as_slice(), &data].concat();
        chunk.extend_from_slice(&body);
        chunk.extend_from_slice(&crc32(&body).to_be_bytes());
        // Insert after the IHDR chunk (8-byte signature + 25-byte IHDR).
        let mut tagged = png[..33].to_vec();
        tagged.extend_from_slice(&chunk);
        tagged.extend_from_slice(&png[33..]);
        tagged.extend_from_slice(b"<script>alert(1)</script>");
        assert!(
            image::load_from_memory(&tagged).is_ok(),
            "test PNG is valid"
        );
        let out = reencode_logo(&tagged).unwrap();
        let has = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        assert!(!has(&out.png, marker));
        assert!(!has(&out.png, b"tEXt"));
        assert!(!has(&out.png, b"script"));
        // A different image has a different id.
        let other = reencode_logo(&encode(&logo(17, 16), ImageFormat::Png)).unwrap();
        assert_ne!(out.id, other.id);
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn operator_text_is_one_short_plain_line() {
        assert!(check_plain_text("Welcome to St. Mark's <3 & friends", 200).is_ok());
        assert!(check_plain_text(&"a".repeat(200), 200).is_ok());
        assert!(check_plain_text(&"a".repeat(201), 200).is_err());
        assert!(
            check_plain_text(&"é".repeat(200), 200).is_ok(),
            "counts characters"
        );
        for bad in [
            "two\nlines",
            "carriage\rreturn",
            "tab\there",
            "nul\0",
            "esc\u{1b}[31m",
            "rtl \u{202E}gnp.exe",
            "isolate \u{2066}x\u{2069}",
            "zero\u{200B}width",
            "bom\u{FEFF}",
            "line\u{2028}separator",
            "tag\u{E0041}",
        ] {
            assert!(check_plain_text(bad, 200).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn support_contact_is_an_email_or_https_url_only() {
        assert_eq!(
            SupportContact::parse("help@church.example"),
            Ok(SupportContact::Email("help@church.example".into()))
        );
        assert_eq!(
            SupportContact::parse(" HTTPS://church.example/help?x=1 "),
            Ok(SupportContact::Url(
                "https://church.example/help?x=1".into()
            ))
        );
        for bad in [
            "javascript:alert(1)",
            "JavaScript:alert(1)//@x.org",
            "data:text/html,<script>alert(1)</script>",
            "http://church.example",
            "mailto:help@church.example",
            "https://",
            "https:///path",
            "https://user@evil.example",
            "https://a b.example",
            "https://church.example/\"onmouseover=x",
            "help@church",
            "@church.example",
            "help@church.example?subject=x",
            "two words@x.org",
            "help@church.example\nBcc: x@y.org",
            "//evil.example",
            "",
        ] {
            assert!(SupportContact::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn settings_validate_on_every_change() {
        let s = BrandingSettings::default();
        let on_but_empty = BrandingPatch {
            welcome_enabled: Some(true),
            ..BrandingPatch::default()
        };
        assert!(matches!(
            s.apply(&on_but_empty),
            Err(BrandingError::InvalidWelcome(_))
        ));
        let draft = BrandingPatch {
            welcome: Some("  Hello  ".into()),
            ..BrandingPatch::default()
        };
        let s2 = s.apply(&draft).unwrap();
        assert_eq!(s2.welcome, "Hello");
        assert!(!s2.welcome_enabled, "a draft stays off");
        let bad_draft = BrandingPatch {
            support: Some("javascript:alert(1)".into()),
            ..BrandingPatch::default()
        };
        assert!(matches!(
            s.apply(&bad_draft),
            Err(BrandingError::InvalidSupport(_))
        ));
        assert_eq!(
            BrandingSettings::from_json(&s2.to_json()).unwrap(),
            s2,
            "roundtrip"
        );
        assert_eq!(BrandingSettings::from_json("").unwrap(), s);
    }
}
