//! The labelled test set on disk, and turning its PNG files into frames.
//!
//! Layout (see the [module docs](super) and DEVELOPMENT.md):
//!
//! ```text
//! <set>/
//!   explicit/      *.png, any depth
//!   suggestive/
//!   neutral/
//!   <other label>/ optional, one folder per policy `other_labels` entry
//! ```
//!
//! Only paths are listed up front; each image is read, decoded, classified
//! and destroyed one at a time by [`super::run`].

use crate::error::DetectError;
use crate::scratch::Scratch;
use faro_platform::{Frame, PixelFormat};
use image::codecs::png::PngDecoder;
use image::ImageDecoder;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// Largest image file accepted.
const MAX_FILE_BYTES: u64 = 256 << 20;
/// Largest image side accepted (the `Frame` limit).
const MAX_SIDE: u32 = 16_384;
/// Largest decoded image accepted, in bytes.
const MAX_DECODED_BYTES: u64 = 512 << 20;
/// Deepest folder nesting followed inside a class folder.
const MAX_DEPTH: usize = 8;

/// One image of the set: its true class and where it is. Never its pixels.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvalImage {
    pub class: String,
    /// Path relative to the set root, for error messages.
    pub relative: PathBuf,
    path: PathBuf,
}

impl EvalImage {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A labelled test set: the list of image paths, sorted by class and path.
#[derive(Debug, Clone)]
pub struct EvalSet {
    root: PathBuf,
    images: Vec<EvalImage>,
}

fn bench_err(m: impl Into<String>) -> DetectError {
    DetectError::Bench(m.into())
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> DetectError + '_ {
    move |source| DetectError::Io {
        path: path.to_owned(),
        source,
    }
}

fn is_hidden(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().starts_with('.')
}

impl EvalSet {
    /// List the set at `root`. Every non-hidden folder at the top level must
    /// be named after one of `classes` and hold at least one image; inside
    /// them, every non-hidden file must be a `.png`. Files at the top level
    /// are ignored (for the curator's own notes); hidden files and folders
    /// (`.DS_Store`) are skipped everywhere.
    pub fn open(root: impl AsRef<Path>, classes: &[String]) -> Result<Self, DetectError> {
        let root = root.as_ref();
        let mut images = Vec::new();
        for entry in std::fs::read_dir(root).map_err(io_err(root))? {
            let entry = entry.map_err(io_err(root))?;
            let name = entry.file_name();
            if is_hidden(&name)
                || !std::fs::metadata(entry.path())
                    .map_err(io_err(root))?
                    .is_dir()
            {
                continue;
            }
            let class = name
                .to_str()
                .filter(|n| classes.iter().any(|c| c == n))
                .ok_or_else(|| {
                    bench_err(format!(
                        "folder {:?} is not a class; expected one of {}",
                        name,
                        classes.join(", ")
                    ))
                })?
                .to_owned();
            let before = images.len();
            collect(root, &entry.path(), &class, 0, &mut images)?;
            if images.len() == before {
                return Err(bench_err(format!("class folder {class:?} has no images")));
            }
        }
        if images.is_empty() {
            return Err(bench_err(format!(
                "{} has no class folders",
                root.display()
            )));
        }
        images.sort();
        Ok(EvalSet {
            root: root.to_owned(),
            images,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn images(&self) -> &[EvalImage] {
        &self.images
    }

    pub fn len(&self) -> usize {
        self.images.len()
    }

    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    /// Number of images per class.
    pub fn class_counts(&self) -> BTreeMap<&str, usize> {
        let mut out = BTreeMap::new();
        for i in &self.images {
            *out.entry(i.class.as_str()).or_default() += 1;
        }
        out
    }
}

fn collect(
    root: &Path,
    dir: &Path,
    class: &str,
    depth: usize,
    out: &mut Vec<EvalImage>,
) -> Result<(), DetectError> {
    if depth > MAX_DEPTH {
        return Err(bench_err(format!(
            "{} is nested more than {MAX_DEPTH} folders deep",
            dir.display()
        )));
    }
    for entry in std::fs::read_dir(dir).map_err(io_err(dir))? {
        let entry = entry.map_err(io_err(dir))?;
        let path = entry.path();
        if is_hidden(&entry.file_name()) {
            continue;
        }
        let relative = path.strip_prefix(root).unwrap_or(&path).to_owned();
        // Symlinked files are followed (the set may live on another
        // volume); symlinked folders are not, so a loop can't trap us.
        let ty = entry.file_type().map_err(io_err(&path))?;
        if ty.is_dir() {
            collect(root, &path, class, depth + 1, out)?;
            continue;
        }
        if !std::fs::metadata(&path).map_err(io_err(&path))?.is_file() {
            return Err(bench_err(format!(
                "{} is not a regular file",
                relative.display()
            )));
        }
        let png = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("png"));
        if !png {
            return Err(bench_err(format!(
                "{} is not a .png (convert it first, see DEVELOPMENT.md)",
                relative.display()
            )));
        }
        out.push(EvalImage {
            class: class.to_owned(),
            relative,
            path,
        });
    }
    Ok(())
}

/// A pixel buffer that will become a frame's. In unit tests it registers
/// with the privacy audit, which checks it is zeroed when freed.
fn pixel_buffer(len: usize) -> Zeroizing<Vec<u8>> {
    let v = vec![0u8; len];
    #[cfg(test)]
    if len > 0 {
        crate::privacy_tests::audit::watch(v.as_ptr(), v.len());
    }
    Zeroizing::new(v)
}

/// Read a PNG file into an RGBA [`Frame`], the type every production frame
/// arrives in, and return the BLAKE3 hash of the file's bytes with it.
///
/// The compressed bytes and any intermediate decode buffer are
/// zeroize-on-drop scratch buffers allocated at their final size; the RGBA
/// buffer belongs to the frame, which zeroizes it on drop. Nothing is
/// written anywhere. Known limitation, as with ONNX Runtime's arena: the
/// PNG decoder's own small internal buffers (inflate window, current
/// scanline) are freed without being zeroized.
pub fn read_frame(path: &Path) -> Result<(Frame, blake3::Hash), DetectError> {
    let io = io_err(path);
    let mut file = std::fs::File::open(path).map_err(io)?;
    let len = file.metadata().map_err(io_err(path))?.len();
    if len > MAX_FILE_BYTES {
        return Err(bench_err(format!(
            "{} is over the {MAX_FILE_BYTES}-byte limit",
            path.display()
        )));
    }
    let mut raw: Scratch<u8> = Scratch::zeroed(usize::try_from(len).unwrap_or(usize::MAX));
    file.read_exact(&mut raw).map_err(io_err(path))?;
    let mut probe = [0u8; 1];
    let grew = file.read(&mut probe).map_err(io_err(path))? != 0;
    probe.zeroize();
    if grew {
        return Err(bench_err(format!(
            "{} changed while it was read",
            path.display()
        )));
    }
    let hash = blake3::hash(&raw);
    let frame = decode_png(&raw).map_err(|e| bench_err(format!("{}: {e}", path.display())))?;
    Ok((frame, hash))
}

/// Decode PNG bytes into an RGBA frame (8- or 16-bit grey, grey+alpha, RGB
/// or RGBA; palette images are expanded by the decoder).
pub(crate) fn decode_png(bytes: &[u8]) -> Result<Frame, String> {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(MAX_DECODED_BYTES);
    let decoder =
        PngDecoder::with_limits(std::io::Cursor::new(bytes), limits).map_err(|e| e.to_string())?;
    let (w, h) = decoder.dimensions();
    let color = decoder.color_type();
    let total = usize::try_from(decoder.total_bytes()).map_err(|_| "image too large")?;
    let pixels = w as usize * h as usize;
    let channels = usize::from(color.channel_count());
    let depth = usize::from(color.bytes_per_pixel()) / channels.max(1);
    if !(1..=4).contains(&channels) || !(depth == 1 || depth == 2) {
        return Err(format!("unsupported colour type {color:?}"));
    }

    let mut rgba = pixel_buffer(pixels * 4);
    if channels == 4 && depth == 1 {
        // Already RGBA8: decode straight into the frame's buffer.
        decoder.read_image(&mut rgba).map_err(|e| e.to_string())?;
    } else {
        let mut buf: Scratch<u8> = Scratch::zeroed(total);
        decoder.read_image(&mut buf).map_err(|e| e.to_string())?;
        // 16-bit samples are native-endian; keep the high byte.
        let sample = |px: &[u8], c: usize| -> u8 {
            if depth == 1 {
                px[c]
            } else {
                (u16::from_ne_bytes([px[2 * c], px[2 * c + 1]]) >> 8) as u8
            }
        };
        for (px, out) in buf
            .chunks_exact(channels * depth)
            .zip(rgba.as_chunks_mut::<4>().0)
        {
            let rgba_px = match channels {
                1 => {
                    let v = sample(px, 0);
                    [v, v, v, 255]
                }
                2 => {
                    let v = sample(px, 0);
                    [v, v, v, sample(px, 1)]
                }
                3 => [sample(px, 0), sample(px, 1), sample(px, 2), 255],
                _ => [sample(px, 0), sample(px, 1), sample(px, 2), sample(px, 3)],
            };
            *out = rgba_px;
        }
    }
    Frame::new(w, h, PixelFormat::Rgba8, 0, std::mem::take(&mut *rgba)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32, color: image::ExtendedColorType, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        image::ImageEncoder::write_image(
            image::codecs::png::PngEncoder::new(&mut out),
            data,
            w,
            h,
            color,
        )
        .unwrap();
        out
    }

    fn first_px(f: &Frame) -> [u8; 4] {
        f.pixels()[..4].try_into().unwrap()
    }

    #[test]
    fn decodes_every_png_colour_type_to_rgba() {
        use image::ExtendedColorType as C;
        let cases: [(C, Vec<u8>, [u8; 4]); 6] = [
            (C::Rgba8, [1, 2, 3, 4].repeat(6), [1, 2, 3, 4]),
            (C::Rgb8, [10, 20, 30].repeat(6), [10, 20, 30, 255]),
            (C::L8, [77].repeat(6), [77, 77, 77, 255]),
            (C::La8, [77, 9].repeat(6), [77, 77, 77, 9]),
            (
                C::Rgb16,
                [0x1234u16, 0xABCD, 0xFF00]
                    .iter()
                    .flat_map(|v| v.to_ne_bytes())
                    .collect::<Vec<_>>()
                    .repeat(6),
                [0x12, 0xAB, 0xFF, 255],
            ),
            (
                C::Rgba16,
                [0x0100u16, 0x0200, 0x0300, 0x8000]
                    .iter()
                    .flat_map(|v| v.to_ne_bytes())
                    .collect::<Vec<_>>()
                    .repeat(6),
                [1, 2, 3, 0x80],
            ),
        ];
        for (color, data, want) in cases {
            let f = decode_png(&png(3, 2, color, &data)).unwrap();
            assert_eq!(
                (f.width(), f.height(), f.format()),
                (3, 2, PixelFormat::Rgba8)
            );
            assert_eq!(first_px(&f), want, "{color:?}");
            assert!(f.pixels().as_chunks::<4>().0.iter().all(|p| *p == want));
        }
        assert!(decode_png(b"not a png").is_err());
        let ok = png(3, 2, C::L8, &[0; 6]);
        assert!(decode_png(&ok[..ok.len() - 20]).is_err());
    }

    fn touch(p: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn classes() -> Vec<String> {
        ["explicit", "neutral", "suggestive"]
            .map(String::from)
            .to_vec()
    }

    #[test]
    fn layout_rules() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        touch(&r.join("NOTES.txt"), b"ignored");
        touch(&r.join(".DS_Store"), b"ignored");
        touch(&r.join("neutral/b.png"), b"");
        touch(&r.join("neutral/a.PNG"), b"");
        touch(&r.join("neutral/.DS_Store"), b"");
        touch(&r.join("explicit/site/x.png"), b"");
        let set = EvalSet::open(r, &classes()).unwrap();
        let listed: Vec<_> = set
            .images()
            .iter()
            .map(|i| (i.class.as_str(), i.relative.to_string_lossy().into_owned()))
            .collect();
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(
            listed,
            [
                ("explicit", format!("explicit{sep}site{sep}x.png")),
                ("neutral", format!("neutral{sep}a.PNG")),
                ("neutral", format!("neutral{sep}b.png")),
            ]
        );
        assert_eq!(
            set.class_counts(),
            BTreeMap::from([("explicit", 1), ("neutral", 2)])
        );

        // A typo in a class name is an error, not a silently empty class.
        touch(&r.join("explict/y.png"), b"");
        assert!(matches!(
            EvalSet::open(r, &classes()),
            Err(DetectError::Bench(_))
        ));
        std::fs::remove_dir_all(r.join("explict")).unwrap();
        // So is a JPEG, and an empty class folder.
        touch(&r.join("suggestive/z.jpg"), b"");
        assert!(EvalSet::open(r, &classes()).is_err());
        std::fs::remove_file(r.join("suggestive/z.jpg")).unwrap();
        assert!(EvalSet::open(r, &classes()).is_err());
        std::fs::remove_dir(r.join("suggestive")).unwrap();
        assert!(EvalSet::open(r, &classes()).is_ok());

        let empty = tempfile::tempdir().unwrap();
        assert!(EvalSet::open(empty.path(), &classes()).is_err());
        assert!(matches!(
            EvalSet::open(r.join("missing"), &classes()),
            Err(DetectError::Io { .. })
        ));
    }

    #[test]
    fn read_frame_hashes_the_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.png");
        let bytes = png(2, 2, image::ExtendedColorType::Rgb8, &[5; 12]);
        std::fs::write(&p, &bytes).unwrap();
        let (f, h) = read_frame(&p).unwrap();
        assert_eq!(h, blake3::hash(&bytes));
        assert_eq!(first_px(&f), [5, 5, 5, 255]);
        std::fs::write(&p, b"junk").unwrap();
        assert!(matches!(read_frame(&p), Err(DetectError::Bench(_))));
    }
}
