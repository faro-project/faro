//! Target selection (channels, `stable-1`, no-downgrade) and streaming
//! artifact verification.

mod common;

use common::*;
use faro_proto::Hash32;
use faro_update::{
    copy_verified_target, verify_target_stream, Channel, Selection, StreamError, TargetFile,
    TargetInfo, TargetKind, Targets, VerifiedTargets, Version,
};
use std::io::{self, Read};

fn verified(entries: Vec<(&str, TargetFile)>) -> VerifiedTargets {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let t: Targets = targets_meta(1, T0 + DAY, entries);
    let tb = sign_targets(&t, &keys.targets);
    let ts = sign_ts(&timestamp_for(1, T0 + DAY, &tb, 1), &keys.timestamp);
    up.verify_timestamp(&ts, T0).unwrap();
    up.verify_targets(&tb, T0).unwrap()
}

fn client(v: &str, channels: &[&str]) -> TargetFile {
    target(
        TargetKind::Client,
        "macos",
        "aarch64",
        v,
        channels,
        v.as_bytes(),
    )
}

fn v(s: &str) -> Version {
    Version::parse(s).unwrap()
}

fn pick(vt: &VerifiedTargets, ch: &str, current: Option<&str>) -> Option<String> {
    let cur = current.map(v);
    vt.select(
        &ch.parse::<Channel>().unwrap(),
        TargetKind::Client,
        "macos",
        "aarch64",
        cur.as_ref(),
    )
    .map(|t| t.custom.version.to_string())
}

fn catalog() -> VerifiedTargets {
    verified(vec![
        ("c-1.8.0", client("1.8.0", &["stable"])),
        ("c-1.8.4", client("1.8.4", &["stable"])),
        ("c-1.9.0", client("1.9.0", &["stable"])),
        ("c-1.9.2", client("1.9.2", &["stable", "beta"])),
        ("c-1.10.1", client("1.10.1", &["stable", "beta"])),
        ("c-1.11.0-beta.2", client("1.11.0-beta.2", &["beta"])),
        // Other platforms/kinds must never be picked for macos/aarch64 client.
        (
            "c-9.9.9-win",
            target(
                TargetKind::Client,
                "windows",
                "x86_64",
                "9.9.9",
                &["stable"],
                b"w",
            ),
        ),
        (
            "c-9.9.9-x86",
            target(
                TargetKind::Client,
                "macos",
                "x86_64",
                "9.9.9",
                &["stable"],
                b"x",
            ),
        ),
        (
            "s-9.9.9",
            target(
                TargetKind::Server,
                "macos",
                "aarch64",
                "9.9.9",
                &["stable"],
                b"s",
            ),
        ),
    ])
}

// --------------------------------------------------------------- selection

#[test]
fn named_channels_pick_highest_semver() {
    let vt = catalog();
    // Semver, not lexicographic: 1.10.1 > 1.9.2.
    assert_eq!(pick(&vt, "stable", None).as_deref(), Some("1.10.1"));
    assert_eq!(pick(&vt, "beta", None).as_deref(), Some("1.11.0-beta.2"));
    assert_eq!(pick(&vt, "nightly", None), None);
}

#[test]
fn stable_minus_one_is_previous_minor_line() {
    let vt = catalog();
    // Newest stable line is 1.10; one below is 1.9, newest there is 1.9.2.
    assert_eq!(pick(&vt, "stable-1", None).as_deref(), Some("1.9.2"));
    // Beta-only releases don't move the stable line.
    assert_eq!(
        pick(&vt, "stable-1", Some("1.9.0")).as_deref(),
        Some("1.9.2")
    );
}

#[test]
fn stable_minus_one_across_major_bump() {
    let vt = verified(vec![
        ("a", client("1.8.3", &["stable"])),
        ("b", client("1.9.7", &["stable"])),
        ("c", client("1.9.1", &["stable"])),
        ("d", client("2.0.1", &["stable"])),
        ("e", client("2.0.0", &["stable"])),
    ]);
    assert_eq!(pick(&vt, "stable-1", None).as_deref(), Some("1.9.7"));
    assert_eq!(pick(&vt, "stable", None).as_deref(), Some("2.0.1"));
}

#[test]
fn stable_minus_one_with_single_line_selects_nothing() {
    let vt = verified(vec![
        ("a", client("3.0.0", &["stable"])),
        ("b", client("3.0.5", &["stable"])),
        ("c", client("2.9.0", &["beta"])),
    ]);
    // Never falls through to the newest release.
    assert_eq!(pick(&vt, "stable-1", None), None);
}

#[test]
fn never_downgrade_or_reinstall_by_default() {
    let vt = catalog();
    assert_eq!(pick(&vt, "stable", Some("1.10.1")), None);
    assert_eq!(
        pick(&vt, "stable", Some("1.10.0")).as_deref(),
        Some("1.10.1")
    );
    assert_eq!(pick(&vt, "stable", Some("1.12.0")), None);
    // Pinning a fleet already on 1.10 to stable-1 holds it there.
    assert_eq!(pick(&vt, "stable-1", Some("1.10.1")), None);
    // A pre-release install is older than its release.
    let vt2 = verified(vec![("a", client("2.0.0", &["stable"]))]);
    assert_eq!(
        pick(&vt2, "stable", Some("2.0.0-rc.1")).as_deref(),
        Some("2.0.0")
    );
}

#[test]
fn allow_downgrade_permits_lower_but_not_equal() {
    let vt = catalog();
    let ch: Channel = "stable-1".parse().unwrap();
    let cur = v("1.10.1");
    let mut q = Selection {
        channel: &ch,
        kind: TargetKind::Client,
        platform: "macos",
        arch: "aarch64",
        current_version: Some(&cur),
        os_version: None,
        allow_downgrade: true,
    };
    assert_eq!(
        vt.select_with(&q).map(|t| t.custom.version),
        Some(v("1.9.2"))
    );
    let same = v("1.9.2");
    q.current_version = Some(&same);
    assert_eq!(vt.select_with(&q), None);
}

#[test]
fn platform_arch_kind_and_any_matching() {
    let vt = verified(vec![
        (
            "model-1",
            target(TargetKind::Model, "any", "any", "1.0.0", &["stable"], b"m1"),
        ),
        (
            "model-2-linux",
            target(
                TargetKind::Model,
                "linux",
                "any",
                "2.0.0",
                &["stable"],
                b"m2",
            ),
        ),
        (
            "bl-1",
            target(
                TargetKind::Blocklist,
                "any",
                "any",
                "5.0.0",
                &["stable"],
                b"b",
            ),
        ),
    ]);
    let st = Channel::stable();
    let m = |p: &str, a: &str| {
        vt.select(&st, TargetKind::Model, p, a, None)
            .map(|t| t.name)
    };
    assert_eq!(m("macos", "aarch64").as_deref(), Some("model-1"));
    assert_eq!(m("linux", "x86_64").as_deref(), Some("model-2-linux"));
    assert_eq!(
        vt.select(&st, TargetKind::Client, "macos", "aarch64", None),
        None
    );
}

#[test]
fn min_os_filters_when_os_version_known() {
    let mut new = client("2.0.0", &["stable"]);
    new.custom.min_os = Some("14".into());
    let vt = verified(vec![("old", client("1.5.0", &["stable"])), ("new", new)]);
    let ch = Channel::stable();
    let q = |os: Option<&Version>| {
        vt.select_with(&Selection {
            channel: &ch,
            kind: TargetKind::Client,
            platform: "macos",
            arch: "aarch64",
            current_version: None,
            os_version: os,
            allow_downgrade: false,
        })
        .map(|t| t.custom.version.to_string())
    };
    assert_eq!(q(Some(&v("13.6.1"))).as_deref(), Some("1.5.0"));
    assert_eq!(q(Some(&v("14.0.0"))).as_deref(), Some("2.0.0"));
    assert_eq!(q(None).as_deref(), Some("2.0.0"));
}

#[test]
fn channel_parsing() {
    assert_eq!("stable".parse::<Channel>().unwrap(), Channel::stable());
    assert_eq!(
        "stable-1".parse::<Channel>().unwrap(),
        Channel::StableMinusOne
    );
    for bad in ["", "beta-1", "Stable", "stable-2", "../x"] {
        assert!(bad.parse::<Channel>().is_err(), "{bad}");
    }
    assert_eq!(Channel::StableMinusOne.to_string(), "stable-1");
}

// ------------------------------------------------------------------ stream

fn info(content: &[u8]) -> TargetInfo {
    TargetInfo {
        name: "t".into(),
        length: content.len() as u64,
        blake3: Hash32::of(content),
        custom: client("1.0.0", &["stable"]).custom,
    }
}

/// Yields data a few bytes at a time and interleaves `Interrupted` errors,
/// like a flaky network socket.
struct Trickle<'a> {
    data: &'a [u8],
    interrupt_next: bool,
}

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.interrupt_next = !self.interrupt_next;
        if self.interrupt_next {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = buf.len().min(3).min(self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

/// An endless stream: the cap must stop us, not EOF.
struct Endless;

impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        buf.fill(b'A');
        Ok(buf.len())
    }
}

#[test]
fn stream_exact_ok_including_trickle_and_empty() {
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    verify_target_stream(&data[..], &info(&data), data.len() as u64).unwrap();
    verify_target_stream(
        Trickle {
            data: &data[..1000],
            interrupt_next: false,
        },
        &info(&data[..1000]),
        u64::MAX,
    )
    .unwrap();
    verify_target_stream(&b""[..], &info(b""), 0).unwrap();
}

#[test]
fn stream_overrun_underrun_and_hash_mismatch() {
    let good = b"the real installer bytes".to_vec();
    let i = info(&good);

    let mut long = good.clone();
    long.push(0);
    assert!(matches!(
        verify_target_stream(&long[..], &i, 1 << 20),
        Err(StreamError::TooLong { .. })
    ));
    assert!(matches!(
        verify_target_stream(Endless, &i, 1 << 20),
        Err(StreamError::TooLong { .. })
    ));
    assert!(matches!(
        verify_target_stream(&good[..good.len() - 1], &i, 1 << 20),
        Err(StreamError::TooShort { got, expected, .. }) if got + 1 == expected
    ));
    let mut evil = good.clone();
    evil[0] ^= 0x80;
    assert!(matches!(
        verify_target_stream(&evil[..], &i, 1 << 20),
        Err(StreamError::HashMismatch { .. })
    ));
}

#[test]
fn stream_cap_checked_before_reading() {
    struct MustNotRead;
    impl Read for MustNotRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("read despite length over cap");
        }
    }
    let i = info(b"0123456789");
    assert!(matches!(
        verify_target_stream(MustNotRead, &i, 9),
        Err(StreamError::ExceedsCap {
            length: 10,
            max_len: 9,
            ..
        })
    ));
}

#[test]
fn copy_never_writes_past_signed_length() {
    let good = b"abcdefgh".to_vec();
    let i = info(&good);
    let mut out = Vec::new();
    copy_verified_target(&good[..], &mut out, &i, 100).unwrap();
    assert_eq!(out, good);

    let mut out = Vec::new();
    let r = copy_verified_target(Endless, &mut out, &i, 100);
    assert!(matches!(r, Err(StreamError::TooLong { .. })));
    assert!(out.len() as u64 <= i.length);
}

#[test]
fn stream_propagates_io_errors() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("connection reset"))
        }
    }
    assert!(matches!(
        verify_target_stream(Broken, &info(b"x"), 10),
        Err(StreamError::Io(_))
    ));
}

#[test]
fn stream_rejects_lying_reader() {
    // Claims to have read more bytes than the buffer it was handed.
    struct Liar;
    impl Read for Liar {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            Ok(buf.len() + 1)
        }
    }
    assert!(matches!(
        verify_target_stream(Liar, &info(b"abc"), 10),
        Err(StreamError::Io(_))
    ));
}

#[test]
fn selected_target_verifies_against_its_content() {
    let vt = catalog();
    let t = vt
        .select(
            &Channel::stable(),
            TargetKind::Client,
            "macos",
            "aarch64",
            None,
        )
        .unwrap();
    // `client()` uses the version string as the artifact content.
    verify_target_stream(&b"1.10.1"[..], &t, 1 << 20).unwrap();
    assert!(verify_target_stream(&b"1.9.2"[..], &t, 1 << 20).is_err());
    assert_eq!(vt.get(&t.name), Some(t));
}

#[test]
fn incremental_verifier_matches_the_stream_rules() {
    use faro_update::TargetVerifier;
    let content = b"0123456789abcdef".repeat(10);
    let i = info(&content);

    // Any chunking of the right bytes passes.
    for size in [1, 7, 64, content.len()] {
        let mut v = TargetVerifier::new(&i, 1 << 20).unwrap();
        for chunk in content.chunks(size) {
            v.update(chunk).unwrap();
        }
        assert_eq!(v.remaining(), 0);
        v.finish().unwrap();
    }

    // A chunk past the signed length is refused before it counts.
    let mut v = TargetVerifier::new(&i, 1 << 20).unwrap();
    v.update(&content[..150]).unwrap();
    assert!(matches!(
        v.update(&content[..11]),
        Err(StreamError::TooLong { .. })
    ));
    assert_eq!(v.remaining(), 10, "the refused chunk was not counted");

    // Short, wrong bytes, and over the caller's cap.
    let mut v = TargetVerifier::new(&i, 1 << 20).unwrap();
    v.update(&content[..159]).unwrap();
    assert!(matches!(
        v.finish(),
        Err(StreamError::TooShort { got: 159, .. })
    ));
    let mut v = TargetVerifier::new(&i, 1 << 20).unwrap();
    let mut wrong = content.clone();
    wrong[0] ^= 1;
    v.update(&wrong).unwrap();
    assert!(matches!(v.finish(), Err(StreamError::HashMismatch { .. })));
    assert!(matches!(
        TargetVerifier::new(&i, 159),
        Err(StreamError::ExceedsCap { .. })
    ));
}
