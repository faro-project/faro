//! The detection pipeline (§3.5): frame in, [`DetectionOutcome`] out.
//!
//! ```text
//! Frame (by value) ─▶ downscale ≤ 768 ─▶ dHash ─▶ dedupe ─┬▶ reuse scores
//!                                                         └▶ classify
//!   context signals ─▶ findings ─────────────▶ fuse ◀───────┘
//!   rating ≥ thumbnail threshold ─▶ blurred thumbnail
//!   frame destroyed (zeroized) ─▶ DetectionOutcome
//! ```
//!
//! What the dedupe cache holds is the *classifier output* for the last
//! classified frame, not the whole outcome: context (URL, title) may change
//! while the pixels do not, and fusing again is cheap, so reused results are
//! always re-fused with the current context.

use crate::classifier::{Classifier, ImageScores, ModelInfo};
use crate::context::{ContextAnalyzer, ContextConfig, ContextSignals};
use crate::dhash::{dhash, DedupeDecision, Deduper, DEFAULT_DEDUPE_THRESHOLD};
use crate::domains::DomainCategorizer;
use crate::error::DetectError;
use crate::fusion::{PolicyConfig, PolicyEngine};
use crate::thumbnail::blur_thumbnail;
use faro_platform::{Frame, MAX_FRAME_SIDE};
use faro_proto::body::{BlurredThumbnail, Rating, Reason};
use serde::{Deserialize, Serialize};

/// Pipeline configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectorConfig {
    /// Max dHash Hamming distance that counts as "unchanged" (§3.4).
    pub dedupe_threshold: u32,
    /// Minimum rating for which a blurred thumbnail is produced. Must be at
    /// least `low`: Faro does not keep pictures of clean screens, blurred
    /// or not.
    pub thumbnail_min_rating: Rating,
    pub policy: PolicyConfig,
    pub context: ContextConfig,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        DetectorConfig {
            dedupe_threshold: DEFAULT_DEDUPE_THRESHOLD,
            thumbnail_min_rating: Rating::Medium,
            policy: PolicyConfig::default(),
            context: ContextConfig::default(),
        }
    }
}

/// The result of processing one frame: the only thing that leaves the
/// pipeline.
///
/// None of these fields can hold raw pixels: the rating, textual reasons, a
/// 64-bit perceptual hash, two flags, and a [`BlurredThumbnail`] that is only
/// ever produced by [`blur_thumbnail`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionOutcome {
    pub rating: Rating,
    /// Strongest first; non-empty whenever `rating > clean`.
    pub reasons: Vec<Reason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<BlurredThumbnail>,
    /// dHash of the frame (as classified, after any downscale).
    pub dhash: u64,
    /// The classifier result was reused from a near-identical earlier frame.
    pub reused: bool,
    /// Some score sits just below a rating-raising threshold; the scheduler
    /// should enter burst mode (§3.4).
    pub borderline: bool,
}

/// The on-device detector. One per service; `Send`, not `Sync` (classifiers
/// are stateful).
pub struct Detector {
    classifier: Box<dyn Classifier>,
    context: ContextAnalyzer,
    policy: PolicyEngine,
    dedupe: Deduper<ImageScores>,
    thumbnail_min_rating: Rating,
}

impl std::fmt::Debug for Detector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detector")
            .field("model", &self.classifier.info().name)
            .field("model_version", &self.classifier.info().version)
            .field("thumbnail_min_rating", &self.thumbnail_min_rating)
            .finish_non_exhaustive()
    }
}

impl Detector {
    pub fn new(
        config: &DetectorConfig,
        classifier: Box<dyn Classifier>,
        domains: Option<DomainCategorizer>,
    ) -> Result<Self, DetectError> {
        if config.thumbnail_min_rating < Rating::Low {
            return Err(DetectError::Config(
                "thumbnail_min_rating must be at least low".into(),
            ));
        }
        if config.dedupe_threshold > 32 {
            return Err(DetectError::Config(
                "dedupe_threshold above 32 would treat unrelated frames as unchanged".into(),
            ));
        }
        Ok(Detector {
            classifier,
            context: ContextAnalyzer::new(&config.context, domains)?,
            policy: PolicyEngine::new(config.policy.clone())?,
            dedupe: Deduper::new(config.dedupe_threshold),
            thumbnail_min_rating: config.thumbnail_min_rating,
        })
    }

    /// Run the pipeline on one frame. The frame is consumed and destroyed
    /// (zeroized) before this returns, on success and on every error path.
    pub fn process(
        &mut self,
        frame: Frame,
        signals: &ContextSignals,
    ) -> Result<DetectionOutcome, DetectError> {
        // The agent already downscales (§3.1); this bounds CPU if it didn't.
        let frame = frame.downscale_to_max(MAX_FRAME_SIDE);
        let display = frame.display_id();
        let hash = dhash(&frame);

        let (scores, reused) = match self.dedupe.check(display, hash) {
            DedupeDecision::Unchanged { previous, .. } => (previous, true),
            DedupeDecision::Changed => {
                // On error `frame` is dropped (and zeroized) by `?`.
                let s = self.classifier.classify(&frame)?;
                self.dedupe.record(display, hash, s.clone());
                (s, false)
            }
        };

        let findings = self.context.analyze(signals);
        let fused = self.policy.fuse(&scores, &findings);

        let thumbnail = if fused.rating >= self.thumbnail_min_rating {
            Some(blur_thumbnail(&frame)?)
        } else {
            None
        };
        frame.destroy();

        Ok(DetectionOutcome {
            rating: fused.rating,
            reasons: fused.reasons,
            thumbnail,
            dhash: hash,
            reused,
            borderline: fused.borderline,
        })
    }

    /// Swap the classifier (e.g. a new model arrived). Cached results came
    /// from the old model, so the dedupe cache is cleared.
    pub fn set_classifier(&mut self, classifier: Box<dyn Classifier>) {
        self.classifier = classifier;
        self.dedupe.clear();
    }

    /// Swap the domain bundle.
    pub fn set_domains(&mut self, domains: Option<DomainCategorizer>) {
        self.context.set_domains(domains);
    }

    /// Forget a display's cached result (e.g. it was disconnected).
    pub fn forget_display(&mut self, display_id: u32) {
        self.dedupe.forget(display_id);
    }

    pub fn model_info(&self) -> &ModelInfo {
        self.classifier.info()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::ScriptedClassifier;
    use crate::domains::{Category, DomainCategorizerBuilder};
    use faro_platform::PixelFormat;
    use faro_proto::body::{BrowserContext, ReasonSource};

    fn scores(v: &[(&str, f32)]) -> ImageScores {
        ImageScores::new(v.iter().map(|&(l, s)| (l, s))).unwrap()
    }

    fn frame(seed: u32, display: u32) -> Frame {
        let (w, h) = (128u32, 80u32);
        let mut px = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                // Large blocks whose brightness depends on the seed, so
                // different seeds give very different dHashes.
                let v = ((x / 16 + y / 10) * 37 + seed * 101) % 251;
                px.extend_from_slice(&[v as u8, (v / 2) as u8, 255 - v as u8, 255]);
            }
        }
        Frame::new(w, h, PixelFormat::Bgra8, display, px).unwrap()
    }

    /// Scripted classifier behind a shared handle so the test can inspect it
    /// after handing it to the detector.
    type Handle = std::sync::Arc<std::sync::Mutex<ScriptedClassifier>>;
    struct Shared {
        info: ModelInfo,
        inner: Handle,
    }
    impl Shared {
        fn boxed(inner: &Handle) -> Box<dyn Classifier> {
            let info = inner.lock().unwrap().info().clone();
            Box::new(Shared {
                info,
                inner: inner.clone(),
            })
        }
    }
    impl Classifier for Shared {
        fn info(&self) -> &ModelInfo {
            &self.info
        }
        fn classify(&mut self, f: &Frame) -> Result<ImageScores, DetectError> {
            self.inner.lock().unwrap().classify(f)
        }
    }

    fn detector(fallback: ImageScores) -> (Detector, Handle) {
        let c: Handle =
            std::sync::Arc::new(std::sync::Mutex::new(ScriptedClassifier::new(fallback)));
        let mut b = DomainCategorizerBuilder::new();
        b.add_domain("adult.test", Category::Adult).unwrap();
        let d = Detector::new(
            &DetectorConfig::default(),
            Shared::boxed(&c),
            Some(b.build().unwrap()),
        )
        .unwrap();
        (d, c)
    }

    #[test]
    fn clean_frame_has_no_thumbnail() {
        let (mut d, _) = detector(scores(&[("explicit", 0.05)]));
        let o = d.process(frame(1, 0), &ContextSignals::default()).unwrap();
        assert_eq!(o.rating, Rating::Clean);
        assert!(o.reasons.is_empty());
        assert!(o.thumbnail.is_none());
        assert!(!o.reused);
    }

    #[test]
    fn high_frame_gets_blurred_thumbnail() {
        let (mut d, _) = detector(scores(&[("explicit", 0.95)]));
        let o = d.process(frame(1, 0), &ContextSignals::default()).unwrap();
        assert_eq!(o.rating, Rating::High);
        assert_eq!(o.reasons[0].to_string(), "image:explicit 0.95");
        let t = o.thumbnail.unwrap();
        assert_eq!((t.width, t.height), (320, 200));
        assert_eq!(t.transform, "gauss12+pix8");
    }

    #[test]
    fn low_rating_has_no_thumbnail_by_default() {
        let (mut d, _) = detector(scores(&[("explicit", 0.45)]));
        let o = d.process(frame(1, 0), &ContextSignals::default()).unwrap();
        assert_eq!(o.rating, Rating::Low);
        assert!(o.thumbnail.is_none());
    }

    #[test]
    fn dedupe_reuses_scores_but_refuses_context() {
        let (mut d, c) = detector(scores(&[("explicit", 0.1)]));
        let o1 = d.process(frame(7, 0), &ContextSignals::default()).unwrap();
        assert!(!o1.reused);
        assert_eq!(o1.rating, Rating::Clean);

        // Same pixels, now on an adult domain: scores reused, context applied.
        let sig = ContextSignals {
            browser: Some(BrowserContext {
                url: Some("https://www.adult.test/".into()),
                title: None,
                incognito: false,
            }),
            ..Default::default()
        };
        let o2 = d.process(frame(7, 0), &sig).unwrap();
        assert!(o2.reused);
        assert_eq!(o2.dhash, o1.dhash);
        assert_eq!(o2.rating, Rating::Medium);
        assert_eq!(o2.reasons[0].source, ReasonSource::Domain);
        assert!(o2.thumbnail.is_some());
        assert_eq!(c.lock().unwrap().calls(), 1);

        // Different display: not reused.
        let o3 = d.process(frame(7, 1), &ContextSignals::default()).unwrap();
        assert!(!o3.reused);
        // Different content: classified again.
        let o4 = d.process(frame(8, 0), &ContextSignals::default()).unwrap();
        assert!(!o4.reused);
        assert_ne!(o4.dhash, o1.dhash);
        assert_eq!(c.lock().unwrap().calls(), 3);

        // Model swap clears the cache.
        d.set_classifier(Shared::boxed(&c));
        assert!(
            !d.process(frame(8, 0), &ContextSignals::default())
                .unwrap()
                .reused
        );
        assert_eq!(c.lock().unwrap().calls(), 4);
    }

    #[test]
    fn classifier_error_propagates_and_is_not_cached() {
        let (mut d, c) = detector(scores(&[("explicit", 0.1)]));
        c.lock().unwrap().push_error("model crashed");
        assert!(matches!(
            d.process(frame(3, 0), &ContextSignals::default()),
            Err(DetectError::Classifier(_))
        ));
        let o = d.process(frame(3, 0), &ContextSignals::default()).unwrap();
        assert!(!o.reused);
        assert_eq!(c.lock().unwrap().calls(), 2);
    }

    #[test]
    fn oversized_frames_are_downscaled_before_classification() {
        let (mut d, c) = detector(scores(&[]));
        let f = Frame::new(1536, 960, PixelFormat::Rgba8, 0, vec![128; 1536 * 960 * 4]).unwrap();
        d.process(f, &ContextSignals::default()).unwrap();
        assert_eq!(c.lock().unwrap().seen_dimensions(), &[(768, 480)]);
    }

    #[test]
    fn config_validation() {
        let mk = |cfg: DetectorConfig| {
            Detector::new(
                &cfg,
                Box::new(crate::classifier::NullClassifier::new()),
                None,
            )
        };
        assert!(mk(DetectorConfig {
            thumbnail_min_rating: Rating::Clean,
            ..Default::default()
        })
        .is_err());
        assert!(mk(DetectorConfig {
            dedupe_threshold: 40,
            ..Default::default()
        })
        .is_err());
        let d = mk(DetectorConfig::default()).unwrap();
        assert_eq!(d.model_info().name, "null");
        let j = serde_json::to_string(&DetectorConfig::default()).unwrap();
        assert_eq!(
            serde_json::from_str::<DetectorConfig>(&j).unwrap(),
            DetectorConfig::default()
        );
    }

    #[test]
    fn detector_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Detector>();
    }
}
