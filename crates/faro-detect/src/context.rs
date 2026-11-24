//! Context signals (§3.5, branch \[B\]): what was on screen *besides* the pixels.
//!
//! The analyzer turns the foreground app, window title and browser context
//! into typed [`ContextFinding`]s. It does not decide ratings; the fusion
//! engine does, so every finding stays explainable as a reason
//! (`domain:adult`, `title:xxx`, `context:incognito`).

use crate::domains::{Category, DomainCategorizer};
use crate::error::DetectError;
use faro_proto::body::{AppInfo, BrowserContext};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Titles longer than this are only scanned up to here; bounds CPU on
/// adversarially long titles.
const MAX_TITLE_SCAN_BYTES: usize = 2048;
const MAX_KEYWORDS: usize = 4096;

/// Everything known about the foreground at capture time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSignals {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<AppInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_title: Option<String>,
    /// From the browser extension over native messaging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserContext>,
    /// A browser is in use but its extension is not reporting.
    #[serde(default)]
    pub browser_without_extension: bool,
}

/// Maps an application id to a category label (e.g. a Tor Browser bundle id
/// to `anonymizing_browser`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppRule {
    /// Bundle id / executable name, matched case-insensitively and exactly
    /// against [`AppInfo::id`].
    pub app_id: String,
    pub category: String,
}

/// Configurable lists for the analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContextConfig {
    /// Matched case-insensitively on word boundaries in the window title and
    /// the browser tab title. Multi-word keywords are allowed.
    pub title_keywords: Vec<String>,
    pub app_rules: Vec<AppRule>,
}

impl Default for ContextConfig {
    /// A deliberately small starting list. Title hits alone only ever rate
    /// `low` by default, so false positives cost little; members and allies
    /// extend it in settings.
    fn default() -> Self {
        let kw = [
            "porn", "porno", "xxx", "nsfw", "hentai", "onlyfans", "nude", "nudes", "camgirl",
            "sex cam", "live sex",
        ];
        ContextConfig {
            title_keywords: kw.iter().map(|s| (*s).to_owned()).collect(),
            app_rules: vec![AppRule {
                app_id: "org.torproject.torbrowser".to_owned(),
                category: "anonymizing_browser".to_owned(),
            }],
        }
    }
}

/// One typed context finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ContextFinding {
    /// The browser URL's domain is listed under `category`; `label` is the
    /// display name (custom categories may be named).
    Domain { category: Category, label: String },
    /// A configured keyword appeared in a title (the normalised keyword).
    TitleKeyword(String),
    /// The foreground app is in a configured category.
    App(String),
    /// The browser tab is private/incognito.
    Incognito,
    /// A browser is in use without the Faro extension.
    BrowserWithoutExtension,
}

/// Compiled context configuration plus an optional domain index.
#[derive(Debug, Clone)]
pub struct ContextAnalyzer {
    keywords: Vec<String>,
    apps: HashMap<String, String>,
    domains: Option<DomainCategorizer>,
}

impl ContextAnalyzer {
    pub fn new(
        config: &ContextConfig,
        domains: Option<DomainCategorizer>,
    ) -> Result<Self, DetectError> {
        if config.title_keywords.len() > MAX_KEYWORDS {
            return Err(DetectError::Config(format!(
                "at most {MAX_KEYWORDS} title keywords"
            )));
        }
        let mut keywords = Vec::with_capacity(config.title_keywords.len());
        for k in &config.title_keywords {
            // Collapse internal whitespace so "sex  cam" == "sex cam".
            let k = k
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            if k.is_empty() {
                return Err(DetectError::Config("empty title keyword".into()));
            }
            if !keywords.contains(&k) {
                keywords.push(k);
            }
        }
        let mut apps = HashMap::new();
        for r in &config.app_rules {
            let id = r.app_id.trim().to_lowercase();
            let cat = r.category.trim();
            if id.is_empty() || cat.is_empty() {
                return Err(DetectError::Config(
                    "app rule needs an app_id and category".into(),
                ));
            }
            apps.insert(id, cat.to_owned());
        }
        Ok(ContextAnalyzer {
            keywords,
            apps,
            domains,
        })
    }

    /// Replace the domain index (a new bundle arrived via updates).
    pub fn set_domains(&mut self, domains: Option<DomainCategorizer>) {
        self.domains = domains;
    }

    pub fn domains(&self) -> Option<&DomainCategorizer> {
        self.domains.as_ref()
    }

    /// Evaluate all context signals. Findings are de-duplicated and in a
    /// stable order: domain, title, app, incognito, extension.
    pub fn analyze(&self, signals: &ContextSignals) -> Vec<ContextFinding> {
        let mut out = Vec::new();

        if let (Some(d), Some(url)) = (
            &self.domains,
            signals.browser.as_ref().and_then(|b| b.url.as_deref()),
        ) {
            for category in d.categorize_url(url) {
                out.push(ContextFinding::Domain {
                    category,
                    label: d.label(category),
                });
            }
        }

        let titles = [
            signals.window_title.as_deref(),
            signals.browser.as_ref().and_then(|b| b.title.as_deref()),
        ];
        for title in titles.into_iter().flatten() {
            for kw in self.keyword_hits(title) {
                let f = ContextFinding::TitleKeyword(kw.to_owned());
                if !out.contains(&f) {
                    out.push(f);
                }
            }
        }

        if let Some(cat) = signals
            .app
            .as_ref()
            .and_then(|a| self.apps.get(&a.id.trim().to_lowercase()))
        {
            out.push(ContextFinding::App(cat.clone()));
        }
        if signals.browser.as_ref().is_some_and(|b| b.incognito) {
            out.push(ContextFinding::Incognito);
        }
        if signals.browser_without_extension {
            out.push(ContextFinding::BrowserWithoutExtension);
        }
        out
    }

    /// Configured keywords that occur in `title` on word boundaries
    /// (case-insensitive; a boundary is any non-alphanumeric character or
    /// the ends of the string).
    pub fn keyword_hits<'a>(&'a self, title: &str) -> Vec<&'a str> {
        let mut end = title.len().min(MAX_TITLE_SCAN_BYTES);
        while !title.is_char_boundary(end) {
            end -= 1;
        }
        let norm = title[..end]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        self.keywords
            .iter()
            .filter(|kw| contains_word(&norm, kw))
            .map(String::as_str)
            .collect()
    }
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    haystack.match_indices(needle).any(|(i, m)| {
        let before = haystack[..i].chars().next_back();
        let after = haystack[i + m.len()..].chars().next();
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::DomainCategorizerBuilder;
    use proptest::prelude::*;

    fn analyzer() -> ContextAnalyzer {
        let mut b = DomainCategorizerBuilder::new();
        b.add_domain("adult.test", Category::Adult).unwrap();
        b.add_domain("both.test", Category::Adult).unwrap();
        b.add_domain("both.test", Category::Gambling).unwrap();
        ContextAnalyzer::new(&ContextConfig::default(), Some(b.build().unwrap())).unwrap()
    }

    fn browser(url: &str, title: &str, incognito: bool) -> Option<BrowserContext> {
        Some(BrowserContext {
            url: Some(url.into()),
            title: Some(title.into()),
            incognito,
        })
    }

    #[test]
    fn word_boundaries() {
        let a = analyzer();
        assert_eq!(a.keyword_hits("Best XXX videos"), vec!["xxx"]);
        assert_eq!(a.keyword_hits("xxx-videos.test"), vec!["xxx"]);
        assert_eq!(a.keyword_hits("PORN"), vec!["porn"]);
        assert!(a.keyword_hits("pornography lecture notes").is_empty());
        assert!(a.keyword_hits("Essex County news").is_empty());
        assert!(a.keyword_hits("Pornhub").is_empty()); // not a word match
        assert_eq!(a.keyword_hits("Free  Sex\tCam site"), vec!["sex cam"]);
        assert!(a.keyword_hits("").is_empty());
        assert_eq!(a.keyword_hits("ÉTÉ xxx"), vec!["xxx"]);
        assert!(a.keyword_hits("éxxx").is_empty());
    }

    #[test]
    fn full_analysis_order_and_dedupe() {
        let a = analyzer();
        let s = ContextSignals {
            app: Some(AppInfo {
                id: "ORG.TorProject.TorBrowser".into(),
                name: None,
            }),
            window_title: Some("xxx — Tor Browser".into()),
            browser: browser("https://m.both.test/x", "XXX nsfw", true),
            browser_without_extension: true,
        };
        assert_eq!(
            a.analyze(&s),
            vec![
                ContextFinding::Domain {
                    category: Category::Adult,
                    label: "adult".into()
                },
                ContextFinding::Domain {
                    category: Category::Gambling,
                    label: "gambling".into()
                },
                ContextFinding::TitleKeyword("xxx".into()),
                ContextFinding::TitleKeyword("nsfw".into()),
                ContextFinding::App("anonymizing_browser".into()),
                ContextFinding::Incognito,
                ContextFinding::BrowserWithoutExtension,
            ]
        );
    }

    #[test]
    fn nothing_found_on_benign_context() {
        let a = analyzer();
        let s = ContextSignals {
            app: Some(AppInfo {
                id: "com.example.editor".into(),
                name: None,
            }),
            window_title: Some("Quarterly report.docx".into()),
            browser: browser("https://notadult.test", "Docs", false),
            browser_without_extension: false,
        };
        assert!(a.analyze(&s).is_empty());
        assert!(a.analyze(&ContextSignals::default()).is_empty());
    }

    #[test]
    fn no_domain_index_means_no_domain_findings() {
        let a = ContextAnalyzer::new(&ContextConfig::default(), None).unwrap();
        let s = ContextSignals {
            browser: browser("https://adult.test", "", false),
            ..Default::default()
        };
        assert!(a.analyze(&s).is_empty());
    }

    #[test]
    fn config_validation() {
        let mut c = ContextConfig::default();
        c.title_keywords.push("   ".into());
        assert!(ContextAnalyzer::new(&c, None).is_err());
        let mut c = ContextConfig::default();
        c.app_rules.push(AppRule {
            app_id: "".into(),
            category: "x".into(),
        });
        assert!(ContextAnalyzer::new(&c, None).is_err());
        let c: ContextConfig =
            serde_json::from_str(r#"{"title_keywords": ["Casino Royale"]}"#).unwrap();
        let a = ContextAnalyzer::new(&c, None).unwrap();
        assert_eq!(
            a.keyword_hits("watching casino royale tonight"),
            vec!["casino royale"]
        );
        // Fields left out keep their defaults.
        assert_eq!(c.app_rules, ContextConfig::default().app_rules);
    }

    proptest! {
        #[test]
        fn arbitrary_titles_never_panic(t in ".{0,3000}") {
            let a = analyzer();
            let _ = a.keyword_hits(&t);
        }
    }
}
