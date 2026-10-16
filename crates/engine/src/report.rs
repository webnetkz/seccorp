//! Result types shared by the engine, the CLI and the GUI.

use serde::{Deserialize, Serialize};

/// Severity of a single detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "moderate" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "severe" => Some(Severity::Critical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Maps a 0..=100 score to a severity.
    pub fn from_score(score: u32) -> Severity {
        match score {
            0..=9 => Severity::Info,
            10..=29 => Severity::Low,
            30..=59 => Severity::Medium,
            60..=89 => Severity::High,
            _ => Severity::Critical,
        }
    }
}

/// Which detection layer produced a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionKind {
    /// Exact hash match.
    Hash,
    /// Byte-pattern (body) signature.
    Pattern,
    /// Rule (YARA subset).
    Rule,
    /// Heuristic analyzer.
    Heuristic,
}

/// Final verdict for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    #[default]
    Clean,
    Suspicious,
    Malicious,
}

/// One detection inside a file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Detection {
    /// Threat / signature / heuristic name, e.g. `EICAR-Test-File`.
    pub name: String,
    pub kind: DetectionKind,
    pub severity: Severity,
    /// Heuristic score contribution (0 for signature detections).
    pub score: u32,
    /// Human readable explanation (English; the GUI translates known names).
    pub description: String,
    /// Location inside a container, e.g. `docs.zip › invoice.pdf.exe`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// Scan result for a single file (or buffer).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileVerdict {
    pub path: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub file_type: String,
    pub verdict: Verdict,
    /// Aggregated heuristic score (0..=100).
    pub score: u32,
    pub detections: Vec<Detection>,
    /// Set when the file could not be (fully) analysed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    pub duration_ms: u64,
}

impl FileVerdict {
    pub fn is_threat(&self) -> bool {
        self.verdict != Verdict::Clean
    }

    /// The most severe detection, preferring signature detections.
    pub fn primary_detection(&self) -> Option<&Detection> {
        self.detections.iter().max_by_key(|d| {
            let kind_rank = match d.kind {
                DetectionKind::Hash => 3,
                DetectionKind::Pattern => 2,
                DetectionKind::Rule => 2,
                DetectionKind::Heuristic => 1,
            };
            (d.severity, kind_rank, d.score)
        })
    }

    pub fn threat_name(&self) -> Option<&str> {
        self.primary_detection().map(|d| d.name.as_str())
    }

    pub fn max_severity(&self) -> Severity {
        self.detections.iter().map(|d| d.severity).max().unwrap_or_default()
    }
}

/// Summary of a whole scan session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub id: String,
    pub roots: Vec<String>,
    pub started_at: u64,
    pub finished_at: u64,
    pub files_scanned: u64,
    pub files_cached: u64,
    pub files_skipped: u64,
    pub bytes_scanned: u64,
    pub errors: u64,
    pub cancelled: bool,
    pub threats: Vec<FileVerdict>,
}
