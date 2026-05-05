"""Scan persistence — SQLite-backed storage for cross-session statistical analysis.

Stores WAF scan findings and recon results across runs, enabling:
- Confidence scoring based on repeated observations (mean, std-dev, stability)
- Trend analysis: is a finding consistent or intermittent?
- Historical comparison: what changed between scans?
- False positive tracking: findings that disappear on re-test get demoted
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Default DB location: ~/.local/share/whatthewaf/scan_history.db
def _default_db_path() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")))
    db_dir = base / "whatthewaf"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "scan_history.db"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    timestamp REAL NOT NULL,
    duration_seconds REAL,
    total_findings INTEGER DEFAULT 0,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    category TEXT NOT NULL,
    layer TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    confidence REAL DEFAULT 0.5,
    verified INTEGER DEFAULT 0,
    fp_verified INTEGER DEFAULT 0,
    timestamp REAL NOT NULL,
    FOREIGN KEY (run_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS recon_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    ip TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    times_seen INTEGER DEFAULT 1,
    classification TEXT,
    provider TEXT,
    bypass_confirmed INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_domain_fp ON findings(domain, fingerprint);
CREATE INDEX IF NOT EXISTS idx_recon_ips_domain ON recon_ips(domain);
CREATE INDEX IF NOT EXISTS idx_recon_ips_domain_ip ON recon_ips(domain, ip);
CREATE INDEX IF NOT EXISTS idx_scan_runs_domain ON scan_runs(domain);
"""


def _finding_fingerprint(category: str, layer: str, title: str) -> str:
    """Generate a stable fingerprint for a finding to track it across scans."""
    raw = f"{category}:{layer}:{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class FindingStats:
    """Statistical summary for a finding observed across multiple scans."""
    fingerprint: str
    title: str
    category: str
    layer: str
    severity: str
    times_seen: int
    total_scans: int
    hit_rate: float  # times_seen / total_scans
    avg_confidence: float
    confidence_stddev: float
    stability: str  # "stable", "intermittent", "rare", "new"
    last_verified: bool
    fp_verified: bool  # passed false-positive check
    first_seen: float
    last_seen: float
    statistical_confidence: float  # computed overall confidence


@dataclass
class IPStats:
    """Statistical summary for a recon IP observed across sessions."""
    ip: str
    domain: str
    sources: List[str]
    times_seen: int
    first_seen: float
    last_seen: float
    classification: Optional[str]
    provider: Optional[str]
    bypass_confirmed: bool
    confidence: float  # based on times_seen and source diversity


class ScanPersistence:
    """SQLite-backed scan history with statistical analysis."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = Path(db_path) if db_path else _default_db_path()
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_schema()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path), timeout=10)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
        return self._conn

    def _ensure_schema(self) -> None:
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Store scan results
    # ------------------------------------------------------------------

    def store_scan(
        self,
        domain: str,
        scan_type: str,
        findings: List[Dict[str, Any]],
        duration_seconds: float = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Store a complete scan run and its findings. Returns the run_id."""
        conn = self._get_conn()
        now = time.time()

        cursor = conn.execute(
            "INSERT INTO scan_runs (domain, scan_type, timestamp, duration_seconds, total_findings, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (domain, scan_type, now, duration_seconds, len(findings),
             json.dumps(metadata) if metadata else None),
        )
        run_id = cursor.lastrowid

        for f in findings:
            fp = _finding_fingerprint(
                f.get("category", ""),
                f.get("layer", ""),
                f.get("title", ""),
            )
            conn.execute(
                "INSERT INTO findings "
                "(run_id, domain, fingerprint, category, layer, severity, title, "
                "description, evidence, confidence, verified, fp_verified, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id, domain, fp,
                    f.get("category", ""),
                    f.get("layer", ""),
                    f.get("severity", "info"),
                    f.get("title", ""),
                    f.get("description", ""),
                    f.get("evidence", ""),
                    f.get("confidence", 0.5),
                    1 if f.get("verified") else 0,
                    1 if f.get("fp_verified") else 0,
                    now,
                ),
            )

        conn.commit()
        return run_id

    def store_recon_ip(
        self,
        domain: str,
        ip: str,
        source: str,
        classification: Optional[str] = None,
        provider: Optional[str] = None,
        bypass_confirmed: bool = False,
    ) -> None:
        """Store or update a recon IP observation."""
        conn = self._get_conn()
        now = time.time()

        row = conn.execute(
            "SELECT id, times_seen, source FROM recon_ips WHERE domain = ? AND ip = ?",
            (domain, ip),
        ).fetchone()

        if row:
            existing_sources = set(row["source"].split(","))
            existing_sources.add(source)
            new_sources = ",".join(sorted(existing_sources))
            conn.execute(
                "UPDATE recon_ips SET last_seen = ?, times_seen = times_seen + 1, "
                "source = ?, classification = COALESCE(?, classification), "
                "provider = COALESCE(?, provider), "
                "bypass_confirmed = MAX(bypass_confirmed, ?) "
                "WHERE id = ?",
                (now, new_sources, classification, provider,
                 1 if bypass_confirmed else 0, row["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO recon_ips (domain, ip, source, first_seen, last_seen, "
                "times_seen, classification, provider, bypass_confirmed) "
                "VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)",
                (domain, ip, source, now, now, classification, provider,
                 1 if bypass_confirmed else 0),
            )

        conn.commit()

    # ------------------------------------------------------------------
    # Statistical analysis
    # ------------------------------------------------------------------

    def get_finding_stats(self, domain: str) -> List[FindingStats]:
        """Get statistical analysis of all findings for a domain across scans."""
        conn = self._get_conn()

        # Count total scans for this domain
        total_scans = conn.execute(
            "SELECT COUNT(*) FROM scan_runs WHERE domain = ?", (domain,)
        ).fetchone()[0]

        if total_scans == 0:
            return []

        # Get all unique fingerprints and their occurrence data
        rows = conn.execute(
            "SELECT fingerprint, category, layer, severity, title, "
            "COUNT(*) as times_seen, "
            "AVG(confidence) as avg_conf, "
            "GROUP_CONCAT(confidence) as conf_list, "
            "MAX(verified) as last_verified, "
            "MAX(fp_verified) as fp_verified, "
            "MIN(timestamp) as first_seen, "
            "MAX(timestamp) as last_seen "
            "FROM findings WHERE domain = ? "
            "GROUP BY fingerprint "
            "ORDER BY times_seen DESC",
            (domain,),
        ).fetchall()

        stats = []
        for row in rows:
            times_seen = row["times_seen"]
            hit_rate = times_seen / total_scans
            avg_conf = row["avg_conf"] or 0.5

            # Calculate confidence std-dev
            conf_values = [float(c) for c in (row["conf_list"] or "0.5").split(",")]
            if len(conf_values) > 1:
                mean = sum(conf_values) / len(conf_values)
                variance = sum((c - mean) ** 2 for c in conf_values) / (len(conf_values) - 1)
                stddev = math.sqrt(variance)
            else:
                stddev = 0.0

            # Determine stability
            if times_seen == 1 and total_scans == 1:
                stability = "new"
            elif hit_rate >= 0.8:
                stability = "stable"
            elif hit_rate >= 0.4:
                stability = "intermittent"
            else:
                stability = "rare"

            # Compute statistical confidence:
            # - Higher hit_rate → more confident it's real
            # - Lower stddev → more consistent
            # - Verified findings get a boost
            # - FP-verified findings get a major boost
            stat_conf = avg_conf * (0.5 + 0.5 * hit_rate)
            if stddev < 0.1:
                stat_conf *= 1.1  # consistent readings
            if row["last_verified"]:
                stat_conf = min(1.0, stat_conf * 1.15)
            if row["fp_verified"]:
                stat_conf = min(1.0, stat_conf * 1.25)
            # Penalize rare findings
            if stability == "rare":
                stat_conf *= 0.6
            elif stability == "intermittent":
                stat_conf *= 0.8
            stat_conf = min(1.0, max(0.0, stat_conf))

            stats.append(FindingStats(
                fingerprint=row["fingerprint"],
                title=row["title"],
                category=row["category"],
                layer=row["layer"],
                severity=row["severity"],
                times_seen=times_seen,
                total_scans=total_scans,
                hit_rate=hit_rate,
                avg_confidence=avg_conf,
                confidence_stddev=stddev,
                stability=stability,
                last_verified=bool(row["last_verified"]),
                fp_verified=bool(row["fp_verified"]),
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                statistical_confidence=stat_conf,
            ))

        return stats

    def get_ip_stats(self, domain: str) -> List[IPStats]:
        """Get statistical analysis of recon IPs for a domain."""
        conn = self._get_conn()

        rows = conn.execute(
            "SELECT ip, source, times_seen, first_seen, last_seen, "
            "classification, provider, bypass_confirmed "
            "FROM recon_ips WHERE domain = ? "
            "ORDER BY times_seen DESC, bypass_confirmed DESC",
            (domain,),
        ).fetchall()

        stats = []
        for row in rows:
            sources = row["source"].split(",") if row["source"] else []
            # Confidence based on times_seen and source diversity
            source_factor = min(1.0, len(sources) / 3.0)  # 3+ sources = max
            seen_factor = min(1.0, row["times_seen"] / 5.0)  # 5+ sightings = max
            confidence = 0.3 + 0.35 * source_factor + 0.35 * seen_factor
            if row["bypass_confirmed"]:
                confidence = min(1.0, confidence + 0.2)

            stats.append(IPStats(
                ip=row["ip"],
                domain=domain,
                sources=sources,
                times_seen=row["times_seen"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                classification=row["classification"],
                provider=row["provider"],
                bypass_confirmed=bool(row["bypass_confirmed"]),
                confidence=confidence,
            ))

        return stats

    def get_scan_history(self, domain: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scan history for a domain."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT id, scan_type, timestamp, duration_seconds, total_findings "
            "FROM scan_runs WHERE domain = ? ORDER BY timestamp DESC LIMIT ?",
            (domain, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_finding_trend(self, domain: str, fingerprint: str) -> List[Dict[str, Any]]:
        """Get the history of a specific finding across scans."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT f.timestamp, f.confidence, f.verified, f.fp_verified, "
            "r.scan_type FROM findings f "
            "JOIN scan_runs r ON f.run_id = r.id "
            "WHERE f.domain = ? AND f.fingerprint = ? "
            "ORDER BY f.timestamp",
            (domain, fingerprint),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_new_findings(self, domain: str, run_id: int) -> List[Dict[str, Any]]:
        """Get findings that are new in this scan (never seen before)."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT f.* FROM findings f "
            "WHERE f.run_id = ? AND f.fingerprint NOT IN ("
            "  SELECT fingerprint FROM findings "
            "  WHERE domain = ? AND run_id < ?"
            ")",
            (run_id, domain, run_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_disappeared_findings(self, domain: str, run_id: int) -> List[Dict[str, Any]]:
        """Get findings from previous scans that didn't appear in this one."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT DISTINCT fingerprint, title, category, severity, layer "
            "FROM findings "
            "WHERE domain = ? AND run_id < ? AND fingerprint NOT IN ("
            "  SELECT fingerprint FROM findings WHERE run_id = ?"
            ")",
            (domain, run_id, run_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def purge_domain(self, domain: str) -> int:
        """Delete all history for a domain. Returns number of runs deleted."""
        conn = self._get_conn()
        run_ids = [r[0] for r in conn.execute(
            "SELECT id FROM scan_runs WHERE domain = ?", (domain,)
        ).fetchall()]
        if run_ids:
            placeholders = ",".join("?" * len(run_ids))
            conn.execute(f"DELETE FROM findings WHERE run_id IN ({placeholders})", run_ids)
            conn.execute("DELETE FROM scan_runs WHERE domain = ?", (domain,))
        conn.execute("DELETE FROM recon_ips WHERE domain = ?", (domain,))
        conn.commit()
        return len(run_ids)

    def get_db_stats(self) -> Dict[str, Any]:
        """Get overall database statistics."""
        conn = self._get_conn()
        domains = conn.execute("SELECT COUNT(DISTINCT domain) FROM scan_runs").fetchone()[0]
        runs = conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]
        findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        ips = conn.execute("SELECT COUNT(*) FROM recon_ips").fetchone()[0]
        return {
            "db_path": str(self._db_path),
            "domains_tracked": domains,
            "total_scans": runs,
            "total_findings": findings,
            "total_recon_ips": ips,
        }
