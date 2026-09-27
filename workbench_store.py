"""Additive portfolio workflows: review history, run metadata and reports."""

from contextlib import closing, contextmanager
from pathlib import Path
import sqlite3


@contextmanager
def connect(path):
    with closing(sqlite3.connect(path, timeout=5)) as c:
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        with c:
            yield c


def migrate(c):
    columns = {r[1] for r in c.execute("PRAGMA table_info(observations)")}
    if "review_note" not in columns:
        c.execute(
            "ALTER TABLE observations ADD COLUMN review_note TEXT NOT NULL DEFAULT ''"
        )
    c.executescript("""
    CREATE TABLE IF NOT EXISTS review_events (
      id INTEGER PRIMARY KEY, observation_id INTEGER NOT NULL REFERENCES observations(id),
      old_status TEXT NOT NULL, new_status TEXT NOT NULL, note TEXT NOT NULL,
      reviewer TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS run_metadata (
      run_id INTEGER PRIMARY KEY REFERENCES investigation_runs(id),
      source TEXT NOT NULL, method TEXT, summary TEXT NOT NULL DEFAULT '');
    CREATE INDEX IF NOT EXISTS idx_observations_run ON observations(run_id);
    """)


def dashboard(path):
    with connect(path) as c:
        counts = {
            k: c.execute("SELECT count(*) FROM " + t).fetchone()[0]
            for k, t in [
                ("engagements", "engagements"),
                ("runs", "investigation_runs"),
                ("observations", "observations"),
            ]
        }
        counts["unreviewed"] = c.execute(
            "SELECT count(*) FROM observations WHERE review_status='unreviewed'"
        ).fetchone()[0]
        counts['recon_runs'] = c.execute('SELECT count(*) FROM recon_runs').fetchone()[0]
        counts['xss_runs'] = c.execute('SELECT count(*) FROM xss_runs').fetchone()[0]
        counts['verified'] = c.execute("SELECT count(*) FROM xss_checks WHERE outcome='execution_verified'").fetchone()[0]
        counts['candidates'] = c.execute("SELECT count(*) FROM observations WHERE check_type='xss_candidate'").fetchone()[0]
        counts['approved'] = c.execute("SELECT count(*) FROM engagements WHERE status='approved'").fetchone()[0]
        recent = [
            dict(r)
            for r in c.execute(
                """SELECT r.*, e.client_name, m.source FROM investigation_runs r
                  JOIN engagements e ON e.id=r.engagement_id LEFT JOIN run_metadata m ON m.run_id=r.id
                  ORDER BY r.id DESC LIMIT 12"""
            )
        ]
        return counts, recent


def begin_run(path, eid, action, target, source, method=""):
    with connect(path) as c:
        rid = c.execute(
            "INSERT INTO investigation_runs (engagement_id,action_type,target_reference) VALUES (?,?,?)",
            (eid, action, target),
        ).lastrowid
        c.execute(
            "INSERT INTO run_metadata(run_id,source,method) VALUES (?,?,?)",
            (rid, source, method),
        )
        return rid


def complete_run(path, rid, state, summary, observations=()):
    if state not in ("response", "error", "denied"):
        raise ValueError("Invalid run state")
    with connect(path) as c:
        if (
            c.execute(
                "UPDATE investigation_runs SET status=?,finished_at=CURRENT_TIMESTAMP,error_reason=? WHERE id=? AND status='pending'",
                (state, None if state == "response" else summary[:200], rid),
            ).rowcount
            != 1
        ):
            raise ValueError("Run was already completed")
        c.execute(
            "UPDATE run_metadata SET summary=? WHERE run_id=?", (summary[:300], rid)
        )
        for item in observations:
            oid = c.execute(
                "INSERT INTO observations(run_id,check_type,severity,title,explanation) VALUES (?,?,?,?,?)",
                (
                    rid,
                    item["check"],
                    item.get("severity", "info"),
                    item["title"][:160],
                    item["detail"][:1500],
                ),
            ).lastrowid
            if item.get("evidence"):
                c.execute(
                    "INSERT INTO evidence_refs(observation_id,evidence_kind,reference_text) VALUES (?,?,?)",
                    (oid, "summary", item["evidence"][:500]),
                )


def detail(path, eid, rid):
    with connect(path) as c:
        row = c.execute(
            """SELECT r.*,m.source,m.method,m.summary FROM investigation_runs r
                 LEFT JOIN run_metadata m ON m.run_id=r.id WHERE r.id=? AND r.engagement_id=?""",
            (rid, eid),
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["observations"] = [
            dict(r)
            for r in c.execute(
                "SELECT * FROM observations WHERE run_id=? ORDER BY id", (rid,)
            )
        ]
        for item in data["observations"]:
            item["evidence"] = [
                dict(r)
                for r in c.execute(
                    "SELECT evidence_kind,reference_text FROM evidence_refs WHERE observation_id=?",
                    (item["id"],),
                )
            ]
            item["history"] = [
                dict(r)
                for r in c.execute(
                    "SELECT * FROM review_events WHERE observation_id=? ORDER BY id DESC",
                    (item["id"],),
                )
            ]
        from xss_store import detail as xss_detail
        data['xss'] = xss_detail(path, rid)
        from recon_store import detail as recon_detail
        recon = recon_detail(path, eid, rid)
        data['recon'] = recon['result'] if recon else None
        return data


def review(path, eid, rid, oid, status, note, reviewer):
    if status not in ("confirmed", "dismissed", "unreviewed"):
        raise ValueError("Choose a valid review status")
    if (
        not isinstance(note, str)
        or len(note) > 1000
        or any(ord(c) < 32 and c not in "\n\t" for c in note)
    ):
        raise ValueError("Review note must be at most 1000 printable characters")
    if status != "unreviewed" and not note.strip():
        raise ValueError("Explain the review decision in a short note")
    with connect(path) as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute(
            """SELECT o.review_status FROM observations o JOIN investigation_runs r ON r.id=o.run_id
                    WHERE o.id=? AND o.run_id=? AND r.engagement_id=?""",
            (oid, rid, eid),
        ).fetchone()
        if row is None:
            raise LookupError("Observation not found for this run")
        c.execute(
            "UPDATE observations SET review_status=?,review_note=? WHERE id=?",
            (status, note.strip(), oid),
        )
        c.execute(
            "INSERT INTO review_events(observation_id,old_status,new_status,note,reviewer) VALUES (?,?,?,?,?)",
            (oid, row[0], status, note.strip(), reviewer[:100]),
        )


def report(path, eid):
    with connect(path) as c:
        e = c.execute("SELECT * FROM engagements WHERE id=?", (eid,)).fetchone()
        if e is None:
            return None
        runs = [
            r[0]
            for r in c.execute(
                "SELECT id FROM investigation_runs WHERE engagement_id=? ORDER BY id",
                (eid,),
            )
        ]
        scope = [
            dict(r)
            for r in c.execute(
                "SELECT target_type,target_value FROM included_targets WHERE engagement_id=?",
                (eid,),
            )
        ]
        exclusions = [
            dict(r)
            for r in c.execute(
                "SELECT target_type,target_value FROM excluded_targets WHERE engagement_id=?",
                (eid,),
            )
        ]
    return {
        "engagement": dict(e),
        "scope": scope,
        "exclusions": exclusions,
        "runs": [detail(path, eid, r) for r in runs],
    }
