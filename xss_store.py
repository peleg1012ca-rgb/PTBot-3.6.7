"""XSS run progress and bounded evidence; additive, per-version SQLite data."""
import json
from workbench_store import connect


def migrate(conn):
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS xss_runs (
      run_id INTEGER PRIMARY KEY REFERENCES investigation_runs(id),
      progress TEXT NOT NULL DEFAULT 'Queued',
      requests_sent INTEGER NOT NULL DEFAULT 0,
      browser_verify INTEGER NOT NULL DEFAULT 1,
      cancel_requested INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS xss_checks (
      id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES investigation_runs(id),
      endpoint TEXT NOT NULL, parameter TEXT NOT NULL, outcome TEXT NOT NULL,
      http_status INTEGER, evidence_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE INDEX IF NOT EXISTS idx_xss_checks_run ON xss_checks(run_id);
    ''')


def begin(path, rid, browser_verify):
    with connect(path) as c:
        c.execute('INSERT INTO xss_runs(run_id,browser_verify) VALUES (?,?)', (rid, int(browser_verify)))


def progress(path, rid, message, sent=False):
    with connect(path) as c:
        c.execute('UPDATE xss_runs SET progress=?, requests_sent=requests_sent+? WHERE run_id=?',
                  (message[:250], int(sent), rid))


def cancelled(path, rid):
    with connect(path) as c:
        row = c.execute('SELECT cancel_requested FROM xss_runs WHERE run_id=?', (rid,)).fetchone()
        return not row or bool(row[0])


def save_check(path, rid, endpoint, parameter, outcome, status, evidence):
    with connect(path) as c:
        c.execute('INSERT INTO xss_checks(run_id,endpoint,parameter,outcome,http_status,evidence_json) VALUES (?,?,?,?,?,?)',
                  (rid, endpoint, parameter, outcome, status, json.dumps(evidence, ensure_ascii=False)))


def detail(path, rid):
    with connect(path) as c:
        row = c.execute('SELECT * FROM xss_runs WHERE run_id=?', (rid,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data['checks'] = []
        for r in c.execute('SELECT * FROM xss_checks WHERE run_id=? ORDER BY id', (rid,)):
            item = dict(r)
            item['evidence'] = json.loads(item.pop('evidence_json'))
            data['checks'].append(item)
        data['verified'] = sum(r['outcome'] == 'execution_verified' for r in data['checks'])
        data['candidates'] = sum(r['outcome'] == 'payload_reflected' for r in data['checks'])
        return data


def recover_interrupted(path):
    """Called once by the single-server entrypoint, before accepting requests."""
    with connect(path) as c:
        ids = [r[0] for r in c.execute("SELECT run_id FROM xss_runs JOIN investigation_runs ON id=run_id WHERE status='pending'")]
        for rid in ids:
            reason = 'Server restarted before this XSS run completed. Partial evidence is retained; start a new run.'
            c.execute("UPDATE investigation_runs SET status='error',error_reason=?,finished_at=CURRENT_TIMESTAMP WHERE id=?",(reason,rid))
            c.execute('UPDATE run_metadata SET summary=? WHERE run_id=?',(reason,rid))
            c.execute("UPDATE xss_runs SET progress='Interrupted by server restart' WHERE run_id=?",(rid,))
