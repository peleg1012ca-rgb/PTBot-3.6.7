"""Persistent website reconnaissance jobs; additive migration only."""
import json
import workbench_store as store


def migrate(c):
    c.executescript('''
    CREATE TABLE IF NOT EXISTS recon_runs (
      run_id INTEGER PRIMARY KEY REFERENCES investigation_runs(id),
      progress TEXT NOT NULL DEFAULT 'Queued',
      result_json TEXT NOT NULL DEFAULT '{}',
      cancel_requested INTEGER NOT NULL DEFAULT 0);
    ''')


def save(path, rid, result, progress):
    with store.connect(path) as c:
        c.execute('UPDATE recon_runs SET result_json=?,progress=? WHERE run_id=?',
                  (json.dumps(result, ensure_ascii=False), progress[:300], rid))


def detail(path, eid, rid):
    with store.connect(path) as c:
        row = c.execute('''SELECT r.*,m.summary,e.client_name,x.progress,x.result_json,x.cancel_requested
          FROM recon_runs x JOIN investigation_runs r ON r.id=x.run_id
          JOIN engagements e ON e.id=r.engagement_id LEFT JOIN run_metadata m ON m.run_id=r.id
          WHERE r.id=? AND r.engagement_id=?''', (rid, eid)).fetchone()
    if row is None:
        return None
    data = dict(row)
    data['result'] = json.loads(data.pop('result_json'))
    return data


def recent(path, eid=None):
    with store.connect(path) as c:
        sql = '''SELECT r.*,e.client_name,x.progress FROM recon_runs x
          JOIN investigation_runs r ON r.id=x.run_id JOIN engagements e ON e.id=r.engagement_id'''
        return [dict(r) for r in c.execute(sql + (' WHERE r.engagement_id=?' if eid else '') +
                ' ORDER BY r.id DESC LIMIT 30', (eid,) if eid else ())]


def recover_interrupted(path):
    with store.connect(path) as c:
        c.execute("UPDATE recon_runs SET progress='Interrupted by server restart' WHERE run_id IN (SELECT id FROM investigation_runs WHERE status='pending')")
        c.execute("UPDATE investigation_runs SET status='error',finished_at=CURRENT_TIMESTAMP,error_reason='Interrupted by server restart' WHERE status='pending' AND id IN (SELECT run_id FROM recon_runs)")
