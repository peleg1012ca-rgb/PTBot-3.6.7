SQLite migration patch for AI-PT-Agent (stage: data models only)

Files:
  database.py                 Replace the project database.py with this file.
  tests/test_database_migration.py   Offline tests using temporary databases.

On Kali, first back up the project database.py; then extract this ZIP into
/home/peleg/AI-PT-Agent (choose overwrite for database.py).

Run from /home/peleg/AI-PT-Agent:
  .venv/bin/python -m unittest discover -s tests -v

The test uses temporary databases. It does not run app.py or any scanners.
init_db() will create four new tables in the project database if app.py is run.
The existing scans/services/findings tables and their rows are retained.

engagements: client and status (draft by default).
included_targets / excluded_targets: targets linked to an engagement.
policy_settings: allowed action and per-minute cap linked to an engagement.
Tables only store data; enforcing scope and policy is a separate future step.
