# Prepare the repository

Do this from PT-Workbench-v1, never from the old project or a directory containing captures.

```bash
git init
git add .
git status --short
```

Inspect the staged list. It must exclude `agent_data.db`, its backups, `instance/`, credentials, raw captures and customer reports. Review files for secrets and client names before the next command. Select a source license after confirming ownership; no publishing/license decision has been made automatically.

```bash
git commit -m "Release PT Workbench v1: scoped checks, evidence and review"
```

Then create your GitHub repository, add its exact remote and push after review. The included GitHub Actions workflow runs offline tests on Python 3.11, 3.12 and 3.13; this matrix has not yet run on GitHub. The local release was tested on Python 3.12.

Suggested demonstration assets: an overview screenshot, a scoped successful run, a denied run, a reviewed observation and a sanitized PDF report. Do not present example data as an external assessment.
