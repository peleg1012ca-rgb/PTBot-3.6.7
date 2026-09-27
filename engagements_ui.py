"""Flask pages for creating, viewing and approving engagements.

Stores scope data and exposes the explicitly authorized local lab action.
"""

import hmac
import secrets
import sqlite3
from itertools import zip_longest

from flask import Blueprint, abort, current_app, redirect, render_template_string, request, session, url_for

import audit_log
import investigation_store
import engagement_store as store
from config import DATABASE_PATH, DEFAULT_RATE_LIMIT_RPS, KNOWN_ACTIONS
from policy_engine import MAX_REQUESTS_PER_MINUTE, check_policy
from local_http import LAB_URL, LocalHTTPResult, fetch_local_lab

engagements_bp = Blueprint('engagements', __name__, url_prefix='/engagements', template_folder='templates')

BLANK_ROWS = 3

LAYOUT = """{% extends 'base.html' %}{% block body %}
{% if errors %}<div class="notice errors"><strong>Please fix the following:</strong><ul>{% for e in errors %}<li>{{ e }}</li>{% endfor %}</ul></div>{% endif %}
__BODY__
{% endblock %}"""

LIST_BODY = '''
<h1>Engagements</h1>
<p><a href="{{ url_for('engagements.new_engagement') }}">Create a new engagement</a></p>
<div class="card">
    <table>
        <tr><th>ID</th><th>Client / program</th><th>Status</th><th>Created</th></tr>
        {% for e in engagements %}
        <tr>
            <td>{{ e.id }}</td>
            <td><a href="{{ url_for('engagements.view', engagement_id=e.id) }}">{{ e.client_name }}</a></td>
            <td class="status-{{ e.status }}">{{ e.status }}</td>
            <td>{{ e.created_at }}</td>
        </tr>
        {% else %}
        <tr><td colspan="4">No engagements yet.</td></tr>
        {% endfor %}
    </table>
</div>
'''

FORM_BODY = '''
<h1>New engagement</h1>
<p><small>The engagement is saved as a <strong>draft</strong>. It must be approved separately before it authorizes anything.</small></p>
<form method="post" action="{{ url_for('engagements.new_engagement') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <div class="card">
        <h2>Client / program</h2>
        <input type="text" class="wide" name="client_name" value="{{ form.client_name }}" maxlength="{{ max_name }}" required>
    </div>
    {% for section, title, rows in sections %}
    <div class="card">
        <h2>{{ title }}</h2>
        <small>domain: example.com &middot; wildcard: *.example.com (subdomains only) &middot; ip: 192.0.2.10 &middot;
            cidr: 192.0.2.0/24 &middot; url: https://example.com/app (same scheme, host, port; path prefix)</small>
        <table id="{{ section }}-rows">
            <tr><th>Type</th><th>Value</th></tr>
            {% for kind, value in rows %}
            <tr>
                <td><select name="{{ section }}_type">
                    <option value="">-- type --</option>
                    {% for t in target_types %}<option value="{{ t }}"{% if t == kind %} selected{% endif %}>{{ t }}</option>{% endfor %}
                </select></td>
                <td><input type="text" class="wide" name="{{ section }}_value" value="{{ value }}"></td>
            </tr>
            {% endfor %}
        </table>
        <button type="button" class="secondary" onclick="addRow('{{ section }}-rows')">Add row</button>
    </div>
    {% endfor %}
    <div class="card">
        <h2>Allowed actions</h2>
        <small>Only checked actions are allowed. Requests per minute: 1 to {{ max_rpm }}.</small>
        <table>
            <tr><th>Allow</th><th>Action</th><th>Requests per minute</th></tr>
            {% for action, description in known_actions.items() %}
            <tr>
                <td><input type="checkbox" name="action" value="{{ action }}" id="action-{{ action }}"{% if action in form.policies %} checked{% endif %}></td>
                <td><label for="action-{{ action }}"><code>{{ action }}</code></label><br><small>{{ description }}</small></td>
                <td><input type="number" name="rpm_{{ action }}" min="1" max="{{ max_rpm }}" step="1"
                           value="{{ form.policies.get(action, default_rpm) }}"></td>
            </tr>
            {% endfor %}
        </table>
    </div>
    <button type="submit">Save as draft</button>
</form>
<script>
function addRow(tableId) {
    var table = document.getElementById(tableId);
    var row = table.rows[table.rows.length - 1].cloneNode(true);
    row.querySelector('select').selectedIndex = 0;
    row.querySelector('input').value = '';
    table.tBodies[0].appendChild(row);
}
</script>
'''

VIEW_BODY = '''
<div class="eyebrow">Scope & authorization</div><h1>Engagement #{{ e.id }}: {{ e.client_name }}</h1>
<div class="row" style="margin-bottom:24px"><a class="button" href="/assessments/{{ e.id }}/recon">Website Recon</a><a class="button secondary" href="/workbench/{{ e.id }}">Open workbench</a><a class="button secondary" href="/reports/{{ e.id }}">Report</a><a class="button secondary" href="/imports/{{ e.id }}">Import evidence</a></div>
<div class="card">
    <p>Status: <span class="status-{{ e.status }}">{{ e.status }}</span></p>
    <p>Created: {{ e.created_at }}</p>
    {% if e.status == 'approved' %}
    <form method="post" action="/engagements/{{ e.id }}/revoke"><input type="hidden" name="csrf_token" value="{{ csrf_token }}"><button class="danger">Revoke engagement</button></form>
    {% endif %}
    {% if e.status == 'draft' %}
    <form method="post" action="{{ url_for('engagements.approve', engagement_id=e.id) }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <label><input type="checkbox" name="confirm" value="yes">
            I confirm that written authorization covers exactly this scope and these actions.</label>
        <p><button type="submit">Approve engagement</button></p>
    </form>
    {% endif %}
</div>
{% for title, rules in (('Included targets', data.includes), ('Excluded targets', data.excludes)) %}
<div class="card">
    <h2>{{ title }}</h2>
    <table>
        <tr><th>Type</th><th>Value</th></tr>
        {% for r in rules %}<tr><td>{{ r.target_type }}</td><td><code>{{ r.target_value }}</code></td></tr>
        {% else %}<tr><td colspan="2">None</td></tr>{% endfor %}
    </table>
</div>
{% endfor %}
<div class="card">
    <h2>Policy settings</h2>
    <table>
        <tr><th>Allowed action</th><th>Requests per minute</th></tr>
        {% for p in data.policies %}<tr><td><code>{{ p.action_type }}</code></td><td>{{ p.requests_per_minute }}</td></tr>
        {% else %}<tr><td colspan="2">No actions allowed</td></tr>{% endfor %}
    </table>
</div>
<div class="card">
    <h2>Policy decision preview</h2>
    <p><small>Offline check only: shows what the scope and policy engines would decide.
        Nothing is executed, no connection is opened, and the engagement is not changed.</small></p>
    <form method="post" action="{{ url_for('engagements.preview_decision', engagement_id=e.id) }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="text" class="wide" name="target" value="{{ preview.target if preview else '' }}"
               placeholder="example.com, 192.0.2.10, 192.0.2.0/28 or https://example.com/app" required>
        <select name="action_type">
            {% for action in known_actions %}
            <option value="{{ action }}"{% if preview and preview.action_type == action %} selected{% endif %}>{{ action }}</option>
            {% endfor %}
        </select>
        <button type="submit" class="secondary">Preview decision</button>
    </form>
    {% if preview %}
    <table>
        <tr><th>Target</th><td><code>{{ preview.target }}</code></td></tr>
        <tr><th>Action</th><td><code>{{ preview.action_type }}</code></td></tr>
        <tr><th>Decision</th>
            <td class="{{ 'status-approved' if preview.decision.allowed else 'status-revoked' }}">
                {{ 'ALLOWED' if preview.decision.allowed else 'DENIED' }}</td></tr>
        <tr><th>Reason</th><td>{{ preview.decision.reason }}</td></tr>
        {% if preview.decision.allowed %}
        <tr><th>Requests per minute</th><td>{{ preview.decision.requests_per_minute }}</td></tr>
        {% endif %}
    </table>
    {% endif %}
</div>
'''

LOCAL_HTTP_BODY = '''
<div class="card">
    <h2>Local lab HTTP check</h2>
    <p><small>One GET to the loopback lab. This demo does not follow redirects.</small></p>
    <form method="post" action="{{ url_for('engagements.local_http_check', engagement_id=e.id) }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <label>Target URL <input type="text" class="wide" name="target" value="{{ lab_url }}" required></label>
        <button type="submit">Run one local GET</button>
    </form>
    {% if http_result %}
    <p>{{ http_result.message }}</p>
    {% if http_result.status is not none %}<p>HTTP status: {{ http_result.status }}</p>{% endif %}
    {% if http_result.preview %}<pre>{{ http_result.preview }}</pre>{% endif %}
    {% endif %}
    <h3>Investigation runs</h3>
    {% if runs is none %}<p class="errors">Investigation history is unavailable.</p>
    {% else %}
    <table><tr><th>#</th><th>Started (UTC)</th><th>Target</th><th>Status</th><th>Checks requiring review</th></tr>
    {% for run in runs %}<tr><td><a href="/engagements/{{ e.id }}/runs/{{ run.id }}">#{{ run.id }} →</a></td><td>{{ run.started_at }}</td>
    <td><code>{{ run.target_reference }}</code></td><td>{{ run.status }}</td><td>{{ run.checks or '-' }}</td></tr>
    {% else %}<tr><td colspan="5">No runs yet.</td></tr>{% endfor %}</table>
    {% endif %}
    <h3>Review observations</h3>
    <small>Passive analysis of the captured response. These are review prompts, not confirmed vulnerabilities.
        Links in HTML were not visited.</small>
    {% if observations is none %}<p class="errors">Observations are unavailable.</p>
    {% else %}
    <table><tr><th>Run</th><th>Check</th><th>Observation</th><th>Review status</th></tr>
    {% for item in observations %}<tr><td>{{ item.run_id }}</td><td>{{ item.check_type }}</td>
        <td>{{ item.title }}<br><small>{{ item.explanation }}</small></td><td>{{ item.review_status }}</td></tr>
    {% else %}<tr><td colspan="4">No observations yet.</td></tr>{% endfor %}</table>
    {% endif %}
    <h3>Recent attempts</h3>
    <small>Last {{ history_limit }} attempts, newest first. Times are UTC. Response bodies are never stored.</small>
    {% if attempts is none %}
    <p class="errors">Audit history is unavailable.</p>
    {% else %}
    <table>
        <tr><th>#</th><th>Time (UTC)</th><th>URL</th><th>Policy</th><th>Outcome</th><th>HTTP status</th><th>Detail</th></tr>
        {% for a in attempts %}
        <tr>
            <td>{{ a.id }}</td>
            <td>{{ a.attempted_at }}</td>
            <td><code>{{ a.requested_url }}</code></td>
            <td class="{{ 'status-approved' if a.policy_decision == 'allowed' else 'status-revoked' }}">{{ a.policy_decision }}<br><small>{{ a.policy_reason }}</small></td>
            <td>{{ a.outcome }}</td>
            <td>{{ a.http_status if a.http_status is not none else '-' }}</td>
            <td>{{ a.detail or '' }}</td>
        </tr>
        {% else %}
        <tr><td colspan="7">No attempts yet.</td></tr>
        {% endfor %}
    </table>
    {% endif %}
</div>
'''


def _render(body, status=200, **context):
    context.setdefault('errors', [])
    return render_template_string(LAYOUT.replace('__BODY__', body), **context), status


def _db_path():
    return current_app.config.get('DATABASE_PATH', DATABASE_PATH)


def _csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return token


@engagements_bp.before_request
def _check_csrf():
    if request.method == 'POST':
        sent = request.form.get('csrf_token', '')
        expected = session.get('csrf_token', '')
        if not sent or not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
            abort(400, "Missing or invalid CSRF token")


def _rows(section):
    types, values = request.form.getlist(f'{section}_type'), request.form.getlist(f'{section}_value')
    return [(kind or '', value or '') for kind, value in zip_longest(types, values)]


def _render_form(form, errors=(), status=200):
    pad = lambda rows: list(rows) + [('', '')] * BLANK_ROWS
    return _render(
        FORM_BODY, status,
        errors=list(errors),
        form=form,
        sections=(('include', 'Included targets', pad(form['includes'])),
                  ('exclude', 'Excluded targets (always take precedence)', pad(form['excludes']))),
        target_types=store.TARGET_TYPES,
        known_actions=KNOWN_ACTIONS,
        max_rpm=MAX_REQUESTS_PER_MINUTE,
        default_rpm=int(DEFAULT_RATE_LIMIT_RPS * 60),
        max_name=store.MAX_NAME_LENGTH,
        csrf_token=_csrf_token(),
    )


@engagements_bp.route('/')
def list_view():
    try:
        engagements = store.list_engagements(_db_path())
    except sqlite3.Error:
        return _render(LIST_BODY, 500, engagements=[], errors=["Engagement database is unavailable"])
    return _render(LIST_BODY, engagements=engagements)


@engagements_bp.route('/new', methods=['GET', 'POST'])
def new_engagement():
    if request.method == 'GET':
        return _render_form({'client_name': '', 'includes': [], 'excludes': [], 'policies': {}})

    form = {
        'client_name': request.form.get('client_name', ''),
        'includes': [r for r in _rows('include') if any(r)],
        'excludes': [r for r in _rows('exclude') if any(r)],
        'policies': {a: request.form.get(f'rpm_{a}', '') for a in request.form.getlist('action')},
    }
    try:
        cleaned = store.validate_engagement(form['client_name'], form['includes'], form['excludes'], form['policies'])
        engagement_id = store.create_engagement(_db_path(), cleaned)
    except store.ValidationError as exc:
        return _render_form(form, exc.errors, 400)
    except sqlite3.Error:
        return _render_form(form, ["Could not save the engagement"], 500)
    return redirect(url_for('engagements.view', engagement_id=engagement_id))


def _render_view(engagement_id, errors=(), status=200, preview=None, http_result=None):
    data = store.get_engagement(_db_path(), engagement_id)
    if data is None:
        abort(404)
    try:
        attempts = audit_log.list_attempts(_db_path(), engagement_id)
    except sqlite3.Error:
        attempts = None
    try:
        runs = investigation_store.list_runs(_db_path(), engagement_id)
    except sqlite3.Error:
        runs = None
    try:
        observations = investigation_store.list_observations(_db_path(), engagement_id)
    except sqlite3.Error:
        observations = None
    return _render(VIEW_BODY + LOCAL_HTTP_BODY, status, e=data['engagement'], data=data, errors=list(errors),
                   csrf_token=_csrf_token(), known_actions=KNOWN_ACTIONS, preview=preview,
                   http_result=http_result, lab_url=LAB_URL,
                   attempts=attempts, runs=runs, observations=observations,
                   history_limit=audit_log.HISTORY_LIMIT)


@engagements_bp.route('/<int:engagement_id>')
def view(engagement_id):
    return _render_view(engagement_id)


@engagements_bp.route('/<int:engagement_id>/approve', methods=['POST'])
def approve(engagement_id):
    if store.get_engagement(_db_path(), engagement_id) is None:
        abort(404)
    if request.form.get('confirm') != 'yes':
        return _render_view(engagement_id, ["Tick the confirmation box to approve"], 400)
    try:
        store.approve_engagement(_db_path(), engagement_id)
    except store.ValidationError as exc:
        return _render_view(engagement_id, exc.errors, 409)
    return redirect(url_for('engagements.view', engagement_id=engagement_id))


@engagements_bp.route('/<int:engagement_id>/preview', methods=['POST'])
def preview_decision(engagement_id):
    """Show the offline policy decision for a target and action. Never performs the action."""
    target = request.form.get('target', '')
    action_type = request.form.get('action_type', '')
    decision = check_policy(_db_path(), engagement_id, target, action_type)
    preview = {'target': target, 'action_type': action_type, 'decision': decision}
    return _render_view(engagement_id, preview=preview)


@engagements_bp.route('/<int:engagement_id>/local-http', methods=['POST'])
def local_http_check(engagement_id):
    """Run one explicitly authorized GET to the loopback lab.

    Every attempt is written to the audit log before fetch_local_lab() runs;
    if that write fails, no request is attempted.
    """
    if store.get_engagement(_db_path(), engagement_id) is None:
        abort(404)
    target = request.form.get('target', '')
    decision = check_policy(_db_path(), engagement_id, target, 'http_request')
    try:
        attempt_id = audit_log.start_attempt(_db_path(), engagement_id, target, decision)
    except sqlite3.Error:
        return _render_view(engagement_id, ["Audit log is unavailable, so no request was made"], 503)
    try:
        run_id = investigation_store.start_run(_db_path(), engagement_id, attempt_id, target)
    except sqlite3.Error:
        audit_log.finish_attempt(_db_path(), attempt_id,
                                 LocalHTTPResult(None, '', 'Investigation storage is unavailable'))
        return _render_view(engagement_id, ["Investigation storage is unavailable, so no request was made"], 503)
    result = fetch_local_lab(_db_path(), engagement_id, target, attempt_id=attempt_id)
    errors = []
    try:
        audit_log.finish_attempt(_db_path(), attempt_id, result)
    except sqlite3.Error:
        errors.append(f"The outcome could not be written to the audit log (attempt #{attempt_id} stays pending)")
    try:
        investigation_store.finish_run(_db_path(), run_id, result)
    except sqlite3.Error:
        errors.append(f"Investigation run #{run_id} could not be completed")
    status = 429 if 'rate limit reached' in result.message else (200 if result.status is not None else 403)
    return _render_view(engagement_id, errors, status=status,
                        http_result=result)
