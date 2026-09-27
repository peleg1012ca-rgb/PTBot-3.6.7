import os
from flask import Flask, render_template_string, request, jsonify, redirect, url_for
from database import init_db, create_scan, get_scan_details, get_all_scans
from scope_checker import validate_target
from tasks import start_scan_in_background
from engagements_ui import engagements_bp
from workbench import bp as workbench_bp, dashboard
from recon_ui import bp as recon_bp
from security import install as install_security
from config import DATABASE_PATH

app = Flask(__name__)
app.secret_key = os.environ.get('AI_PT_SECRET_KEY') or os.urandom(32)
app.config["DATABASE_PATH"] = DATABASE_PATH
app.register_blueprint(engagements_bp)
app.register_blueprint(workbench_bp)
app.register_blueprint(recon_bp)
install_security(app)
init_db()

INDEX_TEMPLATE = """{% extends 'base.html' %}{% block body %}<h1>Legacy scan history</h1><div class="notice">{{ error }}</div><div class="card"><table><tr><th>Target</th><th>Status</th></tr>{% for scan in scans %}<tr><td><a href="/scan/{{ scan.id }}">{{ scan.target }}</a></td><td>{{ scan.status }}</td></tr>{% endfor %}</table></div>{% endblock %}"""
RESULT_TEMPLATE = """{% extends 'base.html' %}{% block body %}<div class="eyebrow">ARCHIVED SCAN #{{ scan.id }}</div><h1>{{ scan.target }}</h1><p class="muted">{{ scan.status }}</p><section class="card"><h2>Services</h2><table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr>{% for s in services %}<tr><td>{{ s.port }}</td><td>{{ s.protocol }}</td><td>{{ s.service_name }}</td><td>{{ s.version }}</td></tr>{% endfor %}</table></section><section class="card"><h2>Findings</h2>{% for f in findings %}<article class="observation"><h3>{{ f.title }}</h3><p>{{ f.description }}</p><pre>{{ f.evidence }}</pre><p>{{ f.remediation }}</p></article>{% endfor %}</section>{% endblock %}"""

@app.route('/')
def index():
    return dashboard()

SCANNING_DISABLED_MESSAGE = "Scanning is disabled until it is connected to approved engagements."


@app.route('/scan', methods=['POST'])
def start_scan():
    """Disabled: never validates, stores or starts anything."""
    scans = get_all_scans()
    return render_template_string(INDEX_TEMPLATE, scans=scans, error=SCANNING_DISABLED_MESSAGE), 403


def legacy_start_scan():
    """Previous /scan implementation, kept unrouted for later integration.

    Not safe to re-enable as is: validate_target() performs DNS and HTTP
    requests, and nothing here checks an approved engagement.
    """
    target_input = request.form.get('target', '')
    is_valid, resolved_ip, target_url, error_msg = validate_target(target_input)
    
    if not is_valid:
        scans = get_all_scans()
        return render_template_string(INDEX_TEMPLATE, scans=scans, error=f"חסימת Scope: {error_msg}")
        
    scan_id = create_scan(target_input)
    start_scan_in_background(scan_id, resolved_ip, target_url)
    return redirect(url_for('view_scan', scan_id=scan_id))

@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    scan, services, findings = get_scan_details(scan_id)
    if scan is None:
        from flask import abort
        abort(404)
    return render_template_string(RESULT_TEMPLATE, scan=scan, services=services, findings=findings)

@app.route('/api/status/<int:scan_id>')
def api_status(scan_id):
    scan, _, _ = get_scan_details(scan_id)
    return jsonify({"status": scan['status'] if scan else "Unknown"})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
