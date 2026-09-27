"""Assessments hub, website Recon form, live result dashboard and JSON export."""
import json
import sqlite3
from flask import Blueprint, current_app, render_template, request, redirect, url_for, abort, jsonify, Response
from config import DATABASE_PATH
from security import validate_csrf
import engagement_store
import workbench_store as store
import recon_store
import recon_engine
import recon_tools

bp=Blueprint('recon', __name__)

def db(): return current_app.config.get('DATABASE_PATH', DATABASE_PATH)

def engagement(eid):
    data=engagement_store.get_engagement(db(),eid)
    if not data: abort(404)
    return data

@bp.before_request
def csrf():
    if request.method=='POST': validate_csrf()

@bp.get('/assessments')
def index():
    return render_template('assessments.html', engagements=engagement_store.list_engagements(db()),
                           recent=recon_store.recent(db()))

@bp.route('/assessments/<int:eid>/recon',methods=['GET','POST'])
def setup(eid):
    data=engagement(eid); error=None
    if request.method=='POST':
        try:
            rid=recon_engine.start(db(),eid,request.form.get('target',''),request.form.getlist('modules'),
                  request.form.get('ports','80,443,8080,8443'),request.form.get('discovery_domain',''))
            return redirect(url_for('recon.result',eid=eid,rid=rid))
        except (ValueError,sqlite3.Error) as exc:
            error=str(exc) if isinstance(exc,ValueError) else 'Could not save the assessment'
    suggested=next((r['target_value'] for r in data['includes'] if r['target_type']=='url'), '')
    if not suggested:
        suggested=next((r['target_value'] for r in data['includes'] if r['target_type'] in ('domain','ip')), '')
    return render_template('recon_setup.html',data=data,error=error,suggested=suggested,
                           tools=recon_tools.availability(), recent=recon_store.recent(db(),eid)), 400 if error else 200

@bp.get('/assessments/<int:eid>/recon/<int:rid>')
def result(eid,rid):
    item=recon_store.detail(db(),eid,rid)
    if not item: abort(404)
    if request.args.get('format')=='json':
        return Response(json.dumps(item,ensure_ascii=False,indent=2),mimetype='application/json',
                        headers={'Content-Disposition':f'attachment; filename=recon-{rid}.json'})
    return render_template('recon_result.html',run=item,r=item['result'])

@bp.get('/assessments/<int:eid>/recon/<int:rid>/status')
def status(eid,rid):
    item=recon_store.detail(db(),eid,rid)
    if not item: abort(404)
    return jsonify(status=item['status'],progress=item['progress'],tools=item['result'].get('tools',{}))

@bp.post('/assessments/<int:eid>/recon/<int:rid>/cancel')
def cancel(eid,rid):
    item=recon_store.detail(db(),eid,rid)
    if not item: abort(404)
    with store.connect(db()) as c: c.execute('UPDATE recon_runs SET cancel_requested=1 WHERE run_id=?',(rid,))
    return redirect(url_for('recon.result',eid=eid,rid=rid))
