'use strict';
document.querySelectorAll('.launch-form').forEach(form => form.addEventListener('submit', () => {
  const button = form.querySelector('button[type="submit"]');
  if (button) { button.disabled = true; button.textContent = 'Starting assessment…'; }
}));
const progress = document.querySelector('[data-run-status]');
if (progress) {
  let polling = true;
  const poll = async () => {
    if (!polling) return;
    try {
      const res = await fetch(progress.dataset.runStatus, {headers:{Accept:'application/json'}});
      if (!res.ok || !res.headers.get('content-type')?.includes('application/json')) throw new Error('status');
      const data = await res.json();
      progress.querySelector('[data-progress]').textContent = data.progress;
      progress.querySelector('[data-request-count]').textContent = data.requests;
      if (data.status !== 'pending') { polling = false; location.reload(); return; }
    } catch (_) {
      progress.querySelector('[data-progress]').textContent = 'Connection interrupted. Refresh to check this run.';
    }
    if (polling) setTimeout(poll, 1500);
  };
  poll();
}
let printDetails = [];
window.addEventListener('beforeprint', () => {
  printDetails = [...document.querySelectorAll('.probe-detail')].map(el => [el, el.open]);
  printDetails.forEach(([el]) => { el.open = true; });
});
window.addEventListener('afterprint', () => printDetails.forEach(([el, opened]) => { el.open = opened; }));
const reconProgress = document.querySelector('[data-recon-status]');
if (reconProgress) {
  const updateRecon = async () => {
    try {
      const res = await fetch(reconProgress.dataset.reconStatus, {headers:{Accept:'application/json'}});
      if (!res.ok || !res.headers.get('content-type')?.includes('application/json')) throw new Error('status');
      const state = await res.json();
      reconProgress.querySelector('[data-recon-progress]').textContent = state.progress;
      Object.entries(state.tools).forEach(([name,info]) => {
        const row = document.querySelector(`[data-module="${name}"]`);
        if (row) {
          const badge = row.querySelector('[data-module-state]');
          badge.textContent = info.status.replaceAll('_',' ');
          badge.className = 'badge ' + info.status;
          row.querySelector('[data-module-message]').textContent = info.message;
        }
      });
      if (state.status !== 'pending') { location.reload(); return; }
    } catch (_) {
      reconProgress.querySelector('[data-recon-progress]').textContent = 'Connection interrupted. Retrying…';
    }
    setTimeout(updateRecon, 1800);
  };
  setTimeout(updateRecon, 500);
}
document.querySelectorAll('[data-print]').forEach(button => button.addEventListener('click', () => window.print()));
document.querySelectorAll('[data-filter-table]').forEach(input => input.addEventListener('input', () => {
  const query = input.value.trim().toLowerCase();
  document.querySelectorAll('#'+input.dataset.filterTable+' tbody tr').forEach(row => {row.hidden = !row.textContent.toLowerCase().includes(query);});
}));
