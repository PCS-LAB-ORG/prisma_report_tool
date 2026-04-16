const F = () => window.TenantCtx ? TenantCtx.apiFetch : fetch;
let editingId = null;

function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }

document.addEventListener('DOMContentLoaded', () => {
  loadSchedules();
  loadHistory();
  loadTemplates();
});

async function loadTemplates() {
  try {
    const r = await F()('/api/templates');
    const templates = await r.json();
    const sel = document.getElementById('sched-template');
    sel.innerHTML = '<option value="">Select a template…</option>' +
      templates.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
  } catch (_) {}
}

async function loadSchedules() {
  try {
    const r = await F()('/api/schedules');
    const rows = await r.json();
    const tbody = document.getElementById('schedules-body');
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="8">No schedules yet. Create one to automate reports.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(s => `<tr>
      <td class="primary">${esc(s.name)}</td>
      <td>${esc(s.template_name || '—')}</td>
      <td><code style="font-family:var(--mono);font-size:var(--text-sm)">${esc(s.cron_expr)}</code></td>
      <td><span class="badge badge-gray">${(s.format || 'pdf').toUpperCase()}</span></td>
      <td class="text-muted">${esc(s.email_to || '—')}</td>
      <td class="text-muted mono" style="font-size:var(--text-sm)">${s.last_run ? s.last_run.slice(0, 16) : '—'}</td>
      <td>${s.enabled ? '<span class="badge badge-green">Active</span>' : '<span class="badge badge-gray">Paused</span>'}</td>
      <td class="right" style="white-space:nowrap">
        <button class="btn btn-ghost sm" onclick="toggleSchedule(${s.id},${s.enabled ? 0 : 1})">${s.enabled ? 'Pause' : 'Enable'}</button>
        <button class="btn btn-ghost sm" onclick="editSchedule(${s.id})">Edit</button>
        <button class="btn btn-ghost sm" style="color:var(--red)" onclick="deleteSchedule(${s.id})">Delete</button>
      </td>
    </tr>`).join('');
  } catch (e) {
    document.getElementById('schedules-body').innerHTML = '<tr><td colspan="8">Error loading schedules</td></tr>';
  }
}

async function loadHistory() {
  try {
    const r = await F()('/api/reports/history');
    const rows = await r.json();
    const tbody = document.getElementById('history-body');
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No reports generated yet.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(h => `<tr>
      <td class="primary">${esc(h.title || 'Untitled')}</td>
      <td><span class="badge badge-gray">${(h.format || '?').toUpperCase()}</span></td>
      <td class="text-muted mono" style="font-size:var(--text-sm)">${(h.created_at || '').slice(0, 16)}</td>
      <td class="right"><a href="/api/reports/download/${h.id}" class="btn btn-secondary sm" download>Download</a></td>
    </tr>`).join('');
  } catch (_) {
    document.getElementById('history-body').innerHTML = '<tr><td colspan="4">Error loading history</td></tr>';
  }
}

function showAddForm() {
  editingId = null;
  document.getElementById('form-title').textContent = 'New Schedule';
  document.getElementById('sched-name').value = '';
  document.getElementById('sched-cron').value = '';
  document.getElementById('sched-email').value = '';
  document.getElementById('sched-format').value = 'pdf';
  document.getElementById('sched-template').value = '';
  document.getElementById('schedule-form').style.display = 'block';
  document.getElementById('sched-name').focus();
}

function hideForm() {
  document.getElementById('schedule-form').style.display = 'none';
  editingId = null;
}

async function editSchedule(id) {
  try {
    const r = await F()('/api/schedules');
    const all = await r.json();
    const s = all.find(x => x.id === id);
    if (!s) return;
    editingId = id;
    document.getElementById('form-title').textContent = 'Edit Schedule';
    document.getElementById('sched-name').value = s.name;
    document.getElementById('sched-cron').value = s.cron_expr;
    document.getElementById('sched-email').value = s.email_to || '';
    document.getElementById('sched-format').value = s.format || 'pdf';
    document.getElementById('sched-template').value = s.template_id || '';
    document.getElementById('schedule-form').style.display = 'block';
  } catch (_) {}
}

async function saveSchedule() {
  const body = {
    name: document.getElementById('sched-name').value,
    template_id: Number(document.getElementById('sched-template').value),
    cron_expr: document.getElementById('sched-cron').value,
    format: document.getElementById('sched-format').value,
    email_to: document.getElementById('sched-email').value || null,
    enabled: true,
  };
  if (!body.name || !body.template_id || !body.cron_expr) {
    alert('Name, template, and cron expression are required.');
    return;
  }
  try {
    const url = editingId ? `/api/schedules/${editingId}` : '/api/schedules';
    const method = editingId ? 'PUT' : 'POST';
    const r = await F()(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const d = await r.json();
    if (d.error) { alert(d.error); return; }
    hideForm();
    loadSchedules();
  } catch (e) { alert('Error: ' + e.message); }
}

async function toggleSchedule(id, enabled) {
  try {
    await F()(`/api/schedules/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !!enabled }) });
    loadSchedules();
  } catch (_) {}
}

async function deleteSchedule(id) {
  if (!confirm('Delete this schedule?')) return;
  try {
    await F()(`/api/schedules/${id}`, { method: 'DELETE' });
    loadSchedules();
  } catch (_) {}
}
