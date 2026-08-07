async function loadAlerts() {
  try {
    const res = await fetch('/api/alerts');
    const alerts = await res.json();
    const container = document.getElementById('alerts');
    container.innerHTML = '';
    if (!alerts || alerts.length === 0) {
      container.innerText = 'No alerts.';
      return;
    }
    alerts.forEach(a => {
      const el = document.createElement('div');
      el.className = 'card';
      el.innerHTML = `<div><strong>IP:</strong> ${a.source_ip}</div>
        <div><strong>Commands:</strong> ${a.command_count} — <strong>Duration:</strong> ${a.session_duration_seconds}s</div>
        <div><strong>Failed logins:</strong> ${a.failed_login_attempts} — <span class="score">Threat: ${a.ai_threat_score}</span></div>`;
      container.appendChild(el);
    });
  } catch (e) {
    document.getElementById('alerts').innerText = 'Error loading alerts.';
  }
}

loadAlerts();
