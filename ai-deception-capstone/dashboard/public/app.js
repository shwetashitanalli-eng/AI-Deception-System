function formatNumber(value) {
  return new Intl.NumberFormat('en-US').format(value ?? 0);
}

function getUniqueSources(alerts, canary) {
  const sources = new Set();
  alerts.forEach(item => item.source_ip && sources.add(item.source_ip));
  canary.forEach(item => item.source_ip && sources.add(item.source_ip));
  return sources.size;
}

function buildBuckets(values) {
  const buckets = [0, 0, 0, 0, 0];
  values.forEach(value => {
    if (value >= 80) buckets[4]++;
    else if (value >= 60) buckets[3]++;
    else if (value >= 40) buckets[2]++;
    else if (value >= 20) buckets[1]++;
    else buckets[0]++;
  });
  return buckets;
}

function computeSeverity(value) {
  if (value >= 90) return 'Critical';
  if (value >= 70) return 'High';
  if (value >= 40) return 'Medium';
  return 'Low';
}

function renderSummary(stats, alerts, canary) {
  const highSeverity = (stats.high_threats || 0) + (stats.critical_threats || 0);
  const sourceDiversity = getUniqueSources(alerts, canary);
  const cards = [
    { title: 'Total Logs Analyzed', value: formatNumber(stats.total_logs_analyzed), note: 'Fleet telemetry ingested' },
    { title: 'ML Anomalies', value: formatNumber(stats.total_anomalies), note: 'High-confidence detections' },
    { title: 'Critical Threats', value: formatNumber(stats.critical_threats), note: 'Immediate response candidates' },
    { title: 'Canary Triggers', value: formatNumber(stats.canary_triggers), note: 'Decoys engaged by adversaries' },
    { title: 'Average Score', value: `${formatNumber(stats.avg_threat_score)}/100`, note: 'AI threat confidence' },
    { title: 'Threat Source Diversity', value: formatNumber(sourceDiversity), note: 'Unique attacker IPs' },
    { title: 'High Severity', value: formatNumber(highSeverity), note: 'High + critical alerts' },
  ];

  const container = document.getElementById('summary-cards');
  container.innerHTML = cards.map(card => `
    <div class="metric-card">
      <h3>${card.title}</h3>
      <div class="metric-value">${card.value}</div>
      <div class="metric-note">${card.note}</div>
    </div>
  `).join('');
}

function renderActivityChart(events) {
  const chart = document.getElementById('activity-chart');
  chart.innerHTML = '';
  const buckets = Array(6).fill(0);
  const labels = [];

  const sliced = events.slice(-6);
  sliced.forEach((event, idx) => {
    const label = new Date(event.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    labels.push(label);
    buckets[idx] = 1;
  });

  if (!events.length) {
    chart.innerHTML = '<div style="color:#94a3b8; text-align:center;">No event activity to display</div>';
    return;
  }

  const max = Math.max(...buckets, 1);
  labels.forEach((label, index) => {
    const column = document.createElement('div');
    column.className = 'line-column';
    const dot = document.createElement('div');
    dot.className = 'line-dot';
    dot.style.height = `${(buckets[index] / max) * 100 + 20}%`;
    column.appendChild(dot);
    const caption = document.createElement('div');
    caption.className = 'bar-label';
    caption.textContent = label;
    column.appendChild(caption);
    chart.appendChild(column);
  });
}

function renderScoreChart(alerts, canary) {
  const chart = document.getElementById('score-chart');
  chart.innerHTML = '';
  const scores = [...alerts, ...canary].map(item => item.ai_threat_score ?? 0);
  if (!scores.length) {
    chart.innerHTML = '<div style="color:#94a3b8; text-align:center;">No scores available</div>';
    return;
  }

  const buckets = buildBuckets(scores);
  const labels = ['0-19', '20-39', '40-59', '60-79', '80-100'];
  const max = Math.max(...buckets, 1);

  labels.forEach((label, index) => {
    const bar = document.createElement('div');
    bar.style.width = '100%';
    bar.innerHTML = `
      <div class="bar" style="height:${Math.max((buckets[index] / max) * 160, 24)}px"></div>
      <div class="bar-label">${label}</div>
    `;
    chart.appendChild(bar);
  });
}

function renderSeverityLegend(alerts, canary) {
  const container = document.getElementById('severity-legend');
  container.innerHTML = '';
  const items = [...alerts, ...canary].map(item => computeSeverity(item.ai_threat_score ?? 0));
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  items.forEach(item => counts[item]++);

  const colors = {
    Critical: '#ef4444',
    High: '#f59e0b',
    Medium: '#10b981',
    Low: '#64748b',
  };

  Object.keys(counts).forEach(key => {
    const row = document.createElement('div');
    row.className = 'legend-item';
    row.innerHTML = `
      <span class="legend-color" style="background:${colors[key]}"></span>
      <span>${key}: ${counts[key]}</span>
    `;
    container.appendChild(row);
  });
}

function renderThreatFeed(alerts) {
  const container = document.getElementById('threat-feed');
  container.innerHTML = '';
  if (!alerts || alerts.length === 0) {
    container.innerHTML = '<div class="alert-card"><p>No threat alerts available.</p></div>';
    return;
  }

  alerts.forEach(alert => {
    const card = document.createElement('div');
    card.className = 'alert-card';
    card.innerHTML = `
      <h3>Alert - ${alert.source_ip}</h3>
      <div class="alert-meta">
        <div><strong>Commands:</strong> ${alert.command_count}</div>
        <div><strong>Duration:</strong> ${alert.session_duration_seconds}s</div>
        <div><strong>Failed logins:</strong> ${alert.failed_login_attempts}</div>
        <div><strong>Threat Score:</strong> ${alert.ai_threat_score}</div>
      </div>
    `;
    container.appendChild(card);
  });
}

function renderCanaryEvents(events) {
  const container = document.getElementById('canary-events');
  container.innerHTML = '';
  if (!events || events.length === 0) {
    container.innerHTML = '<div class="canary-card"><p>Canary events unavailable.</p></div>';
    return;
  }

  events.forEach(event => {
    const card = document.createElement('div');
    card.className = 'canary-card';
    card.innerHTML = `
      <h3>${event.threat_type}</h3>
      <div class="canary-meta">
        <div><strong>Source IP:</strong> ${event.source_ip}</div>
        <div><strong>Score:</strong> ${event.ai_threat_score}</div>
        <div><strong>Timestamp:</strong> ${new Date(event.timestamp).toLocaleString()}</div>
        <div><strong>Description:</strong> ${event.description}</div>
      </div>
    `;
    container.appendChild(card);
  });
}

function renderOverviewCaption(stats, alerts, canary) {
  const caption = document.getElementById('overview-caption');
  const totalEvents = alerts.length + canary.length;
  caption.textContent = `${totalEvents} live detections · ${stats.critical_threats || 0} critical · ${stats.canary_triggers || 0} canary triggers`;
}

async function loadDashboard() {
  try {
    const [statsRes, alertsRes, canaryRes] = await Promise.all([
      fetch('/api/stats'),
      fetch('/api/alerts'),
      fetch('/api/canary-events'),
    ]);

    const [stats, alerts, canary] = await Promise.all([
      statsRes.json(),
      alertsRes.json(),
      canaryRes.json(),
    ]);

    const now = new Date();
    document.getElementById('last-updated').textContent = `Updated ${now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;

    renderSummary(stats, alerts, canary);
    renderOverviewCaption(stats, alerts, canary);
    renderActivityChart(canary.length ? canary : alerts);
    renderScoreChart(alerts, canary);
    renderSeverityLegend(alerts, canary);
    renderThreatFeed(alerts);
    renderCanaryEvents(canary);
  } catch (error) {
    document.getElementById('summary-cards').innerHTML = '<div class="metric-card"><p>Error loading dashboard data.</p></div>';
    document.getElementById('threat-feed').innerHTML = '<div class="alert-card"><p>Error loading threat feed.</p></div>';
    document.getElementById('canary-events').innerHTML = '<div class="canary-card"><p>Error loading canary events.</p></div>';
  }
}

loadDashboard();
