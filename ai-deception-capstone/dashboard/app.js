const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Path references to ml_engine output files
const LOGS_PATH = path.join(__dirname, '..', 'ml_engine', 'data', 'cowrie_sample.json');
const ALERTS_PATH = path.join(__dirname, '..', 'ml_engine', 'data', 'canary_alerts.json');

// API Endpoint: Get Canary Token Triggered Alerts
app.get('/api/canary-alerts', (req, res) => {
    if (!fs.existsSync(ALERTS_PATH)) {
        return res.json({ status: 'success', data: [] });
    }
    fs.readFile(ALERTS_PATH, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).json({ status: 'error', message: 'Failed to read Canary alerts' });
        }
        try {
            const alerts = JSON.parse(data);
            res.json({ status: 'success', count: alerts.length, data: alerts });
        } catch (parseErr) {
            res.status(500).json({ status: 'error', message: 'Error parsing Canary log data' });
        }
    });
});

// API Endpoint: Get Real-time System Metrics and Session Summaries
app.get('/api/soc-summary', (req, res) => {
    let rawLogs = [];
    let canaryAlerts = [];

    if (fs.existsSync(LOGS_PATH)) {
        rawLogs = JSON.parse(fs.readFileSync(LOGS_PATH, 'utf8') || '[]');
    }
    if (fs.existsSync(ALERTS_PATH)) {
        canaryAlerts = JSON.parse(fs.readFileSync(ALERTS_PATH, 'utf8') || '[]');
    }

    const totalSessions = new Set(rawLogs.map(log => log.session)).size;
    const fileUploads = rawLogs.filter(log => log.eventid === 'cowrie.session.file_upload').length;
    const failedLogins = rawLogs.filter(log => log.eventid === 'cowrie.login.failed').length;

    res.json({
        status: 'success',
        metrics: {
            active_sessions: totalSessions,
            total_failed_logins: failedLogins,
            file_upload_events: fileUploads,
            canary_triggers: canaryAlerts.length
        }
    });
});

app.listen(PORT, () => {
    console.log(`[+] SOC Dashboard Server running on http://localhost:${PORT}`);
});
