const API_URL = "http://localhost:8000";

// 1. Initialize on Page Load
document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    
    if (!token) {
        console.warn('No active auth token found.');
        document.getElementById("loginPage").style.display = "flex";
        document.getElementById("app").style.display = "none";
    } else {
        bootApp();
    }
});

// 2. Authentication Logic
async function performLogin() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const errorDiv = document.getElementById("loginError");

    try {
        const response = await fetch(`${API_URL}/api/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) throw new Error("Unauthorized");

        const data = await response.json();
        localStorage.setItem("token", data.access_token);
        localStorage.setItem("username", data.username);
        localStorage.setItem("fullName", data.full_name || data.username);
        
        bootApp();
    } catch (err) {
        errorDiv.style.display = "block";
    }
}

function logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    localStorage.removeItem("fullName");
    document.getElementById("app").style.display = "none";
    document.getElementById("loginPage").style.display = "flex";
    document.getElementById("username").value = "";
    document.getElementById("password").value = "";
}

// 3. Application Boot Sequence
function bootApp() {
    document.getElementById("loginPage").style.display = "none";
    document.getElementById("app").style.display = "block";
    
    // Display the real user name
    const realName = localStorage.getItem("fullName") || "Security Analyst";
    document.getElementById("displayUsername").innerText = realName;
    
    fetchBackendData();
}

// 4. Fetch Live Data from Backend
async function fetchBackendData() {
    const token = localStorage.getItem("token");
    const headers = { "Authorization": `Bearer ${token}` };

    try {
        // Fetch Summary Stats
        const sumRes = await fetch(`${API_URL}/api/dashboard/summary`, { headers });
        const summary = await sumRes.json();
        
        document.getElementById("statLogs").innerText = summary.total_logs_analyzed;
        document.getElementById("statAnomalies").innerText = summary.ml_anomalies;
        document.getElementById("statCritical").innerText = summary.critical_threats;
        document.getElementById("statCanary").innerText = summary.canary_triggers;
        document.getElementById("statScore").innerText = `${summary.average_threat_score}/100`;
        document.getElementById("statIps").innerText = summary.unique_attacker_ips;

        // Fetch Honeypot Sessions
        const sessRes = await fetch(`${API_URL}/api/honeypot/sessions`, { headers });
        const sessions = await sessRes.json();
        
        const homeSessionHtml = sessions.map(s => `
            <tr>
                <td class="font-mono">${s.source_ip}</td>
                <td>${s.event_type}</td>
                <td>${s.username || 'root'}</td>
                <td><span class="status ${s.ml_status === 'ANOMALY' ? 'anomaly' : 'medium'}">${s.ml_status}</span></td>
            </tr>
        `).join('');
        
        const sessionTable = document.getElementById("homeSessionTable");
        if (sessionTable) sessionTable.innerHTML = homeSessionHtml;

    } catch (err) {
        console.error("Failed to sync telemetry from backend API:", err);
    }
}

// 5. Sidebar Navigation Router
function showPage(pageId, element) {
    // Hide all pages
    document.querySelectorAll(".page").forEach(page => {
        page.classList.remove("active-page");
    });
    
    // Show selected page
    const selected = document.getElementById(pageId);
    if (selected) {
        selected.classList.add("active-page");
    }

    // Update active sidebar styling
    document.querySelectorAll(".nav-item").forEach(item => {
        item.classList.remove("active");
    });
    if (element) {
        element.classList.add("active");
    }

    // Update Header Title dynamically
    const titles = {
        dashboard: "Dashboard",
        honeypot: "Honeypot Monitoring",
        logs: "Honeypot Logs",
        canary: "Canary Token Monitoring",
        ml: "AI / ML Engine",
        anomalies: "ML Anomalies",
        alerts: "Security Alerts",
        analytics: "Security Analytics",
        reports: "Security Reports",
        settings: "System Settings"
    };

    const headerTitle = document.getElementById("pageTitle");
    if (headerTitle) {
        headerTitle.innerText = titles[pageId] || "Dashboard";
    }
}