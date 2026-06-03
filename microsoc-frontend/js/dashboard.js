// Dashboard Specific JavaScript

function getApiBaseUrl() {
    return window.MICROSOC_API_BASE_URL || 'http://localhost:5001/api';
}

function getAuthHeaders() {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
    };
}

// Initialize Dashboard
function initDashboard() {
    loadStats();
    loadAttackTrends();
    loadTopAttackers();
    initCharts();
}

// Load Stats Cards
async function loadStats() {
    const container = document.getElementById('stats-container');
    if (!container) return;
    container.innerHTML = '<div class="empty-state">Loading dashboard stats...</div>';

    try {
        const response = await fetch(`${getApiBaseUrl()}/dashboard/stats`, {
            headers: getAuthHeaders()
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'Could not load dashboard stats');
        }
        const stats = payload.stats || [];

    container.innerHTML = stats.map(stat => `
        <div class="stat-card">
            <div class="stat-icon" style="background: ${stat.color}20; color: ${stat.color}">
                <i class="fas ${stat.icon}"></i>
            </div>
            <div class="stat-info">
                <h3>${stat.title}</h3>
                <div class="stat-value">${stat.value}</div>
                <div class="stat-change ${stat.changeType}">
                    <i class="fas fa-arrow-${stat.changeType === 'positive' ? 'up' : 'down'}"></i>
                    ${stat.change}
                </div>
            </div>
        </div>
    `).join('');
    } catch (error) {
        console.error('Dashboard stats failed:', error);
        container.innerHTML = '<div class="empty-state">No live dashboard stats available. Check backend/session.</div>';
    }
}

// Load Attack Trends Chart
async function loadAttackTrends() {
    const ctx = document.getElementById('attackTrendsChart');
    if (!ctx) return;

    let data;
    try {
        const response = await fetch(`${getApiBaseUrl()}/analytics/threat-timeline?timeRange=7d`, {
            headers: getAuthHeaders()
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'Could not load threat timeline');
        }
        data = payload.timeline || payload.data?.timeline;
    } catch (error) {
        console.error('Attack trends failed:', error);
        return;
    }

    if (window.attackTrendsChart?.destroy) {
        window.attackTrendsChart.destroy();
    }

    const chartData = data?.labels && data?.datasets
        ? data
        : {
            labels: [],
            datasets: []
        };

    window.attackTrendsChart = new Chart(ctx, {
        type: 'line',
        data: chartData,
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0, 0, 0, 0.1)'
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

// Load Top Attackers
async function loadTopAttackers() {
    const container = document.getElementById('top-attackers');
    if (!container) return;
    container.innerHTML = '<tr><td colspan="4">Loading top attackers...</td></tr>';

    try {
        const response = await fetch(`${getApiBaseUrl()}/dashboard/realtime`, {
            headers: getAuthHeaders()
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'Could not load top attackers');
        }
        const attackers = payload.realtimeData?.topAttackers || [];

    container.innerHTML = attackers.map(attacker => `
        <tr>
            <td class="ip-address">${attacker.ip || attacker._id}</td>
            <td>
                <i class="fas fa-globe-americas"></i>
                ${attacker.country || 'Unknown'}
            </td>
            <td>
                <span class="badge badge-danger">${attacker.attacks || attacker.count || 0}</span>
            </td>
            <td class="timestamp">
                ${formatDate(attacker.lastSeen)}
            </td>
        </tr>
    `).join('') || '<tr><td colspan="4">No attacker data yet.</td></tr>';
    } catch (error) {
        console.error('Top attackers failed:', error);
        container.innerHTML = '<tr><td colspan="4">No live attacker data available.</td></tr>';
    }
}

// Start Real-time Log Stream
function startLogStream() {
    const container = document.getElementById('realtime-logs');
    if (!container) return;

    container.innerHTML = '';
    fetch(`${getApiBaseUrl()}/logs?limit=10&timeRange=all`, { headers: getAuthHeaders() })
        .then(response => response.json())
        .then(payload => {
            (payload.logs || []).reverse().forEach(log => appendLog(container, log));
        })
        .catch(error => {
            console.error('Initial realtime logs failed:', error);
        });

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${new URL(getApiBaseUrl()).host}/ws/threat-feed`;
    const socket = new WebSocket(wsUrl);
    socket.addEventListener('message', event => {
        const payload = JSON.parse(event.data);
        if (payload.log) appendLog(container, payload.log);
    });
}

function appendLog(container, log) {
    const severity = log.severity || 'medium';
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    logEntry.innerHTML = `
        <div class="log-icon" style="color: ${getSeverityColor(severity)}">
            <i class="fas ${getAttackTypeIcon(log.attackType || 'Other')}"></i>
        </div>
        <div class="log-content">
            <strong>${log.attackType || 'Threat'}</strong> attack detected
            <div class="log-meta">
                <span class="log-ip">${log.sourceIP || 'Unknown'}</span>
                <span class="log-severity badge" style="background: ${getSeverityColor(severity)}">${severity.toUpperCase()}</span>
                <span class="log-country">${log.country || 'Unknown'}</span>
                <span class="log-time">${new Date(log.timestamp || Date.now()).toLocaleTimeString()}</span>
            </div>
        </div>
    `;

    container.insertBefore(logEntry, container.firstChild);

    if (container.children.length > 20) {
        container.removeChild(container.lastChild);
    }
}

// Clear Logs
function clearLogs() {
    const container = document.getElementById('realtime-logs');
    if (container) {
        container.innerHTML = '';
    }
}

// Update Incident Count
function updateIncidentCount() {
    const incidentCount = document.getElementById('incident-count');
    if (incidentCount) {
        let count = parseInt(incidentCount.textContent) || 0;
        count++;
        incidentCount.textContent = count;
    }
}

// Update Chart
function updateChart() {
    const timeRange = document.getElementById('time-range').value;
    // In a real app, this would fetch new data based on time range
    console.log('Updating chart for:', timeRange);
}

// Initialize Charts
function initCharts() {
    // Additional charts can be initialized here
}
function loadUserProfile() {
    const user = JSON.parse(localStorage.getItem('user'));
    if (!user) return;
    
    // Profile information update karo
    document.getElementById('profile-name').textContent = user.name;
    document.getElementById('profile-role').textContent = `Role: ${user.role}`;
    document.getElementById('profile-email').textContent = `Email: ${user.email}`;
    
    // Last login time
    const lastLogin = localStorage.getItem('lastLogin') || new Date().toISOString();
    document.getElementById('profile-last-login').textContent = 
        `Last Login: ${formatDateTime(lastLogin)}`;
    
    // Save current login time
    localStorage.setItem('lastLogin', new Date().toISOString());
}

// Export functions
window.loadStats = loadStats;
window.loadAttackTrends = loadAttackTrends;
window.loadTopAttackers = loadTopAttackers;
window.startLogStream = startLogStream;
window.clearLogs = clearLogs;
window.updateChart = updateChart;
window.initDashboard = initDashboard;
