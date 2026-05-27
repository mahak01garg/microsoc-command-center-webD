// Dashboard Specific JavaScript

// Initialize Dashboard
function initDashboard() {
    loadStats();
    loadAttackTrends();
    loadTopAttackers();
    startLogStream();
    initCharts();
}

// Load Stats Cards
function loadStats() {
    const stats = [
        {
            icon: 'fa-broadcast-tower',
            title: 'Total Logs',
            value: '12,478',
            change: '+3.2%',
            changeType: 'positive',
            color: '#007bff'
        },
        {
            icon: 'fa-exclamation-triangle',
            title: 'Active Incidents',
            value: '23',
            change: '-2',
            changeType: 'negative',
            color: '#dc3545'
        },
        {
            icon: 'fa-skull-crossbones',
            title: 'Critical Threats',
            value: '5',
            change: '+1',
            changeType: 'negative',
            color: '#fd7e14'
        },
        {
            icon: 'fa-clock',
            title: 'Avg Response Time',
            value: '2.4h',
            change: '-0.5h',
            changeType: 'positive',
            color: '#28a745'
        },
        {
            icon: 'fa-shield-alt',
            title: 'Attacks Today',
            value: '347',
            change: '+12%',
            changeType: 'negative',
            color: '#17a2b8'
        },
        {
            icon: 'fa-check-circle',
            title: 'Prevented Attacks',
            value: '289',
            change: '+8%',
            changeType: 'positive',
            color: '#28a745'
        }
    ];
    
    const container = document.getElementById('stats-container');
    if (!container) return;
    
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
}

// Load Attack Trends Chart
function loadAttackTrends() {
    const ctx = document.getElementById('attackTrendsChart');
    if (!ctx) return;
    
    const data = {
        labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        datasets: [
            {
                label: 'XSS Attacks',
                data: [45, 32, 56, 28, 39, 25, 42],
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                tension: 0.4
            },
            {
                label: 'SQL Injection',
                data: [28, 35, 31, 42, 26, 38, 29],
                borderColor: '#007bff',
                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                tension: 0.4
            },
            {
                label: 'Port Scans',
                data: [78, 65, 89, 72, 81, 68, 75],
                borderColor: '#28a745',
                backgroundColor: 'rgba(40, 167, 69, 0.1)',
                tension: 0.4
            },
            {
                label: 'Brute Force',
                data: [42, 38, 51, 34, 47, 41, 39],
                borderColor: '#ffc107',
                backgroundColor: 'rgba(255, 193, 7, 0.1)',
                tension: 0.4
            }
        ]
    };
    
    new Chart(ctx, {
        type: 'line',
        data: data,
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
function loadTopAttackers() {
    const attackers = [
        { ip: '192.168.1.105', country: 'USA', attacks: 245, lastSeen: new Date(Date.now() - 3600000) },
        { ip: '10.0.0.42', country: 'China', attacks: 189, lastSeen: new Date(Date.now() - 7200000) },
        { ip: '172.16.0.88', country: 'Russia', attacks: 156, lastSeen: new Date(Date.now() - 10800000) },
        { ip: '203.0.113.25', country: 'Germany', attacks: 98, lastSeen: new Date(Date.now() - 14400000) },
        { ip: '198.51.100.13', country: 'India', attacks: 134, lastSeen: new Date(Date.now() - 18000000) }
    ];
    
    const container = document.getElementById('top-attackers');
    if (!container) return;
    
    container.innerHTML = attackers.map(attacker => `
        <tr>
            <td class="ip-address">${attacker.ip}</td>
            <td>
                <i class="fas fa-globe-americas"></i>
                ${attacker.country}
            </td>
            <td>
                <span class="badge badge-danger">${attacker.attacks}</span>
            </td>
            <td class="timestamp">
                ${formatDate(attacker.lastSeen)}
            </td>
        </tr>
    `).join('');
}

// Start Real-time Log Stream
function startLogStream() {
    const container = document.getElementById('realtime-logs');
    if (!container) return;
    
    // Initial logs
    generateLogs(container, 10);
    
    // Add new log every 5 seconds
    setInterval(() => {
        generateLogs(container, 1);
    }, 5001);
}

// Generate Logs
function generateLogs(container, count) {
    const attackTypes = ['XSS', 'SQL Injection', 'Port Scan', 'Brute Force', 'DDoS', 'Malware'];
    const severities = ['low', 'medium', 'high', 'critical'];
    const countries = ['USA', 'China', 'Russia', 'Germany', 'India', 'Brazil', 'Japan'];
    
    for (let i = 0; i < count; i++) {
        const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
        const severity = severities[Math.floor(Math.random() * severities.length)];
        const ip = generateIP();
        const country = countries[Math.floor(Math.random() * countries.length)];
        
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        logEntry.innerHTML = `
            <div class="log-icon" style="color: ${getSeverityColor(severity)}">
                <i class="fas ${getAttackTypeIcon(attackType)}"></i>
            </div>
            <div class="log-content">
                <strong>${attackType}</strong> attack detected
                <div class="log-meta">
                    <span class="log-ip">${ip}</span>
                    <span class="log-severity badge" style="background: ${getSeverityColor(severity)}">${severity.toUpperCase()}</span>
                    <span class="log-country">${country}</span>
                    <span class="log-time">${new Date().toLocaleTimeString()}</span>
                </div>
            </div>
        `;
        
        container.insertBefore(logEntry, container.firstChild);
        
        // Limit to 20 logs
        if (container.children.length > 20) {
            container.removeChild(container.lastChild);
        }
        
        // Update incident count if critical
        if (severity === 'critical') {
            updateIncidentCount();
        }
    }
}

// Clear Logs
function clearLogs() {
    const container = document.getElementById('realtime-logs');
    if (container) {
        container.innerHTML = '';
        generateLogs(container, 5); // Add initial logs back
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