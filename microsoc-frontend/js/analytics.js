// analytics.js - Analytics Page JavaScript

// Analytics Data
let attackDistributionChart = null;
let threatTimelineChart = null; 
let analyticsData = {
    attackDistribution: {},
    threatTimeline: [],
    patterns: [],
    topSources: [],
    anomalies: [],
    remediations: [],
    predictions: [],
    aiInsights: []
};

const attackTypes = [
    "Brute Force",
    "SQL Injection",
    "XSS Attempt",
    "DDoS Attack",
    "Malware Detected",
    "Port Scanning"
];

function addThreatFeedItem() {
    const feed = document.getElementById("threatFeed");
    if (!feed) return;

    const attack = attackTypes[Math.floor(Math.random() * attackTypes.length)];
    const time = new Date().toLocaleTimeString();

    const li = document.createElement("li");
    li.textContent = `[${time}] ${attack} detected`;

    feed.prepend(li);

    // limit feed size
    if (feed.children.length > 10) {
        feed.removeChild(feed.lastChild);
    }
}

function startThreatFeed() {
    setInterval(addThreatFeedItem, 4000);
}

// Initialize Analytics
function initAnalytics() {
    // Load mock data
    loadAnalyticsData();
    
    // Initialize charts
    initCharts();
    
    // Load patterns
    loadPatterns();
    
    // Load top sources
    loadTopSources();
    
    // Load anomalies
    loadAnomalies();
    
    // Load remediations
    loadRemediations();
    
    // Load predictions
    loadPredictions();
    
    // Load AI insights
    loadAIInsights();
    
    // Update stats
    updateAnalyticsStats();

    startLiveSimulation();

    startThreatFeed();

}

// Load Analytics Data
function loadAnalyticsData() {
    // Attack Distribution Data
    analyticsData.attackDistribution = {
        labels: ['XSS', 'SQL Injection', 'Port Scan', 'Brute Force', 'DDoS', 'Malware', 'Phishing'],
        datasets: [{
            data: [25, 20, 18, 15, 10, 8, 4],
            backgroundColor: [
                '#dc3545', '#fd7e14', '#ffc107', '#28a745',
                '#17a2b8', '#6f42c1', '#e83e8c'
            ]
        }]
    };
    
    // Threat Timeline Data
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    analyticsData.threatTimeline = {
        labels: days,
        datasets: [
            {
                label: 'Critical',
                data: days.map(() => Math.floor(Math.random() * 20) + 5),
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                tension: 0.4
            },
            {
                label: 'High',
                data: days.map(() => Math.floor(Math.random() * 30) + 10),
                borderColor: '#fd7e14',
                backgroundColor: 'rgba(253, 126, 20, 0.1)',
                tension: 0.4
            },
            {
                label: 'Medium',
                data: days.map(() => Math.floor(Math.random() * 40) + 15),
                borderColor: '#ffc107',
                backgroundColor: 'rgba(255, 193, 7, 0.1)',
                tension: 0.4
            }
        ]
    };
}
function startLiveSimulation() {
    setInterval(() => {
        // Random attack count increase
        analyticsData.attackDistribution.datasets[0].data =
            analyticsData.attackDistribution.datasets[0].data.map(
                val => val + Math.floor(Math.random() * 3)
            );

        // Update doughnut chart
        if (attackDistributionChart instanceof Chart) {
            attackDistributionChart.update();
        }

        // Timeline chart update
        const timelineData = analyticsData.threatTimeline.datasets[0].data;
        timelineData.shift();
        timelineData.push(Math.floor(Math.random() * 20));

        if (window.threatTimelineChart instanceof Chart) {
            window.threatTimelineChart.update();
        }

    }, 3000); // every 3 sec
}

// Initialize Charts
function initCharts() {

    // ===============================
    // Attack Distribution Chart
    // ===============================
    const attackDistributionCtx = document.getElementById('attackDistributionChart');
    if (attackDistributionCtx) {

        // ✅ destroy only if real Chart object
        if (attackDistributionChart instanceof Chart) {
            attackDistributionChart.destroy();
        }

        attackDistributionChart = new Chart(attackDistributionCtx, {
            type: 'doughnut',
            data: analyticsData.attackDistribution,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} attacks (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });

        createAttackDistributionLegend();
    }

    // ===============================
    // Threat Timeline Chart
    // ===============================
    const threatTimelineCtx = document.getElementById('threatTimelineChart');
    if (threatTimelineCtx) {

        // ✅ destroy only if real Chart object
        if (window.threatTimelineChart instanceof Chart) {
            window.threatTimelineChart.destroy();
        }

        window.threatTimelineChart = new Chart(threatTimelineCtx, {
            type: 'line',
            data: analyticsData.threatTimeline,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top' }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Attacks'
                        }
                    }
                }
            }
        });
    }
}


// Create Attack Distribution Legend
function createAttackDistributionLegend() {
    const legendContainer = document.getElementById('attack-distribution-legend');
    if (!legendContainer || !analyticsData.attackDistribution.labels) return;
    
    const colors = analyticsData.attackDistribution.datasets[0].backgroundColor;
    const data = analyticsData.attackDistribution.datasets[0].data;
    const total = data.reduce((a, b) => a + b, 0);
    
    legendContainer.innerHTML = analyticsData.attackDistribution.labels.map((label, index) => {
        const percentage = Math.round((data[index] / total) * 100);
        return `
            <div class="legend-item">
                <span class="legend-color" style="background: ${colors[index]}"></span>
                <span>${label}: ${percentage}%</span>
            </div>
        `;
    }).join('');
}

// Toggle Timeline View
function toggleTimelineView() {
    if (!window.threatTimelineChart) return;
    
    const currentType = window.threatTimelineChart.config.type;
    const newType = currentType === 'line' ? 'bar' : 'line';
    
    window.threatTimelineChart.config.type = newType;
    window.threatTimelineChart.update();
}

// Load Patterns
function loadPatterns() {
    const patterns = [
        {
            id: 1,
            name: 'Distributed Brute Force',
            confidence: 92,
            description: 'Multiple IP addresses targeting same credentials within 5-minute window',
            type: 'Brute Force',
            frequency: '45 attacks/hour',
            timeframe: 'Last 24 hours',
            severity: 'High'
        },
        {
            id: 2,
            name: 'Port Scan Cascade',
            confidence: 87,
            description: 'Sequential port scanning from same subnet',
            type: 'Port Scan',
            frequency: '120 scans/minute',
            timeframe: 'Last 2 hours',
            severity: 'Medium'
        },
        {
            id: 3,
            name: 'XSS Payload Pattern',
            confidence: 95,
            description: 'Similar XSS payloads across multiple endpoints',
            type: 'XSS',
            frequency: '18 attacks',
            timeframe: 'Last 6 hours',
            severity: 'High'
        },
        {
            id: 4,
            name: 'SQL Injection Pattern',
            confidence: 84,
            description: 'Common SQL injection attempts on login forms',
            type: 'SQL Injection',
            frequency: '32 attempts',
            timeframe: 'Last 12 hours',
            severity: 'Critical'
        },
        {
            id: 5,
            name: 'Geolocation Cluster',
            confidence: 78,
            description: 'Attacks originating from same geographic region',
            type: 'Geographic',
            frequency: '89 attacks',
            timeframe: 'Last 48 hours',
            severity: 'Medium'
        }
    ];
    
    analyticsData.patterns = patterns;
    
    const container = document.getElementById('patterns-list');
    if (!container) return;
    
    container.innerHTML = patterns.map(pattern => `
        <div class="pattern-item" onclick="showPatternDetail(${pattern.id})">
            <div class="pattern-header">
                <span class="pattern-name">${pattern.name}</span>
                <span class="pattern-confidence">${pattern.confidence}%</span>
            </div>
            <div class="pattern-description">${pattern.description}</div>
            <div class="pattern-meta">
                <span><i class="fas fa-bug"></i> ${pattern.type}</span>
                <span><i class="fas fa-wave-square"></i> ${pattern.frequency}</span>
                <span><i class="fas fa-clock"></i> ${pattern.timeframe}</span>
            </div>
        </div>
    `).join('');
    
    document.getElementById('patterns-detected').textContent = `${patterns.length} patterns`;
}

// Show Pattern Detail
function showPatternDetail(patternId) {
    const pattern = analyticsData.patterns.find(p => p.id === patternId);
    if (!pattern) return;
    
    const content = document.getElementById('pattern-detail-content');
    content.innerHTML = `
        <div class="pattern-detail">
            <div class="detail-header">
                <h4>${pattern.name}</h4>
                <div class="detail-meta">
                    <span class="badge" style="background: ${getSeverityColor(pattern.severity)}">
                        ${pattern.severity}
                    </span>
                    <span class="confidence">Confidence: ${pattern.confidence}%</span>
                </div>
            </div>
            
            <div class="detail-section">
                <h5><i class="fas fa-info-circle"></i> Description</h5>
                <p>${pattern.description}</p>
            </div>
            
            <div class="detail-section">
                <h5><i class="fas fa-chart-line"></i> Statistics</h5>
                <div class="stats-grid">
                    <div class="stat">
                        <div class="stat-label">Attack Type</div>
                        <div class="stat-value">${pattern.type}</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Frequency</div>
                        <div class="stat-value">${pattern.frequency}</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Timeframe</div>
                        <div class="stat-value">${pattern.timeframe}</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">First Detected</div>
                        <div class="stat-value">${timeAgo(new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString())}</div>
                    </div>
                </div>
            </div>
            
            <div class="detail-section">
                <h5><i class="fas fa-exclamation-triangle"></i> Impact Assessment</h5>
                <div class="impact-assessment">
                    <div class="impact-factor">
                        <span class="factor-name">Potential Damage</span>
                        <span class="factor-rating high">High</span>
                    </div>
                    <div class="impact-factor">
                        <span class="factor-name">Spread Potential</span>
                        <span class="factor-rating medium">Medium</span>
                    </div>
                    <div class="impact-factor">
                        <span class="factor-name">Detection Difficulty</span>
                        <span class="factor-rating low">Low</span>
                    </div>
                </div>
            </div>
            
            <div class="detail-section">
                <h5><i class="fas fa-lightbulb"></i> Recommended Actions</h5>
                <ul class="recommendations">
                    <li>Update firewall rules to block source IPs</li>
                    <li>Implement rate limiting on affected endpoints</li>
                    <li>Review and update security configurations</li>
                    <li>Monitor for similar patterns</li>
                </ul>
            </div>
        </div>
    `;
    
    document.getElementById('pattern-detail-modal').classList.remove('hidden');
}

// Close Pattern Detail
function closePatternDetail() {
    document.getElementById('pattern-detail-modal').classList.add('hidden');
}

// Create Incident from Pattern
function createIncidentFromPattern() {
    alert('Incident created from pattern analysis');
    closePatternDetail();
}

// Load Top Sources
function loadTopSources() {
    const sources = [
        { ip: '192.168.1.105', country: 'US', attacks: 245, location: 'New York, USA' },
        { ip: '10.0.0.42', country: 'CN', attacks: 189, location: 'Beijing, China' },
        { ip: '172.16.0.88', country: 'RU', attacks: 156, location: 'Moscow, Russia' },
        { ip: '203.0.113.25', country: 'DE', attacks: 98, location: 'Berlin, Germany' },
        { ip: '198.51.100.13', country: 'IN', attacks: 134, location: 'Mumbai, India' },
        { ip: '203.0.113.17', country: 'BR', attacks: 87, location: 'São Paulo, Brazil' },
        { ip: '192.0.2.8', country: 'JP', attacks: 76, location: 'Tokyo, Japan' },
        { ip: '198.51.100.42', country: 'KR', attacks: 65, location: 'Seoul, South Korea' }
    ];
    
    analyticsData.topSources = sources;
    
    const container = document.getElementById('top-sources');
    if (!container) return;
    
    container.innerHTML = sources.map(source => `
        <div class="source-item">
            <div class="source-info">
                <span class="source-country">${getCountryFlag(source.country)}</span>
                <div class="source-details">
                    <span class="source-ip">${source.ip}</span>
                    <span class="source-count">${source.location}</span>
                </div>
            </div>
            <div class="source-attacks">
                <span class="attack-count">${source.attacks}</span>
                <span class="attack-label">attacks</span>
            </div>
        </div>
    `).join('');
}

// Show Geo Map
function showGeoMap() {
    // Create world map visualization
    const container = document.getElementById('world-map');
    if (!container) return;
    
    container.innerHTML = `
        <div class="world-map-visualization">
            <div class="map-point" style="top: 30%; left: 25%; background: #dc3545;" data-country="USA">
                <div class="map-tooltip">USA: 245 attacks</div>
            </div>
            <div class="map-point" style="top: 35%; left: 75%; background: #dc3545;" data-country="China">
                <div class="map-tooltip">China: 189 attacks</div>
            </div>
            <div class="map-point" style="top: 25%; left: 65%; background: #fd7e14;" data-country="Russia">
                <div class="map-tooltip">Russia: 156 attacks</div>
            </div>
            <div class="map-point" style="top: 40%; left: 48%; background: #ffc107;" data-country="Germany">
                <div class="map-tooltip">Germany: 98 attacks</div>
            </div>
            <div class="map-point" style="top: 45%; left: 70%; background: #fd7e14;" data-country="India">
                <div class="map-tooltip">India: 134 attacks</div>
            </div>
            <div class="map-point" style="top: 55%; left: 30%; background: #28a745;" data-country="Brazil">
                <div class="map-tooltip">Brazil: 87 attacks</div>
            </div>
            <div class="map-point" style="top: 40%; left: 85%; background: #ffc107;" data-country="Japan">
                <div class="map-tooltip">Japan: 76 attacks</div>
            </div>
        </div>
    `;
    
    document.getElementById('geo-map-modal').classList.remove('hidden');
}

// Close Geo Map
function closeGeoMap() {
    document.getElementById('geo-map-modal').classList.add('hidden');
}

// Load Anomalies
function loadAnomalies() {
    const anomalies = [
        {
            id: 1,
            title: 'Unusual Outbound Traffic Spike',
            severity: 'Critical',
            description: '5000% increase in outbound traffic detected at 02:45 AM',
            timestamp: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(),
            confidence: 96
        },
        {
            id: 2,
            title: 'Suspicious Login Pattern',
            severity: 'High',
            description: 'Multiple failed login attempts from geographically dispersed locations',
            timestamp: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(),
            confidence: 87
        },
        {
            id: 3,
            title: 'Anomalous Port Activity',
            severity: 'Medium',
            description: 'Unusual traffic on non-standard port 4444',
            timestamp: new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString(),
            confidence: 78
        }
    ];
    
    analyticsData.anomalies = anomalies;
    
    const container = document.getElementById('anomalies-container');
    if (!container) return;
    
    container.innerHTML = anomalies.map(anomaly => `
        <div class="anomaly-item">
            <div class="anomaly-header">
                <span class="anomaly-title">${anomaly.title}</span>
                <span class="anomaly-severity">${anomaly.severity}</span>
            </div>
            <div class="anomaly-description">${anomaly.description}</div>
            <div class="anomaly-time">
                <i class="fas fa-clock"></i> Detected ${timeAgo(anomaly.timestamp)}
            </div>
        </div>
    `).join('');
    
    document.getElementById('anomalies-count').textContent = `${anomalies.length} anomalies`;
}

// Load Remediations
function loadRemediations() {
    const remediations = [
        {
            id: 1,
            title: 'Implement WAF Rules for XSS',
            priority: 'High',
            steps: 'Add regex-based WAF rules to detect and block XSS payloads',
            impact: 'Reduces XSS attacks by 95%',
            effort: '2 hours',
            effectiveness: 92
        },
        {
            id: 2,
            title: 'Enable MFA for Admin Accounts',
            priority: 'Critical',
            steps: 'Configure multi-factor authentication for all administrative accounts',
            impact: 'Prevents 99% of credential-based attacks',
            effort: '4 hours',
            effectiveness: 98
        },
        {
            id: 3,
            title: 'Update Firewall Rules',
            priority: 'Medium',
            steps: 'Block traffic from high-risk countries and known malicious IPs',
            impact: 'Reduces attack surface by 60%',
            effort: '1 hour',
            effectiveness: 85
        },
        {
            id: 4,
            title: 'Patch SQL Server Vulnerabilities',
            priority: 'High',
            steps: 'Apply latest security patches and updates to database servers',
            impact: 'Closes 3 critical SQL injection vectors',
            effort: '3 hours',
            effectiveness: 96
        }
    ];
    
    analyticsData.remediations = remediations;
    
    const container = document.getElementById('remediation-container');
    if (!container) return;
    
    container.innerHTML = remediations.map(remediation => `
        <div class="remediation-item">
            <div class="remediation-header">
                <span class="remediation-title">${remediation.title}</span>
                <span class="remediation-priority">${remediation.priority}</span>
            </div>
            <div class="remediation-steps">${remediation.steps}</div>
            <div class="remediation-impact">
                <i class="fas fa-chart-line"></i> Impact: ${remediation.impact} | 
                <i class="fas fa-clock"></i> Effort: ${remediation.effort} | 
                <i class="fas fa-bullseye"></i> Effectiveness: ${remediation.effectiveness}%
            </div>
        </div>
    `).join('');
}

// Generate Remediations
function generateRemediations() {
    // Simulate AI generating new remediations
    const newRemediation = {
        id: Date.now(),
        title: 'Implement Behavioral Analytics',
        priority: 'High',
        steps: 'Deploy machine learning model to detect anomalous user behavior',
        impact: 'Identifies 85% of insider threats',
        effort: '8 hours',
        effectiveness: 88
    };
    
    analyticsData.remediations.unshift(newRemediation);
    
    // Reload remediations
    loadRemediations();
    
    showNotification('New remediation suggestions generated', 'success');
}

// Load Predictions
function loadPredictions() {
    const predictions = [
        {
            id: 1,
            title: 'DDoS Attack Probability',
            probability: 85,
            description: 'High probability of DDoS attack within next 24 hours based on traffic patterns',
            timeframe: 'Next 24 hours',
            confidence: 78
        },
        {
            id: 2,
            title: 'Credential Stuffing Attack',
            probability: 72,
            description: 'Likely credential stuffing attack targeting user accounts',
            timeframe: 'Next 12 hours',
            confidence: 82
        },
        {
            id: 3,
            title: 'Ransomware Infection',
            probability: 45,
            description: 'Medium risk of ransomware based on recent phishing campaign',
            timeframe: 'Next 48 hours',
            confidence: 65
        }
    ];
    
    analyticsData.predictions = predictions;
    
    const container = document.getElementById('predictions-container');
    if (!container) return;
    
    container.innerHTML = predictions.map(prediction => `
        <div class="prediction-item">
            <div class="prediction-header">
                <span class="prediction-title">${prediction.title}</span>
                <span class="prediction-probability">${prediction.probability}%</span>
            </div>
            <div class="prediction-description">${prediction.description}</div>
            <div class="prediction-timeframe">
                <i class="fas fa-calendar-alt"></i> Timeframe: ${prediction.timeframe}
            </div>
        </div>
    `).join('');
    
    // Update prediction confidence
    const avgConfidence = Math.round(predictions.reduce((acc, p) => acc + p.confidence, 0) / predictions.length);
    document.getElementById('prediction-confidence').textContent = `${avgConfidence}% accuracy`;
}

// Load AI Insights
function loadAIInsights() {
    const insights = [
        {
            id: 1,
            title: 'Attack Pattern Shift Detected',
            confidence: 92,
            content: 'Analysis shows attackers are shifting from SQL injection to XSS attacks. This suggests improved database security but potential weaknesses in input validation.',
            recommendations: [
                'Review and update input validation mechanisms',
                'Implement Content Security Policy (CSP)',
                'Conduct security training on XSS prevention'
            ],
            timestamp: new Date().toISOString()
        },
        {
            id: 2,
            title: 'Geographic Attack Trends',
            confidence: 85,
            content: '65% of recent attacks originate from 3 countries: USA, China, and Russia. Consider implementing geo-blocking for non-essential services.',
            recommendations: [
                'Implement geographic IP blocking',
                'Monitor traffic from high-risk regions',
                'Review business requirements for international access'
            ],
            timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
        },
        {
            id: 3,
            title: 'Time-Based Attack Patterns',
            confidence: 78,
            content: 'Peak attack hours are between 2 AM - 5 AM UTC. This correlates with low staffing levels in your region.',
            recommendations: [
                'Increase monitoring during peak attack hours',
                'Consider automated response systems',
                'Review shift schedules for security team'
            ],
            timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString()
        }
    ];
    
    analyticsData.aiInsights = insights;
    renderAIInsights(insights);
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function renderAIInsights(insights) {
    const container = document.getElementById('insights-container');
    if (!container) return;
    
    container.innerHTML = insights.map(insight => `
        <div class="insight-item ${insight.mode === 'ai' ? 'ai-live-insight' : ''}">
            <div class="insight-header">
                <span class="insight-title">${escapeHtml(insight.title)}</span>
                <span class="insight-confidence">${escapeHtml(insight.confidence)}% confidence</span>
            </div>
            <div class="insight-content">${escapeHtml(insight.content)}</div>
            <div class="insight-recommendations">
                <strong>Recommendations:</strong>
                <ul>
                    ${(insight.recommendations || []).map(rec => `<li>${escapeHtml(rec)}</li>`).join('')}
                </ul>
            </div>
            ${insight.watchlist?.length ? `
                <div class="insight-recommendations">
                    <strong>Watchlist:</strong>
                    <ul>${insight.watchlist.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
                </div>
            ` : ''}
            <div class="insight-footer">
                <small><i class="fas fa-clock"></i> Generated ${timeAgo(insight.timestamp)}${insight.mode ? ` | ${escapeHtml(insight.mode === 'ai' ? 'AI model' : 'local fallback')}` : ''}</small>
            </div>
        </div>
    `).join('');
}

// Generate AI Insights
async function generateAIInsights() {
    showNotification('Generating AI SOC report...', 'info');

    try {
        const response = await fetch('https://microsoc-backend.onrender.com/api/ai/generate-report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
            },
            body: JSON.stringify({
                analytics: analyticsData,
                riskScore: document.getElementById('risk-score')?.textContent || '68',
                generatedFrom: 'analytics-page'
            })
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'AI report failed');
        }

        const report = payload.data || {};
        const newInsight = {
            id: Date.now(),
            title: report.title || 'AI SOC Executive Summary',
            confidence: report.confidence || 86,
            content: report.summary || 'AI report generated successfully.',
            recommendations: report.recommendedActions || report.keyFindings || [],
            watchlist: report.watchlist || [],
            timestamp: new Date().toISOString(),
            mode: payload.mode
        };

        analyticsData.aiInsights = [newInsight, ...(analyticsData.aiInsights || [])].slice(0, 6);
        renderAIInsights(analyticsData.aiInsights);
        showNotification('AI SOC report generated', 'success');
    } catch (error) {
        console.error('AI insights failed:', error);
        showNotification('AI report failed. Please check backend login/session.', 'error');
    }
}

// Update Analytics
function updateAnalytics() {
    const timePeriod = document.getElementById('time-period').value;
    
    // Simulate updating data based on time period
    showNotification(`Updating analytics for ${timePeriod}...`, 'info');
    
    // In a real app, this would fetch new data from the server
    setTimeout(() => {
        // Update charts with new data
        if (window.threatTimelineChart) {
            // Generate new random data based on time period
            const days = timePeriod === '24h' ? 
                ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'] :
                timePeriod === '7d' ? 
                ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] :
                ['Week 1', 'Week 2', 'Week 3', 'Week 4'];
            
            analyticsData.threatTimeline.labels = days;
            analyticsData.threatTimeline.datasets.forEach(dataset => {
                dataset.data = days.map(() => Math.floor(Math.random() * 50) + 10);
            });
            
            window.threatTimelineChart.update();
        }
        
        // Update patterns count
        const newPatternCount = Math.floor(Math.random() * 5) + 3;
        document.getElementById('patterns-detected').textContent = `${newPatternCount} patterns`;
        
        // Update anomalies count
        const newAnomaliesCount = Math.floor(Math.random() * 4) + 1;
        document.getElementById('anomalies-count').textContent = `${newAnomaliesCount} anomalies`;
        
        // Update risk score
        const newRiskScore = Math.floor(Math.random() * 30) + 50;
        document.getElementById('risk-score').textContent = newRiskScore;
        
        showNotification(`Analytics updated for ${timePeriod}`, 'success');
    }, 1000);
}

// Run Pattern Analysis
function runPatternAnalysis() {
    showNotification('Running advanced pattern analysis...', 'info');
    
    // Simulate analysis running
    setTimeout(() => {
        // Add new patterns
        const newPattern = {
            id: Date.now(),
            name: 'AI-Detected Behavioral Pattern',
            confidence: 91,
            description: 'Machine learning algorithm detected new behavioral pattern in attack sequences',
            type: 'Behavioral',
            frequency: 'Pattern detected across 24 instances',
            timeframe: 'Last 72 hours',
            severity: 'High'
        };
        
        analyticsData.patterns.unshift(newPattern);
        loadPatterns();
        
        // Add new anomaly
        const newAnomaly = {
            id: Date.now(),
            title: 'AI-Detected Anomalous Behavior',
            severity: 'High',
            description: 'Machine learning detected anomalous behavior in network traffic patterns',
            timestamp: new Date().toISOString(),
            confidence: 89
        };
        
        analyticsData.anomalies.unshift(newAnomaly);
        loadAnomalies();
        
        showNotification('Pattern analysis complete. New patterns and anomalies detected.', 'success');
    }, 2000);
}

// Export Analytics
function exportAnalytics() {
    const exportData = {
        timestamp: new Date().toISOString(),
        analytics: analyticsData,
        summary: {
            patternsDetected: analyticsData.patterns.length,
            anomaliesFound: analyticsData.anomalies.length,
            topSource: analyticsData.topSources[0]?.ip || 'N/A',
            riskScore: document.getElementById('risk-score')?.textContent || 'N/A'
        }
    };
    
    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `analytics-report-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    showNotification('Analytics report exported successfully', 'success');
}

// Update Analytics Stats
function updateAnalyticsStats() {
    // In a real app, these would be calculated from actual data
    const stats = {
        detectionRate: (98.5 + Math.random() * 0.5).toFixed(1),
        preventionSuccess: (93.5 + Math.random() * 1.5).toFixed(1),
        responseTime: (1.7 + Math.random() * 0.3).toFixed(1),
        aiConfidence: (88.5 + Math.random() * 2).toFixed(1)
    };
    
    // Update stat cards
    document.querySelectorAll('.stat-value')[0].textContent = `${stats.detectionRate}%`;
    document.querySelectorAll('.stat-value')[1].textContent = `${stats.preventionSuccess}%`;
    document.querySelectorAll('.stat-value')[2].textContent = `${stats.responseTime}h`;
    document.querySelectorAll('.stat-value')[3].textContent = `${stats.aiConfidence}%`;
}

// Export functions for global use
window.initAnalytics = initAnalytics;
window.toggleTimelineView = toggleTimelineView;
window.showPatternDetail = showPatternDetail;
window.closePatternDetail = closePatternDetail;
window.createIncidentFromPattern = createIncidentFromPattern;
window.showGeoMap = showGeoMap;
window.closeGeoMap = closeGeoMap;
window.generateRemediations = generateRemediations;
window.generateAIInsights = generateAIInsights;
window.updateAnalytics = updateAnalytics;
window.runPatternAnalysis = runPatternAnalysis;
window.exportAnalytics = exportAnalytics;
