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

const LOG_STORAGE_KEY = 'microsocSecurityLogs';

function getCurrentUserRole() {
    try {
        return JSON.parse(localStorage.getItem('user') || '{}').role || 'analyst';
    } catch (error) {
        return 'analyst';
    }
}

function isAdminUser() {
    return getCurrentUserRole() === 'admin';
}

function getApiBaseUrl() {
    return window.MICROSOC_API_BASE_URL || 'https://microsoc-backend.onrender.com/api';
}

function getStoredSecurityLogs() {
    try {
        const logs = JSON.parse(localStorage.getItem(LOG_STORAGE_KEY) || '[]');
        return Array.isArray(logs)
            ? logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            : [];
    } catch (error) {
        return [];
    }
}

function getAnalyticsTimeWindow() {
    const value = document.getElementById('time-period')?.value || '7d';
    const now = Date.now();
    const windows = {
        '24h': 24 * 60 * 60 * 1000,
        '7d': 7 * 24 * 60 * 60 * 1000,
        '30d': 30 * 24 * 60 * 60 * 1000
    };
    return { value, since: now - (windows[value] || windows['7d']) };
}

function getAnalyticsLogs() {
    const { since } = getAnalyticsTimeWindow();
    return getStoredSecurityLogs().filter(log => new Date(log.timestamp).getTime() >= since);
}

function countBy(items, keyGetter) {
    return items.reduce((acc, item) => {
        const key = keyGetter(item) || 'Unknown';
        acc[key] = (acc[key] || 0) + 1;
        return acc;
    }, {});
}

function severityWeight(severity) {
    return { critical: 95, high: 75, medium: 50, low: 25 }[String(severity).toLowerCase()] || 35;
}

function formatEmptyState(message) {
    return `<div style="padding: 18px; color: var(--text-secondary);">${escapeHtml(message)}</div>`;
}

// Initialize Analytics
function initAnalytics() {
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
    syncAnalyticsRoleUi();

    window.addEventListener('microsoc:logs-updated', updateAnalytics);

}

function syncAnalyticsRoleUi() {
    const adminOnlyButtons = [
        'button[onclick*="updateAnalytics"]',
        'button[onclick*="exportAnalytics"]',
        'button[onclick*="runPatternAnalysis"]'
    ];

    if (isAdminUser()) return;

    adminOnlyButtons.forEach(selector => {
        document.querySelectorAll(selector).forEach(button => {
            button.style.display = 'none';
        });
    });
}

// Load Analytics Data
function loadAnalyticsData() {
    const logs = getAnalyticsLogs();
    const typeCounts = countBy(logs, log => log.attackType);
    const labels = Object.keys(typeCounts);
    const colors = ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#17a2b8', '#6f42c1', '#e83e8c', '#0d6efd'];

    analyticsData.attackDistribution = {
        labels: labels.length ? labels : ['No attacks'],
        datasets: [{
            data: labels.length ? labels.map(label => typeCounts[label]) : [0],
            backgroundColor: labels.length ? labels.map((_, index) => colors[index % colors.length]) : ['#6c757d']
        }]
    };
    
    const { value } = getAnalyticsTimeWindow();
    const labelsForPeriod = value === '24h'
        ? Array.from({ length: 6 }, (_, index) => `${String(index * 4).padStart(2, '0')}:00`)
        : value === '30d'
            ? ['Week 1', 'Week 2', 'Week 3', 'Week 4']
            : ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const severities = ['critical', 'high', 'medium'];

    analyticsData.threatTimeline = {
        labels: labelsForPeriod,
        datasets: severities.map(severity => ({
            label: severity.charAt(0).toUpperCase() + severity.slice(1),
            data: buildTimelineSeries(logs, labelsForPeriod, value, severity),
            borderColor: getSeverityColor(severity),
            backgroundColor: `${getSeverityColor(severity)}22`,
            tension: 0.4
        }))
    };
}

function buildTimelineSeries(logs, labels, period, severity) {
    const counts = labels.map(() => 0);
    logs
        .filter(log => log.severity === severity)
        .forEach(log => {
            const date = new Date(log.timestamp);
            let index = 0;
            if (period === '24h') {
                index = Math.min(labels.length - 1, Math.floor(date.getHours() / 4));
            } else if (period === '30d') {
                index = Math.min(labels.length - 1, Math.floor((Date.now() - date.getTime()) / (7 * 24 * 60 * 60 * 1000)));
                index = labels.length - 1 - index;
            } else {
                index = date.getDay();
            }
            counts[index] += 1;
        });
    return counts;
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
        const percentage = total ? Math.round((data[index] / total) * 100) : 0;
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
    const logs = getAnalyticsLogs();
    const byType = countBy(logs, log => log.attackType);
    const byCountry = countBy(logs, log => log.country);
    const patterns = Object.entries(byType)
        .filter(([, count]) => count >= 2)
        .map(([type, count], index) => {
            const related = logs.filter(log => log.attackType === type);
            const highest = ['critical', 'high', 'medium', 'low'].find(level => related.some(log => log.severity === level)) || 'medium';
            return {
                id: index + 1,
                name: `${type} cluster`,
                confidence: Math.min(98, 60 + count * 8),
                description: `${count} ${type} event${count === 1 ? '' : 's'} detected in the selected time window`,
                type,
                frequency: `${count} events`,
                timeframe: document.getElementById('time-period')?.selectedOptions?.[0]?.textContent || 'Selected window',
                severity: highest.charAt(0).toUpperCase() + highest.slice(1)
            };
        });

    const countryCluster = Object.entries(byCountry).sort((a, b) => b[1] - a[1])[0];
    if (countryCluster && countryCluster[1] >= 3) {
        patterns.push({
            id: patterns.length + 1,
            name: `${countryCluster[0]} source concentration`,
            confidence: Math.min(95, 55 + countryCluster[1] * 5),
            description: `${countryCluster[1]} events came from ${countryCluster[0]} in the selected time window`,
            type: 'Geographic',
            frequency: `${countryCluster[1]} events`,
            timeframe: document.getElementById('time-period')?.selectedOptions?.[0]?.textContent || 'Selected window',
            severity: 'Medium'
        });
    }
    
    analyticsData.patterns = patterns;
    
    const container = document.getElementById('patterns-list');
    if (!container) return;
    
    container.innerHTML = patterns.length ? patterns.map(pattern => `
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
    `).join('') : formatEmptyState('No repeat attack patterns yet. Start live stream or widen the time period.');
    
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
                </div>
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
    const logs = getAnalyticsLogs();
    const grouped = logs.reduce((acc, log) => {
        acc[log.sourceIP] = acc[log.sourceIP] || { ip: log.sourceIP, country: log.country, attacks: 0, lastSeen: log.timestamp };
        acc[log.sourceIP].attacks += 1;
        if (new Date(log.timestamp) > new Date(acc[log.sourceIP].lastSeen)) {
            acc[log.sourceIP].lastSeen = log.timestamp;
        }
        return acc;
    }, {});
    const sources = Object.values(grouped).sort((a, b) => b.attacks - a.attacks).slice(0, 8);
    
    analyticsData.topSources = sources;
    
    const container = document.getElementById('top-sources');
    if (!container) return;
    
    container.innerHTML = sources.length ? sources.map(source => `
        <div class="source-item">
            <div class="source-info">
                <span class="source-country">${getCountryFlag(source.country)}</span>
                <div class="source-details">
                    <span class="source-ip">${source.ip}</span>
                    <span class="source-count">Last seen ${timeAgo(source.lastSeen)}</span>
                </div>
            </div>
            <div class="source-attacks">
                <span class="attack-count">${source.attacks}</span>
                <span class="attack-label">attacks</span>
            </div>
        </div>
    `).join('') : formatEmptyState('No source data yet.');
}

// Show Geo Map
function showGeoMap() {
    // Create world map visualization
    const container = document.getElementById('world-map');
    if (!container) return;
    
    const countries = countBy(getAnalyticsLogs(), log => log.country);
    const positions = {
        USA: [30, 25], China: [35, 75], Russia: [25, 65], Germany: [40, 48],
        India: [45, 70], Brazil: [55, 30], Japan: [40, 85], UK: [36, 46], France: [42, 47]
    };
    container.innerHTML = `
        <div class="world-map-visualization">
            ${Object.entries(countries).map(([country, count]) => {
                const [top, left] = positions[country] || [50, 50];
                return `<div class="map-point" style="top: ${top}%; left: ${left}%; background: ${count > 5 ? '#dc3545' : count > 2 ? '#fd7e14' : '#28a745'};" data-country="${escapeHtml(country)}">
                    <div class="map-tooltip">${escapeHtml(country)}: ${count} attacks</div>
                </div>`;
            }).join('') || formatEmptyState('No geo data yet.')}
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
    const logs = getAnalyticsLogs();
    const activeHigh = logs.filter(log => !log.isBlocked && ['critical', 'high'].includes(log.severity));
    const repeatedSources = Object.values(logs.reduce((acc, log) => {
        acc[log.sourceIP] = acc[log.sourceIP] || [];
        acc[log.sourceIP].push(log);
        return acc;
    }, {})).filter(group => group.length >= 3);
    const unusualPorts = logs.filter(log => Number(log.port) > 49151);
    const anomalies = [];

    if (activeHigh.length) {
        anomalies.push({
            id: 1,
            title: 'Unblocked high-risk events',
            severity: activeHigh.some(log => log.severity === 'critical') ? 'Critical' : 'High',
            description: `${activeHigh.length} critical/high event${activeHigh.length === 1 ? '' : 's'} remain active in the selected window`,
            timestamp: activeHigh[0].timestamp,
            confidence: Math.min(98, 70 + activeHigh.length * 5)
        });
    }

    repeatedSources.slice(0, 2).forEach((group, index) => {
        anomalies.push({
            id: anomalies.length + index + 1,
            title: `Repeated source ${group[0].sourceIP}`,
            severity: group.some(log => log.severity === 'critical') ? 'Critical' : 'High',
            description: `${group.length} events from the same source targeting ${[...new Set(group.map(log => log.targetSystem))].join(', ')}`,
            timestamp: group[0].timestamp,
            confidence: Math.min(96, 65 + group.length * 6)
        });
    });

    if (unusualPorts.length) {
        anomalies.push({
            id: anomalies.length + 1,
            title: 'High ephemeral port activity',
            severity: 'Medium',
            description: `${unusualPorts.length} events touched high-numbered ports in the selected window`,
            timestamp: unusualPorts[0].timestamp,
            confidence: Math.min(90, 55 + unusualPorts.length * 4)
        });
    }
    
    analyticsData.anomalies = anomalies;
    
    const container = document.getElementById('anomalies-container');
    if (!container) return;
    
    container.innerHTML = anomalies.length ? anomalies.map(anomaly => `
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
    `).join('') : formatEmptyState('No anomalies detected from current logs.');
    
    document.getElementById('anomalies-count').textContent = `${anomalies.length} anomalies`;
}

// Load Remediations
function loadRemediations() {
    const logs = getAnalyticsLogs();
    const topTypes = Object.entries(countBy(logs, log => log.attackType)).sort((a, b) => b[1] - a[1]).slice(0, 4);
    const remediations = topTypes.map(([type, count], index) => {
        const related = logs.filter(log => log.attackType === type);
        const active = related.filter(log => !log.isBlocked).length;
        const priority = related.some(log => log.severity === 'critical') ? 'Critical' : related.some(log => log.severity === 'high') ? 'High' : 'Medium';
        return {
            id: index + 1,
            title: `Review controls for ${type}`,
            priority,
            steps: `${count} ${type} event${count === 1 ? '' : 's'} detected; ${active} active/unblocked. Use the log action AI button for event-specific prevention.`,
            impact: `${Math.round((active / Math.max(count, 1)) * 100)}% currently unblocked`,
            effort: 'Based on selected log window',
            effectiveness: Math.max(0, Math.round((1 - active / Math.max(count, 1)) * 100))
        };
    });
    
    analyticsData.remediations = remediations;
    
    const container = document.getElementById('remediation-container');
    if (!container) return;
    
    container.innerHTML = remediations.length ? remediations.map(remediation => `
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
    `).join('') : formatEmptyState('No remediation candidates until attacks are detected.');
}

// Generate Remediations
function generateRemediations() {
    loadRemediations();
    showNotification('Remediation suggestions recalculated from stored logs', 'success');
}

// Load Predictions
function loadPredictions() {
    const logs = getAnalyticsLogs();
    const typeCounts = Object.entries(countBy(logs, log => log.attackType)).sort((a, b) => b[1] - a[1]).slice(0, 3);
    const predictions = typeCounts.map(([type, count], index) => {
        const recent = logs.filter(log => log.attackType === type && Date.now() - new Date(log.timestamp).getTime() < 60 * 60 * 1000).length;
        const probability = Math.min(92, 25 + count * 8 + recent * 12);
        return {
            id: index + 1,
            title: `${type} continuation risk`,
            probability,
            description: `${count} ${type} event${count === 1 ? '' : 's'} in the selected window, with ${recent} in the last hour`,
            timeframe: recent ? 'Next 1-4 hours' : 'Selected window trend',
            confidence: Math.min(90, 50 + count * 7)
        };
    });
    
    analyticsData.predictions = predictions;
    
    const container = document.getElementById('predictions-container');
    if (!container) return;
    
    container.innerHTML = predictions.length ? predictions.map(prediction => `
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
    `).join('') : formatEmptyState('No predictions until log volume exists.');
    
    // Update prediction confidence
    const avgConfidence = predictions.length
        ? Math.round(predictions.reduce((acc, p) => acc + p.confidence, 0) / predictions.length)
        : 0;
    document.getElementById('prediction-confidence').textContent = `${avgConfidence}% confidence`;
}

// Load AI Insights
function loadAIInsights() {
    analyticsData.aiInsights = [];
    renderAIInsights([]);
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

    if (!insights.length) {
        container.innerHTML = formatEmptyState('Click Generate Insights to ask AI to analyze the currently stored logs.');
        return;
    }
    
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

function renderAIInsightsLoading() {
    const container = document.getElementById('insights-container');
    if (!container) return;

    container.innerHTML = `
        <div class="ai-loading-state analytics-ai-loading">
            <div class="ai-loading-orb"><i class="fas fa-chart-line"></i></div>
            <h4>AI is generating SOC report...</h4>
            <p>MicroSOC AI is reviewing alerts, logs, attacker distribution, and risk signals.</p>
            <div class="ai-loading-steps">
                <span>Reading analytics</span>
                <span>Correlating logs</span>
                <span>Writing SOC insights</span>
            </div>
        </div>
    `;
}

function renderAIInsightsError(message) {
    const container = document.getElementById('insights-container');
    if (!container) return;

    container.innerHTML = `
        <div class="ai-loading-state ai-error-state analytics-ai-loading">
            <div class="ai-loading-orb"><i class="fas fa-triangle-exclamation"></i></div>
            <h4>AI SOC report failed</h4>
            <p>${escapeHtml(message || 'Please check backend login/session and try again.')}</p>
        </div>
    `;
}

// Generate AI Insights
async function generateAIInsights() {
    renderAIInsightsLoading();
    showNotification('Generating AI SOC report...', 'info');

    try {
        const response = await fetch(`${getApiBaseUrl()}/ai/generate-report`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
            },
            body: JSON.stringify({
                analytics: analyticsData,
                logs: getAnalyticsLogs(),
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
        renderAIInsightsError(error.message || 'AI report failed. Please check backend login/session.');
        showNotification('AI report failed. Please check backend login/session.', 'error');
    }
}

// Update Analytics
function updateAnalytics() {
    if (!isAdminUser()) {
        showNotification('Analytics is view-only for analysts.', 'warning');
        return;
    }
    loadAnalyticsData();
    if (attackDistributionChart instanceof Chart) {
        attackDistributionChart.data = analyticsData.attackDistribution;
        attackDistributionChart.update();
        createAttackDistributionLegend();
    }
    if (window.threatTimelineChart instanceof Chart) {
        window.threatTimelineChart.data = analyticsData.threatTimeline;
        window.threatTimelineChart.update();
    }
    loadPatterns();
    loadTopSources();
    loadAnomalies();
    loadRemediations();
    loadPredictions();
    updateAnalyticsStats();
    showNotification('Analytics recalculated from stored logs', 'success');
}

// Run Pattern Analysis
function runPatternAnalysis() {
    if (!isAdminUser()) {
        showNotification('Pattern analysis is available for admins only.', 'warning');
        return;
    }
    loadPatterns();
    loadAnomalies();
    showNotification('Pattern analysis recalculated from stored logs', 'success');
}

// Export Analytics
function exportAnalytics() {
    if (!isAdminUser()) {
        showNotification('Only admins can export analytics.', 'warning');
        return;
    }
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
    const logs = getAnalyticsLogs();
    const total = logs.length;
    const blocked = logs.filter(log => log.isBlocked).length;
    const criticalHigh = logs.filter(log => ['critical', 'high'].includes(log.severity)).length;
    const avgSeverity = total
        ? Math.round(logs.reduce((sum, log) => sum + severityWeight(log.severity), 0) / total)
        : 0;
    const stats = {
        detectionRate: total ? '100.0' : '0.0',
        preventionSuccess: total ? ((blocked / total) * 100).toFixed(1) : '0.0',
        responseTime: total ? `${criticalHigh}` : '0',
        aiConfidence: total ? String(Math.min(95, 45 + avgSeverity / 2).toFixed(1)) : '0.0'
    };
    
    // Update stat cards
    document.querySelectorAll('.stat-value')[0].textContent = `${stats.detectionRate}%`;
    document.querySelectorAll('.stat-value')[1].textContent = `${stats.preventionSuccess}%`;
    document.querySelectorAll('.stat-value')[2].textContent = stats.responseTime;
    document.querySelectorAll('.stat-value')[3].textContent = `${stats.aiConfidence}%`;

    const riskScore = document.getElementById('risk-score');
    if (riskScore) {
        const activeRisk = logs.filter(log => !log.isBlocked).reduce((sum, log) => sum + severityWeight(log.severity), 0);
        riskScore.textContent = total ? Math.min(100, Math.round((activeRisk / Math.max(total, 1)) + criticalHigh * 4)) : 0;
    }
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
