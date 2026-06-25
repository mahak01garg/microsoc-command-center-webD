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
    clusters: [],
    aiInsights: []
};

const LOG_STORAGE_KEY = 'microsocSecurityLogs';
let analyticsLogCache = [];
let analyticsLogsReady = false;

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

function getAnalyticsAuthHeaders() {
    return {
        'Authorization': `Bearer ${localStorage.getItem('token') || ''}`,
        'Cache-Control': 'no-cache'
    };
}

function ensureAnalyticsAllTimeOption() {
    const select = document.getElementById('time-period');
    if (!select) return;

    const hadAllTime = Boolean(select.querySelector('option[value="all"]'));
    if (!select.querySelector('option[value="all"]')) {
        const option = document.createElement('option');
        option.value = 'all';
        option.textContent = 'All Time';
        select.insertBefore(option, select.firstChild);
    }

    if (!hadAllTime || !sessionStorage.getItem('microsocAnalyticsTimeTouched')) {
        select.value = 'all';
    }

    if (!select.dataset.analyticsTimeSynced) {
        select.addEventListener('change', () => {
            sessionStorage.setItem('microsocAnalyticsTimeTouched', 'true');
        });
        select.dataset.analyticsTimeSynced = 'true';
    }
}

function normalizeAnalyticsLog(log) {
    return {
        ...log,
        id: log.id || log._id,
        timestamp: log.timestamp || log.createdAt || new Date().toISOString(),
        attackType: log.attackType || 'Other',
        sourceIP: log.sourceIP || 'Unknown',
        targetSystem: log.targetSystem || 'Unknown',
        severity: String(log.severity || 'medium').toLowerCase(),
        country: log.country || 'Unknown',
        isBlocked: Boolean(log.isBlocked)
    };
}

function getAnalyticsLogId(log) {
    return String(log?._id || log?.id || `${log?.timestamp || ''}-${log?.sourceIP || ''}-${log?.attackType || ''}`);
}

function mergeAnalyticsLogs(...logGroups) {
    const merged = new Map();
    logGroups.flat().filter(Boolean).forEach((log) => {
        const normalized = normalizeAnalyticsLog(log);
        const id = getAnalyticsLogId(normalized);
        merged.set(id, { ...(merged.get(id) || {}), ...normalized });
    });
    return Array.from(merged.values()).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

function syncAnalyticsLogsFromStorage() {
    analyticsLogCache = mergeAnalyticsLogs(analyticsLogCache, getStoredSecurityLogs());
    analyticsLogsReady = true;
}

async function fetchAnalyticsLogsFromBackend() {
    const firstUrl = `${getApiBaseUrl()}/logs?limit=5000&page=1&timeRange=all&sortBy=timestamp&sortOrder=desc&_=${Date.now()}`;
    const firstResponse = await fetch(firstUrl, {
        headers: getAnalyticsAuthHeaders(),
        cache: 'no-store'
    });
    const firstPayload = await firstResponse.json();
    if (!firstResponse.ok || !firstPayload.success) {
        throw new Error(firstPayload.message || 'Could not load analytics logs');
    }

    const logs = Array.isArray(firstPayload.logs) ? [...firstPayload.logs] : [];
    const totalPages = Math.max(1, Number(firstPayload.totalPages) || 1);

    if (totalPages > 1) {
        const remainingPages = Array.from({ length: totalPages - 1 }, (_, index) => index + 2);
        const pages = await Promise.all(remainingPages.map(async (page) => {
            const response = await fetch(`${getApiBaseUrl()}/logs?limit=5000&page=${page}&timeRange=all&sortBy=timestamp&sortOrder=desc&_=${Date.now()}`, {
                headers: getAnalyticsAuthHeaders(),
                cache: 'no-store'
            });
            const payload = await response.json();
            return response.ok && payload.success && Array.isArray(payload.logs) ? payload.logs : [];
        }));
        pages.forEach(pageLogs => logs.push(...pageLogs));
    }

    return logs.map(normalizeAnalyticsLog);
}

async function hydrateAnalyticsLogs() {
    const storedLogs = getStoredSecurityLogs().map(normalizeAnalyticsLog);
    try {
        const backendLogs = await fetchAnalyticsLogsFromBackend();
        analyticsLogCache = mergeAnalyticsLogs(backendLogs, storedLogs);
        analyticsLogsReady = true;
        localStorage.setItem(LOG_STORAGE_KEY, JSON.stringify(analyticsLogCache));
    } catch (error) {
        console.warn('Analytics backend log sync failed, using local cache:', error);
        analyticsLogCache = mergeAnalyticsLogs(analyticsLogCache, storedLogs);
        analyticsLogsReady = true;
    }
}

function getAnalyticsTimeWindow() {
    const value = document.getElementById('time-period')?.value || 'all';
    const now = Date.now();
    const windows = {
        '24h': 24 * 60 * 60 * 1000,
        '7d': 7 * 24 * 60 * 60 * 1000,
        '30d': 30 * 24 * 60 * 60 * 1000,
        '90d': 90 * 24 * 60 * 60 * 1000
    };
    return { value, since: value === 'all' ? null : now - (windows[value] || windows['7d']) };
}

function getAnalyticsLogs() {
    const { since } = getAnalyticsTimeWindow();
    const logs = analyticsLogsReady ? analyticsLogCache : getStoredSecurityLogs().map(normalizeAnalyticsLog);
    if (!since) return logs;
    return logs.filter(log => new Date(log.timestamp).getTime() >= since);
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

function renderAnalyticsWidgets(options = {}) {
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
    loadClusterDetection();
    loadAnomalies();
    loadPredictions();
    updateAnalyticsStats();

    if (options.notify) {
        showNotification('Analytics synced with backend security logs', 'success');
    }
}

// Initialize Analytics
function initAnalytics() {
    ensureAnalyticsAllTimeOption();
    removeThreatFeedWidget();
    removeRetiredAnalyticsWidgets();
    ensureClusterDetectionWidget();
    loadAnalyticsData();
    
    // Initialize charts
    initCharts();
    
    // Load anomalies
    loadClusterDetection();
    loadAnomalies();

    // Load predictions
    loadPredictions();
    
    // Load AI insights
    loadAIInsights();
    
    // Update stats
    updateAnalyticsStats();
    syncAnalyticsRoleUi();

    syncAnalyticsLogsFromStorage();
    renderAnalyticsWidgets();
    hydrateAnalyticsLogs().then(() => renderAnalyticsWidgets());

    window.addEventListener('microsoc:logs-updated', () => {
        syncAnalyticsLogsFromStorage();
        renderAnalyticsWidgets();
        hydrateAnalyticsLogs().then(() => renderAnalyticsWidgets());
    });

    window.addEventListener('storage', event => {
        if (event.key !== LOG_STORAGE_KEY) return;
        syncAnalyticsLogsFromStorage();
        renderAnalyticsWidgets();
    });
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
            : value === 'all'
                ? buildAllTimeTimelineLabels(logs)
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

function formatTimelineDateLabel(date) {
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function buildAllTimeTimelineLabels(logs) {
    const labels = [...new Set((Array.isArray(logs) ? logs : [])
        .map(log => new Date(log.timestamp))
        .filter(date => !Number.isNaN(date.getTime()))
        .sort((a, b) => a - b)
        .map(formatTimelineDateLabel))];
    return labels.length ? labels.slice(-10) : ['No logs'];
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
            } else if (period === 'all') {
                index = labels.indexOf(formatTimelineDateLabel(date));
            } else {
                index = date.getDay();
            }
            if (index >= 0) {
                counts[index] += 1;
            }
        });
    return counts;
}

function normalizeAnalyticsCountryKey(country) {
    const raw = String(country || 'Unknown').trim();
    const upper = raw.toUpperCase();
    const aliases = {
        USA: 'US',
        'UNITED STATES': 'US',
        'UNITED STATES OF AMERICA': 'US',
        CHINA: 'CN',
        RUSSIA: 'RU',
        GERMANY: 'DE',
        INDIA: 'IN',
        BRAZIL: 'BR',
        JAPAN: 'JP',
        'UNITED KINGDOM': 'UK',
        UK: 'UK',
        FRANCE: 'FR',
        KOREA: 'KR',
        'SOUTH KOREA': 'KR'
    };
    return aliases[upper] || upper;
}

function getAnalyticsCountryName(country) {
    const key = normalizeAnalyticsCountryKey(country);
    const names = {
        US: 'United States',
        CN: 'China',
        RU: 'Russia',
        DE: 'Germany',
        IN: 'India',
        BR: 'Brazil',
        JP: 'Japan',
        UK: 'United Kingdom',
        FR: 'France',
        KR: 'South Korea'
    };
    return names[key] || String(country || 'Unknown');
}

function getAnalyticsCountryFlag(country) {
    const key = normalizeAnalyticsCountryKey(country);
    return typeof getCountryFlag === 'function' ? getCountryFlag(key) : '🌍';
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

function removeThreatFeedWidget() {
    document.getElementById('threatFeed')?.closest('.threat-feed')?.remove();
    document.getElementById('analytics-threat-feed-styles')?.remove();
}

function removeRetiredAnalyticsWidgets() {
    [
        'patterns-list',
        'top-sources',
        'remediation-container'
    ].forEach((id) => {
        document.getElementById(id)?.closest('.card')?.remove();
    });

    document.getElementById('geo-map-modal')?.remove();
    document.getElementById('pattern-detail-modal')?.remove();
}

function ensureClusterDetectionWidget() {
    if (document.getElementById('cluster-detection-container')) return;

    const timelineCard = document.getElementById('threatTimelineChart')?.closest('.card');
    if (!timelineCard) return;
    ensureClusterDetectionStyles();

    const card = document.createElement('div');
    card.className = 'card cluster-detection-card';
    card.innerHTML = `
        <div class="card-header">
            <h3><i class="fas fa-object-group"></i> Cluster Detection</h3>
            <span class="badge badge-info" id="clusters-detected">0 clusters</span>
        </div>
        <div class="card-body">
            <div class="cluster-detection-container" id="cluster-detection-container"></div>
        </div>
    `;
    timelineCard.after(card);
}

function ensureClusterDetectionStyles() {
    if (document.getElementById('analytics-cluster-detection-styles')) return;
    const style = document.createElement('style');
    style.id = 'analytics-cluster-detection-styles';
    style.textContent = `
        .cluster-detection-container {
            display: flex;
            flex-direction: column;
            gap: 12px;
            max-height: 330px;
            overflow-y: auto;
        }

        .cluster-item {
            border: 1px solid var(--border-color);
            border-radius: 12px;
            background: var(--bg-secondary);
            padding: 14px;
            color: var(--text-primary);
        }

        .cluster-head {
            display: flex;
            justify-content: space-between;
            gap: 14px;
            align-items: flex-start;
            margin-bottom: 10px;
        }

        .cluster-head strong {
            color: var(--text-primary);
            font-size: 15px;
        }

        .cluster-head p {
            margin: 5px 0 0;
            color: var(--text-secondary);
            font-size: 13px;
        }

        .cluster-severity {
            border-radius: 999px;
            padding: 4px 10px;
            background: rgba(34, 211, 238, 0.14);
            color: #0891b2;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 0.08em;
            white-space: nowrap;
        }

        .cluster-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 10px 14px;
            color: var(--text-secondary);
            font-size: 12px;
        }
    `;
    document.head.appendChild(style);
}

function buildAttackClusters(logs, windowMinutes = 10, minEvents = 3) {
    const windowMs = windowMinutes * 60 * 1000;
    const normalizedLogs = (Array.isArray(logs) ? logs : [])
        .map(normalizeAnalyticsLog)
        .filter(log => log.attackType && !Number.isNaN(new Date(log.timestamp).getTime()));

    const createGroupedClusters = (keyGetter, type) => {
        const grouped = new Map();
        normalizedLogs.forEach((log) => {
            const key = keyGetter(log);
            if (!key) return;
            const current = grouped.get(key) || [];
            current.push(log);
            grouped.set(key, current);
        });

        const clusters = [];
        grouped.forEach((items) => {
            const sorted = items.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            let index = 0;

            while (index < sorted.length) {
                const startTime = new Date(sorted[index].timestamp).getTime();
                let endIndex = index;
                while (
                    endIndex + 1 < sorted.length &&
                    new Date(sorted[endIndex + 1].timestamp).getTime() - startTime <= windowMs
                ) {
                    endIndex += 1;
                }

                const windowItems = sorted.slice(index, endIndex + 1);
                if (windowItems.length >= minEvents) {
                    const latest = windowItems[windowItems.length - 1];
                    const highestSeverity = ['critical', 'high', 'medium', 'low'].find(level =>
                        windowItems.some(log => log.severity === level)
                    ) || 'medium';
                    const sourceIPs = [...new Set(windowItems.map(log => log.sourceIP).filter(Boolean))];
                    clusters.push({
                        id: `${type}-${latest.attackType}-${sourceIPs[0] || 'multi'}-${windowItems[0].timestamp}-${latest.timestamp}`,
                        type,
                        attackType: latest.attackType,
                        sourceIP: type === 'source' ? sourceIPs[0] : `${sourceIPs.length} sources`,
                        sourceIPs,
                        targetSystems: [...new Set(windowItems.map(log => log.targetSystem).filter(Boolean))],
                        country: latest.country || 'Unknown',
                        events: windowItems.length,
                        windowMinutes,
                        firstSeen: windowItems[0].timestamp,
                        lastSeen: latest.timestamp,
                        severity: highestSeverity
                    });
                    index = endIndex + 1;
                } else {
                    index += 1;
                }
            }
        });
        return clusters;
    };

    const sourceClusters = createGroupedClusters(
        log => log.sourceIP ? `${String(log.attackType).toLowerCase()}|${log.sourceIP}` : null,
        'source'
    );
    const attackWaveClusters = createGroupedClusters(
        log => String(log.attackType).toLowerCase(),
        'attack-wave'
    );

    const unique = new Map();
    [...sourceClusters, ...attackWaveClusters]
        .sort((a, b) => {
            if (a.type !== b.type) return a.type === 'source' ? -1 : 1;
            return b.events - a.events || new Date(b.lastSeen) - new Date(a.lastSeen);
        })
        .forEach(cluster => {
            const key = `${cluster.type}|${cluster.attackType}|${cluster.sourceIP}|${cluster.firstSeen}|${cluster.lastSeen}`;
            if (!unique.has(key)) unique.set(key, cluster);
        });

    const windowClusters = Array.from(unique.values()).slice(0, 6);
    if (windowClusters.length) return windowClusters;

    const historicalGroups = new Map();
    normalizedLogs.forEach((log) => {
        const key = String(log.attackType || 'Other').toLowerCase();
        const current = historicalGroups.get(key) || [];
        current.push(log);
        historicalGroups.set(key, current);
    });

    return Array.from(historicalGroups.values())
        .filter(items => items.length >= minEvents)
        .map((items) => {
            const sorted = items.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            const latest = sorted[sorted.length - 1];
            const sourceIPs = [...new Set(sorted.map(log => log.sourceIP).filter(Boolean))];
            const highestSeverity = ['critical', 'high', 'medium', 'low'].find(level =>
                sorted.some(log => log.severity === level)
            ) || 'medium';

            return {
                id: `historical-${latest.attackType}-${latest.timestamp}`,
                type: 'historical-attack-wave',
                attackType: latest.attackType,
                sourceIP: `${sourceIPs.length} sources`,
                sourceIPs,
                targetSystems: [...new Set(sorted.map(log => log.targetSystem).filter(Boolean))],
                country: latest.country || 'Unknown',
                events: sorted.length,
                windowMinutes: null,
                windowLabel: 'selected log window',
                firstSeen: sorted[0].timestamp,
                lastSeen: latest.timestamp,
                severity: highestSeverity
            };
        })
        .sort((a, b) => b.events - a.events || new Date(b.lastSeen) - new Date(a.lastSeen))
        .slice(0, 6);
}

function loadClusterDetection() {
    ensureClusterDetectionWidget();
    const container = document.getElementById('cluster-detection-container');
    if (!container) return;

    const clusters = buildAttackClusters(getAnalyticsLogs());
    analyticsData.clusters = clusters;

    const badge = document.getElementById('clusters-detected');
    if (badge) {
        badge.textContent = `${clusters.length} cluster${clusters.length === 1 ? '' : 's'}`;
    }

    if (!clusters.length) {
        container.innerHTML = formatEmptyState('No clusters yet. Need 3+ related attack events in the selected logs.');
        return;
    }

    container.innerHTML = clusters.map((cluster) => {
        const isSourceCluster = cluster.type === 'source';
        const windowLabel = cluster.windowLabel || `${cluster.windowMinutes} min`;
        const sourceCount = cluster.sourceIPs?.length || 0;
        const title = isSourceCluster
            ? `${cluster.attackType} Source Cluster Detected`
            : `${cluster.attackType} Attack Wave Detected`;
        const summary = isSourceCluster
            ? `${cluster.events} related events from ${cluster.sourceIP} in ${windowLabel}`
            : `${cluster.events} related events across ${sourceCount} sources in ${windowLabel}`;
        const sourceMeta = isSourceCluster
            ? `IP: ${cluster.sourceIP}`
            : `Sources: ${sourceCount}`;

        return `
            <article class="cluster-item">
                <div class="cluster-head">
                    <div>
                        <strong>${escapeHtml(title)}</strong>
                        <p>${escapeHtml(summary)}</p>
                    </div>
                    <span class="cluster-severity">${escapeHtml(cluster.severity.toUpperCase())}</span>
                </div>
                <div class="cluster-meta">
                    <span><i class="fas fa-network-wired"></i> ${escapeHtml(sourceMeta)}</span>
                    <span><i class="fas fa-layer-group"></i> Events: ${cluster.events}</span>
                    <span><i class="fas fa-clock"></i> ${escapeHtml(timeAgo(cluster.lastSeen))}</span>
                    <span><i class="fas fa-server"></i> ${escapeHtml(cluster.targetSystems.slice(0, 2).join(', ') || 'Unknown target')}</span>
                </div>
            </article>
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
    const byCountry = countBy(logs, log => normalizeAnalyticsCountryKey(log.country));
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
        const countryName = getAnalyticsCountryName(countryCluster[0]);
        patterns.push({
            id: patterns.length + 1,
            name: `${countryName} source concentration`,
            confidence: Math.min(95, 55 + countryCluster[1] * 5),
            description: `${countryCluster[1]} events came from ${countryName} in the selected time window`,
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
        const key = log.sourceIP || 'Unknown';
        acc[key] = acc[key] || { ip: key, country: log.country, attacks: 0, lastSeen: log.timestamp };
        acc[key].attacks += 1;
        if (new Date(log.timestamp) > new Date(acc[key].lastSeen)) {
            acc[key].lastSeen = log.timestamp;
            acc[key].country = log.country;
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
                <span class="source-country" title="${escapeHtml(getAnalyticsCountryName(source.country))}">${getAnalyticsCountryFlag(source.country)}</span>
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
    
    const countryGroups = getAnalyticsLogs().reduce((acc, log) => {
        const key = normalizeAnalyticsCountryKey(log.country);
        if (!acc[key]) {
            acc[key] = {
                key,
                country: getAnalyticsCountryName(log.country),
                count: 0
            };
        }
        acc[key].count += 1;
        return acc;
    }, {});
    const positions = {
        US: [30, 25], CN: [35, 75], RU: [25, 65], DE: [40, 48],
        IN: [45, 70], BR: [55, 30], JP: [40, 85], UK: [36, 46], FR: [42, 47], KR: [39, 82]
    };
    const countries = Object.values(countryGroups).sort((a, b) => b.count - a.count);
    container.innerHTML = `
        <div class="world-map-visualization">
            ${countries.map((item, index) => {
                const [top, left] = positions[item.key] || [45 + (index % 4) * 8, 40 + (index % 5) * 7];
                return `<div class="map-point" style="top: ${top}%; left: ${left}%; background: ${item.count > 50 ? '#dc3545' : item.count > 25 ? '#fd7e14' : item.count > 5 ? '#ffc107' : '#28a745'};" data-country="${escapeHtml(item.country)}">
                    <div class="map-tooltip">${escapeHtml(item.country)}: ${item.count} attacks</div>
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
    if (!analyticsLogsReady) {
        await hydrateAnalyticsLogs();
        renderAnalyticsWidgets();
    }

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
async function updateAnalytics() {
    await hydrateAnalyticsLogs();
    renderAnalyticsWidgets({ notify: true });
}

// Run Pattern Analysis
function runPatternAnalysis() {
    if (!isAdminUser()) {
        showNotification('Analysis refresh is available for admins only.', 'warning');
        return;
    }
    loadClusterDetection();
    loadAnomalies();
    loadPredictions();
    updateAnalyticsStats();
    showNotification('Analytics recalculated from stored logs', 'success');
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
