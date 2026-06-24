// Dashboard Specific JavaScript

let dashboardLiveSocket = null;
let dashboardRefreshTimer = null;
const DASHBOARD_LIVE_STREAM_STATE_KEY = 'microsocLiveStreamState';
const DASHBOARD_LIVE_STREAM_TAB_ID_KEY = 'microsocLiveStreamTabId';
const DASHBOARD_LOG_STORAGE_KEY = 'microsocSecurityLogs';
const DASHBOARD_DELETED_LOG_IDS_KEY = 'microsocDeletedLogIds';
const DASHBOARD_FETCH_TIMEOUT_MS = 2500;

function getApiBaseUrl() {
    return window.MICROSOC_API_BASE_URL || 'https://microsoc-backend.onrender.com/api';
}

function getAuthHeaders() {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
    };
}

async function fetchJsonWithTimeout(url, options = {}, timeoutMs = DASHBOARD_FETCH_TIMEOUT_MS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        const payload = await response.json().catch(() => ({}));
        return { response, payload };
    } finally {
        clearTimeout(timer);
    }
}

// Initialize Dashboard
function initDashboard() {
    removeDashboardStreamControls();
    removeProfileRefreshButton();
    loadStats();
    loadAttackTrends();
    loadTopAttackers();
    loadAttackMap();
    loadNotifications();
    initCharts();
    loadUserProfile();
    checkSystemHealth();
    updateTime();
    setInterval(updateTime, 1000);
    refreshDashboardLiveView();
    syncDashboardLiveStreamFromState();
    if (!dashboardRefreshTimer) {
        dashboardRefreshTimer = setInterval(refreshDashboardLiveView, 5000);
    }
}

function removeDashboardStreamControls() {
    document.querySelectorAll('.main-header .log-controls').forEach((controls) => {
        controls.remove();
    });
}

function removeProfileRefreshButton() {
    document
        .querySelectorAll('.card-header button[onclick="refreshProfile()"]')
        .forEach((button) => button.remove());
}

function loadDashboardStoredLogs() {
    try {
        const stored = JSON.parse(localStorage.getItem(DASHBOARD_LOG_STORAGE_KEY) || '[]');
        return filterDashboardDeletedLogs(Array.isArray(stored) ? stored : []);
    } catch (error) {
        return [];
    }
}

function getDashboardLogId(log) {
    return String(log?._id || log?.id || `${log?.timestamp || ''}-${log?.sourceIP || ''}-${log?.attackType || ''}`);
}

function getDashboardDeletedLogIds() {
    try {
        const ids = JSON.parse(localStorage.getItem(DASHBOARD_DELETED_LOG_IDS_KEY) || '[]');
        return new Set(Array.isArray(ids) ? ids.map(String) : []);
    } catch (error) {
        return new Set();
    }
}

function filterDashboardDeletedLogs(logs) {
    const deletedIds = getDashboardDeletedLogIds();
    return (Array.isArray(logs) ? logs : []).filter(log => !deletedIds.has(getDashboardLogId(log)));
}

async function loadDashboardLogsFromApi() {
    try {
        const { response, payload } = await fetchJsonWithTimeout(`${getApiBaseUrl()}/logs?limit=10&timeRange=all&_=${Date.now()}`, {
            headers: {
                ...getAuthHeaders(),
                'Cache-Control': 'no-cache'
            },
            cache: 'no-store'
        });
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'Could not load live logs');
        }
        return filterDashboardDeletedLogs(payload.logs || []);
    } catch (error) {
        console.warn('Dashboard live logs fetch failed:', error);
        return [];
    }
}

async function refreshDashboardLiveView() {
    syncDashboardLogsFromStorage();
    loadTopAttackers();
    loadAttackMap();

    const state = getDashboardLiveStreamState();
    if (!state.active) return;

    const apiLogs = await loadDashboardLogsFromApi();
    if (apiLogs.length > 0) {
        const container = document.getElementById('realtime-logs');
        if (container) {
            container.innerHTML = '';
            apiLogs.slice().reverse().forEach(log => appendLog(container, log));
        }
    }
}

// Load Stats Cards
async function loadStats() {
    const container = document.getElementById('stats-container');
    if (!container) return;
    container.innerHTML = '<div class="empty-state">Loading dashboard stats...</div>';

    try {
        const { response, payload } = await fetchJsonWithTimeout(`${getApiBaseUrl()}/dashboard/stats`, {
            headers: getAuthHeaders()
        });
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'Could not load dashboard stats');
        }
        const stats = payload.stats || [];

        if (stats.length && stats.some(stat => String(stat.value || '').trim() !== '0')) {
            renderDashboardStats(stats);
            return;
        }

        const logStats = await fetchLogStatsFallback();
        if (logStats) {
            renderDashboardStats(buildStatsFromLogStats(logStats));
            return;
        }

        renderDashboardStats(stats);
    } catch (error) {
        console.error('Dashboard stats failed:', error);
        const logStats = await fetchLogStatsFallback();
        if (logStats) {
            renderDashboardStats(buildStatsFromLogStats(logStats));
            return;
        }
        loadLocalStats();
    }
}

function renderDashboardStats(stats) {
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

async function fetchLogStatsFallback() {
    try {
        const { response, payload } = await fetchJsonWithTimeout(`${getApiBaseUrl()}/logs/stats?timeRange=24h`, {
            headers: getAuthHeaders()
        });
        if (!response.ok || !payload.success || !payload.stats) {
            return null;
        }
        return payload.stats;
    } catch (error) {
        console.warn('Log stats fallback failed:', error);
        return null;
    }
}

function countItems(items, predicate) {
    return (Array.isArray(items) ? items : []).filter(predicate).length;
}

const COUNTRY_POSITION_MAP = {
    US: [30, 25],
    CN: [35, 75],
    RU: [25, 65],
    DE: [40, 48],
    IN: [45, 70],
    BR: [55, 30],
    JP: [40, 85],
    UK: [36, 46],
    FR: [42, 47],
    KR: [39, 82]
};

const COUNTRY_NAME_MAP = {
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

const COUNTRY_ALIAS_MAP = {
    us: 'US',
    usa: 'US',
    'united states': 'US',
    'united states of america': 'US',
    'u.s.a.': 'US',
    america: 'US',
    cn: 'CN',
    china: 'CN',
    ru: 'RU',
    russia: 'RU',
    'russian federation': 'RU',
    de: 'DE',
    germany: 'DE',
    in: 'IN',
    india: 'IN',
    br: 'BR',
    brazil: 'BR',
    jp: 'JP',
    japan: 'JP',
    uk: 'UK',
    'united kingdom': 'UK',
    kr: 'KR',
    korea: 'KR',
    'south korea': 'KR',
    france: 'FR',
    fr: 'FR'
};

function normalizeCountryKey(value) {
    const raw = String(value || '').trim();
    if (!raw) return 'Unknown';
    return COUNTRY_ALIAS_MAP[raw.toLowerCase()] || raw.toUpperCase();
}

function getCountryDisplayName(value) {
    const key = normalizeCountryKey(value);
    if (key === 'Unknown') return 'Unknown';
    return COUNTRY_NAME_MAP[key] || value || key;
}

function getCountryPosition(value, index = 0) {
    const key = normalizeCountryKey(value);
    return COUNTRY_POSITION_MAP[key] || [18 + ((index * 13) % 64), 24 + ((index * 19) % 46)];
}

async function loadLogsForRange(timeRange = '24h', limit = 5000) {
    const { response, payload } = await fetchJsonWithTimeout(`${getApiBaseUrl()}/logs?limit=${limit}&timeRange=${encodeURIComponent(timeRange)}`, {
        headers: getAuthHeaders()
    });
    if (!response.ok || !payload.success) {
        throw new Error(payload.message || 'Could not load logs');
    }
    return Array.isArray(payload.logs) ? payload.logs : [];
}

function buildTrendSeriesFromLogs(logs, timeRange = '7d') {
    const windows = {
        '24h': 24 * 60 * 60 * 1000,
        '7d': 7 * 24 * 60 * 60 * 1000,
        '30d': 30 * 24 * 60 * 60 * 1000
    };
    const now = Date.now();
    const since = now - (windows[timeRange] || windows['7d']);
    const buckets = new Map();

    logs.forEach((log) => {
        const timestamp = new Date(log.timestamp || log.createdAt).getTime();
        if (!Number.isFinite(timestamp) || timestamp < since) return;

        const date = new Date(timestamp);
        const bucketKey = timeRange === '24h'
            ? `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}-${date.getHours()}`
            : `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
        const label = timeRange === '24h'
            ? `${String(date.getHours()).padStart(2, '0')}:00`
            : `${date.toLocaleString('en-US', { month: 'short', day: 'numeric' })}`;
        const current = buckets.get(bucketKey) || {
            key: bucketKey,
            label,
            timestamp,
            critical: 0,
            high: 0,
            medium: 0
        };

        const severity = String(log.severity || '').toLowerCase();
        if (severity === 'critical') current.critical += 1;
        else if (severity === 'high') current.high += 1;
        else if (severity === 'medium') current.medium += 1;
        current.timestamp = Math.min(current.timestamp, timestamp);
        buckets.set(bucketKey, current);
    });

    return Array.from(buckets.values()).sort((a, b) => a.timestamp - b.timestamp);
}

function summarizeLogStats(logStats) {
    const totalLogs = logStats?.totalLogs?.[0]?.count || 0;
    const blockedAttacks = logStats?.blockedAttacks?.[0]?.count || 0;
    const severityDistribution = Array.isArray(logStats?.severityDistribution) ? logStats.severityDistribution : [];
    const criticalLogs = severityDistribution.find(item => item._id === 'critical')?.count || 0;
    const highLogs = severityDistribution.find(item => item._id === 'high')?.count || 0;
    const mediumLogs = severityDistribution.find(item => item._id === 'medium')?.count || 0;
    const uniqueSources = Array.isArray(logStats?.topAttackers) ? logStats.topAttackers.length : 0;
    const blockedPercentage = totalLogs > 0 ? Math.round((blockedAttacks / totalLogs) * 100) : 0;
    return {
        totalLogs,
        blockedAttacks,
        criticalLogs,
        highLogs,
        mediumLogs,
        uniqueSources,
        blockedPercentage
    };
}

function buildStatsFromLogStats(logStats) {
    const summary = summarizeLogStats(logStats);
    const severityTotal = Math.max(1, summary.criticalLogs + summary.highLogs + summary.mediumLogs);
    const logPressure = Math.round(
        ((summary.criticalLogs / severityTotal) * 45) +
        ((summary.highLogs / severityTotal) * 25) +
        ((summary.mediumLogs / severityTotal) * 12)
    );
    const responsePressure = Math.min(35, Math.round(summary.totalLogs > 0 ? summary.totalLogs * 0 : 0) + 0);
    const resilienceBonus = Math.min(15, Math.round(summary.blockedPercentage / 7)) + Math.min(10, Math.round(summary.uniqueSources / 20));
    const totalThreatSignals = summary.totalLogs + summary.blockedAttacks + summary.uniqueSources;
    const securityScore = Math.max(
        totalThreatSignals > 0 ? 20 : 45,
        Math.min(
            100,
            92
                - logPressure
                - responsePressure
                + resilienceBonus
                + (totalThreatSignals > 0 ? 4 : 0)
        )
    );

    return [
        {
            icon: 'fa-shield-virus',
            title: 'Security Score',
            value: `${securityScore}/100`,
            change: summary.totalLogs > 0 ? `${summary.blockedPercentage}% blocked` : 'Awaiting logs',
            changeType: securityScore >= 80 ? 'positive' : 'negative',
            color: '#20c997'
        },
        {
            icon: 'fa-broadcast-tower',
            title: 'Total Logs (24h)',
            value: summary.totalLogs.toLocaleString(),
            change: summary.totalLogs > 0 ? `${summary.totalLogs >= 100 ? '+' : ''}${summary.totalLogs}` : 'No activity',
            changeType: summary.totalLogs > 0 ? 'negative' : 'positive',
            color: '#007bff'
        },
        {
            icon: 'fa-exclamation-triangle',
            title: 'Critical Threats',
            value: summary.criticalLogs,
            change: summary.criticalLogs > 0 ? '+Active' : 'Stable',
            changeType: summary.criticalLogs > 0 ? 'negative' : 'positive',
            color: '#dc3545'
        },
        {
            icon: 'fa-clock',
            title: 'Blocked Attacks',
            value: summary.blockedAttacks,
            change: `${summary.blockedPercentage}%`,
            changeType: summary.blockedPercentage >= 50 ? 'positive' : 'negative',
            color: '#28a745'
        },
        {
            icon: 'fa-shield-alt',
            title: 'Attack Prevention',
            value: `${summary.blockedPercentage}%`,
            change: summary.blockedPercentage >= 50 ? 'Strong' : 'Needs tuning',
            changeType: summary.blockedPercentage >= 50 ? 'positive' : 'negative',
            color: '#17a2b8'
        },
        {
            icon: 'fa-network-wired',
            title: 'Unique Sources',
            value: summary.uniqueSources,
            change: summary.uniqueSources > 0 ? `${summary.uniqueSources} active` : 'None yet',
            changeType: summary.uniqueSources > 0 ? 'negative' : 'positive',
            color: '#6c757d'
        }
    ];
}

function loadLocalStats() {
    const storedLogs = loadDashboardStoredLogs();
    if (storedLogs.length) {
        const summary = summarizeStoredLogs(storedLogs);
        renderDashboardStats(buildStatsFromStoredLogs(summary));
        return;
    }

    renderDashboardStats([
        { icon: 'fa-broadcast-tower', title: 'Total Logs', value: '0', change: 'Waiting', changeType: 'positive', color: '#007bff' },
        { icon: 'fa-exclamation-triangle', title: 'Active Incidents', value: '0', change: 'Waiting', changeType: 'positive', color: '#dc3545' },
        { icon: 'fa-skull-crossbones', title: 'Critical Threats', value: '0', change: 'Waiting', changeType: 'positive', color: '#fd7e14' },
        { icon: 'fa-clock', title: 'Avg Response Time', value: 'N/A', change: 'Waiting', changeType: 'positive', color: '#28a745' },
        { icon: 'fa-shield-alt', title: 'Attack Prevention', value: '0%', change: 'Waiting', changeType: 'positive', color: '#17a2b8' },
        { icon: 'fa-network-wired', title: 'Unique Sources', value: '0', change: 'Waiting', changeType: 'positive', color: '#6c757d' }
    ]);
}

function summarizeStoredLogs(logs) {
    const totalLogs = logs.length;
    const blockedAttacks = countItems(logs, log => log.isBlocked);
    const criticalLogs = countItems(logs, log => String(log.severity).toLowerCase() === 'critical');
    const highLogs = countItems(logs, log => String(log.severity).toLowerCase() === 'high');
    const mediumLogs = countItems(logs, log => String(log.severity).toLowerCase() === 'medium');
    const uniqueSources = new Set(logs.map(log => log.sourceIP).filter(Boolean)).size;
    const blockedPercentage = totalLogs > 0 ? Math.round((blockedAttacks / totalLogs) * 100) : 0;
    return { totalLogs, blockedAttacks, criticalLogs, highLogs, mediumLogs, uniqueSources, blockedPercentage };
}

function buildStatsFromStoredLogs(summary) {
    const severityTotal = Math.max(1, summary.criticalLogs + summary.highLogs + summary.mediumLogs);
    const logPressure = Math.round(
        ((summary.criticalLogs / severityTotal) * 45) +
        ((summary.highLogs / severityTotal) * 25) +
        ((summary.mediumLogs / severityTotal) * 12)
    );
    const responsePressure = 0;
    const resilienceBonus = Math.min(15, Math.round(summary.blockedPercentage / 7)) + Math.min(10, Math.round(summary.uniqueSources / 20));
    const totalThreatSignals = summary.totalLogs + summary.blockedAttacks + summary.uniqueSources;
    const securityScore = Math.max(
        totalThreatSignals > 0 ? 20 : 45,
        Math.min(
            100,
            92
                - logPressure
                - responsePressure
                + resilienceBonus
                + (totalThreatSignals > 0 ? 4 : 0)
        )
    );

    return [
        {
            icon: 'fa-shield-virus',
            title: 'Security Score',
            value: `${securityScore}/100`,
            change: `${summary.blockedPercentage}% blocked`,
            changeType: securityScore >= 80 ? 'positive' : 'negative',
            color: '#20c997'
        },
        {
            icon: 'fa-broadcast-tower',
            title: 'Total Logs (24h)',
            value: summary.totalLogs.toLocaleString(),
            change: `${summary.totalLogs} live events`,
            changeType: summary.totalLogs > 0 ? 'negative' : 'positive',
            color: '#007bff'
        },
        {
            icon: 'fa-exclamation-triangle',
            title: 'Critical Threats',
            value: summary.criticalLogs,
            change: summary.criticalLogs > 0 ? '+Active' : 'Stable',
            changeType: summary.criticalLogs > 0 ? 'negative' : 'positive',
            color: '#dc3545'
        },
        {
            icon: 'fa-clock',
            title: 'Blocked Attacks',
            value: summary.blockedAttacks,
            change: `${summary.blockedPercentage}%`,
            changeType: summary.blockedPercentage >= 50 ? 'positive' : 'negative',
            color: '#28a745'
        },
        {
            icon: 'fa-shield-alt',
            title: 'Attack Prevention',
            value: `${summary.blockedPercentage}%`,
            change: summary.blockedPercentage >= 50 ? 'Strong' : 'Needs tuning',
            changeType: summary.blockedPercentage >= 50 ? 'positive' : 'negative',
            color: '#17a2b8'
        },
        {
            icon: 'fa-network-wired',
            title: 'Unique Sources',
            value: summary.uniqueSources,
            change: summary.uniqueSources > 0 ? `${summary.uniqueSources} active` : 'None yet',
            changeType: summary.uniqueSources > 0 ? 'negative' : 'positive',
            color: '#6c757d'
        }
    ];
}

// Load Attack Trends Chart
async function loadAttackTrends() {
    const ctx = document.getElementById('attackTrendsChart');
    if (!ctx) return;

    const timeRange = document.getElementById('time-range')?.value || '7d';
    let trendSeries = [];
    try {
        const logs = await loadLogsForRange(timeRange, 5000);
        trendSeries = buildTrendSeriesFromLogs(logs, timeRange);
    } catch (error) {
        console.error('Attack trends failed:', error);
    }

    if (window.attackTrendsChart?.destroy) {
        window.attackTrendsChart.destroy();
    }

    const labels = trendSeries.map(item => item.label);
    const chartData = {
        labels,
        datasets: [
            {
                label: 'Critical',
                data: trendSeries.map(item => item.critical),
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                tension: 0.4
            },
            {
                label: 'High',
                data: trendSeries.map(item => item.high),
                borderColor: '#fd7e14',
                backgroundColor: 'rgba(253, 126, 20, 0.1)',
                tension: 0.4
            },
            {
                label: 'Medium',
                data: trendSeries.map(item => item.medium),
                borderColor: '#ffc107',
                backgroundColor: 'rgba(255, 193, 7, 0.1)',
                tension: 0.4
            }
        ]
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

    const loading = document.getElementById('chart-loading');
    if (loading) {
        loading.style.display = 'none';
    }
}

// Load Top Attackers
async function loadTopAttackers() {
    const container = document.getElementById('top-attackers');
    if (!container) return;
    const storedAttackers = getTopAttackersFromStoredLogs();

    try {
        const { response, payload } = await fetchJsonWithTimeout(`${getApiBaseUrl()}/logs?limit=200&timeRange=all&_=${Date.now()}`, {
            headers: {
                ...getAuthHeaders(),
                'Cache-Control': 'no-cache'
            },
            cache: 'no-store'
        });
        if (!response.ok || !payload.success) throw new Error(payload.message || 'Could not load top attackers');
        const apiLogs = filterDashboardDeletedLogs(payload.logs || []);
        const attackers = summarizeTopAttackers(apiLogs);
        if (attackers.length) {
            renderTopAttackers(attackers);
            return;
        }
    } catch (error) {
        console.error('Top attackers failed:', error);
        if (storedAttackers.length) {
            renderTopAttackers(storedAttackers);
            return;
        }
    }

    renderEmptyTopAttackers();
}

function renderTopAttackersFromStoredLogs() {
    const container = document.getElementById('top-attackers');
    if (!container) return false;

    const attackers = getTopAttackersFromStoredLogs();

    if (!attackers.length) return false;

    renderTopAttackers(attackers);
    return true;
}

function getTopAttackersFromStoredLogs() {
    return summarizeTopAttackers(loadDashboardStoredLogs());
}

function summarizeTopAttackers(logs) {
    if (!Array.isArray(logs) || !logs.length) return [];

    return Object.values(logs.reduce((acc, log) => {
        const ip = log.sourceIP || 'Unknown';
        if (!acc[ip]) {
            acc[ip] = {
                ip,
                country: log.country || 'Unknown',
                attacks: 0,
                lastSeen: log.timestamp
            };
        }
        acc[ip].attacks += 1;
        const currentTime = new Date(acc[ip].lastSeen || 0).getTime();
        const nextTime = new Date(log.timestamp || Date.now()).getTime();
        if (nextTime >= currentTime) {
            acc[ip].lastSeen = log.timestamp;
            acc[ip].country = log.country || acc[ip].country;
        }
        return acc;
    }, {}))
        .sort((a, b) => {
            if (b.attacks !== a.attacks) return b.attacks - a.attacks;
            return new Date(b.lastSeen || 0).getTime() - new Date(a.lastSeen || 0).getTime();
        })
        .slice(0, 5);
}

function renderTopAttackers(attackers) {
    const container = document.getElementById('top-attackers');
    if (!container) return;

    container.innerHTML = attackers.map(attacker => `
        <tr>
            <td class="ip-address">${attacker.ip}</td>
            <td><i class="fas fa-globe-americas"></i> ${attacker.country}</td>
            <td><span class="badge badge-danger">${attacker.attacks}</span></td>
            <td class="timestamp">${formatDate(attacker.lastSeen)}</td>
        </tr>
    `).join('');
}

function renderEmptyTopAttackers() {
    const container = document.getElementById('top-attackers');
    if (!container) return;
    container.innerHTML = '<tr><td colspan="4" class="empty-state" style="text-align:center;padding:20px;">No attacker data yet. Start the Logs live stream to populate this table.</td></tr>';
}

async function loadAttackMap() {
    const container = document.getElementById('attack-map-container');
    if (!container) return;

    try {
        const firstPage = await fetchJsonWithTimeout(`${getApiBaseUrl()}/logs?limit=5000&page=1&timeRange=all&_=${Date.now()}`, {
            headers: {
                ...getAuthHeaders(),
                'Cache-Control': 'no-cache'
            },
            cache: 'no-store'
        }, 10000);
        const { response, payload } = firstPage;
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'Could not load attack map');
        }
        const logs = Array.isArray(payload.logs) ? [...payload.logs] : [];
        const totalPages = Math.max(1, Number(payload.totalPages) || 1);
        if (totalPages > 1) {
            const remainingPages = Array.from({ length: totalPages - 1 }, (_, index) => index + 2);
            const pageResponses = await Promise.all(remainingPages.map(async (page) => {
                const pageResult = await fetchJsonWithTimeout(`${getApiBaseUrl()}/logs?limit=5000&page=${page}&timeRange=all&_=${Date.now()}`, {
                    headers: {
                        ...getAuthHeaders(),
                        'Cache-Control': 'no-cache'
                    },
                    cache: 'no-store'
                }, 10000);
                if (!pageResult.response.ok || !pageResult.payload.success) {
                    return [];
                }
                return Array.isArray(pageResult.payload.logs) ? pageResult.payload.logs : [];
            }));
            pageResponses.forEach(pageLogs => logs.push(...pageLogs));
        }
        renderAttackMap(filterDashboardDeletedLogs(logs));
        return;
    } catch (error) {
        console.error('Attack map failed:', error);
    }

    renderAttackMap(loadDashboardStoredLogs());
}

function refreshAttackMap() {
    loadAttackMap().catch(error => {
        console.error('Refresh attack map failed:', error);
    });
}

function renderAttackMap(logs) {
    const container = document.getElementById('attack-map-container');
    if (!container) return;

    const normalizedLogs = (Array.isArray(logs) ? logs : []).map((log) => ({
        country: getCountryDisplayName(log.country || 'Unknown'),
        key: normalizeCountryKey(log.country || 'Unknown'),
        severity: String(log.severity || 'low').toLowerCase()
    }));
    const countryCounts = normalizedLogs.reduce((acc, log) => {
        if (!acc[log.key]) {
            acc[log.key] = { country: log.country, key: log.key, count: 0, severityRank: 0 };
        }
        acc[log.key].count += 1;
        const rank = log.severity === 'critical' ? 4 : log.severity === 'high' ? 3 : log.severity === 'medium' ? 2 : 1;
        acc[log.key].severityRank = Math.max(acc[log.key].severityRank, rank);
        return acc;
    }, {});
    const countrySummaries = Object.values(countryCounts).sort((a, b) => b.count - a.count);
    const totalAttacks = normalizedLogs.length;

    const summaryMarkup = countrySummaries.length ? `
        <div class="attack-country-summary">
            <div class="attack-country-summary-title">All-time logs · Total attacks ${totalAttacks}</div>
            <div class="attack-country-summary-list">
                ${countrySummaries.map(item => `
                    <div class="attack-country-summary-item">
                        <span>${item.country}</span>
                        <strong>${item.count}</strong>
                    </div>
                `).join('')}
            </div>
        </div>
    ` : '';

    container.innerHTML = `
        <div class="map-surface">
            <div class="map-grid"></div>
            ${countrySummaries.length ? '' : '<div class="map-empty-state">No country activity yet.</div>'}
            ${countrySummaries.map((attacker, index) => {
                const pos = getCountryPosition(attacker.key, index);
                const severity = attacker.severityRank >= 4
                    ? 'critical'
                    : attacker.severityRank === 3
                        ? 'high'
                        : attacker.severityRank === 2
                            ? 'medium'
                            : 'low';
                return `
                    <div class="map-point map-point-${attacker.key || index}" style="top:${pos[0]}%;left:${pos[1]}%;background:${getSeverityColor(severity)};">
                        <span class="map-point-count">${attacker.count}</span>
                        <span class="map-tooltip">${attacker.country} • ${attacker.count} attacks</span>
                    </div>
                `;
            }).join('')}
        </div>
        ${summaryMarkup}
    `;
}

function renderStaticAttackMap() {
    const container = document.getElementById('attack-map-container');
    if (!container) return;
    renderAttackMap(loadDashboardStoredLogs());
}

function loadMockAttackTrends() {
    if (window.attackTrendsChart?.destroy) {
        window.attackTrendsChart.destroy();
    }
    const ctx = document.getElementById('attackTrendsChart');
    if (!ctx) return;
    window.attackTrendsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [
                {
                    label: 'Critical',
                    data: [5, 8, 3, 12, 7, 4, 9],
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'High',
                    data: [12, 15, 10, 18, 14, 11, 16],
                    borderColor: '#fd7e14',
                    backgroundColor: 'rgba(253, 126, 20, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Medium',
                    data: [25, 28, 22, 30, 26, 24, 29],
                    borderColor: '#ffc107',
                    backgroundColor: 'rgba(255, 193, 7, 0.1)',
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'top' } },
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(0, 0, 0, 0.1)' } },
                x: { grid: { display: false } }
            }
        }
    });
}

async function loadNotifications() {
    const token = localStorage.getItem('token');
    try {
        const { response, payload } = await fetchJsonWithTimeout(`${getApiBaseUrl()}/dashboard/alerts`, {
            headers: { 'Authorization': `Bearer ${token || ''}` }
        });
        if (response.ok && payload.success) {
            updateNotificationCount(payload.summary?.requiringAction || 0);
            return;
        }
    } catch (error) {
        console.error('Failed to load notifications:', error);
    }
    updateNotificationCount(3);
}

function showNotifications() {
    const modal = document.getElementById('notifications-modal');
    if (modal) modal.classList.remove('hidden');
}

function closeNotifications() {
    const modal = document.getElementById('notifications-modal');
    if (modal) modal.classList.add('hidden');
}

function updateNotificationCount(count) {
    const element = document.getElementById('notification-count');
    if (element) {
        element.textContent = count;
        element.style.display = count > 0 ? 'block' : 'none';
    }
}

// Start Real-time Log Stream
function startLogStream() {
    const container = document.getElementById('realtime-logs');
    if (!container) return;

    if (dashboardLiveSocket && dashboardLiveSocket.readyState === WebSocket.OPEN) {
        return;
    }

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
    dashboardLiveSocket = new WebSocket(wsUrl);
    dashboardLiveSocket.addEventListener('message', event => {
        const payload = JSON.parse(event.data);
        if (payload.log) appendLog(container, payload.log);
        if (payload.alert) {
            const toastType = payload.alert.severity === 'critical' ? 'error' : 'warning';
            showNotification(
                payload.alert.message || payload.alert.title || 'Security alert detected',
                toastType,
                { title: payload.alert.title || 'Threat Alert' }
            );
        }
        if (payload.incident) {
            updateIncidentCount();
            showNotification(
                payload.incident.title || 'Incident created',
                payload.incident.severity === 'critical' ? 'error' : 'warning',
                { title: 'Incident Created' }
            );
        }
    });
    dashboardLiveSocket.addEventListener('close', () => {
        dashboardLiveSocket = null;
    });
}

function getDashboardLiveStreamState() {
    try {
        const state = JSON.parse(localStorage.getItem(DASHBOARD_LIVE_STREAM_STATE_KEY) || 'null');
        return state && typeof state === 'object' ? state : { active: false, owner: null };
    } catch (error) {
        return { active: false, owner: null };
    }
}

function getDashboardLiveStreamTabId() {
    let tabId = sessionStorage.getItem(DASHBOARD_LIVE_STREAM_TAB_ID_KEY);
    if (!tabId) {
        tabId = `tab-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
        sessionStorage.setItem(DASHBOARD_LIVE_STREAM_TAB_ID_KEY, tabId);
    }
    return tabId;
}

function syncDashboardLiveStreamFromState() {
    const state = getDashboardLiveStreamState();
    if (state.active) {
        refreshDashboardLiveView();
    } else {
        if (dashboardLiveSocket) {
            dashboardLiveSocket.close();
            dashboardLiveSocket = null;
        }
        const container = document.getElementById('realtime-logs');
        if (container) {
            container.innerHTML = `
                <div class="log-entry log-entry--placeholder">
                    <div class="log-icon" style="color: #17a2b8">
                        <i class="fas fa-info-circle"></i>
                    </div>
                    <div class="log-content">
                        <strong>Dashboard</strong> waiting for live stream from the Logs page...
                        <div class="log-meta">
                            <span class="log-time">${new Date().toLocaleTimeString()}</span>
                        </div>
                    </div>
                </div>
            `;
        }
    }
}

function syncDashboardLogsFromStorage() {
    const container = document.getElementById('realtime-logs');
    if (!container) return;

    const logs = loadDashboardStoredLogs();
    if (!logs.length) {
        if (!container.querySelector('.log-entry')) {
            container.innerHTML = `
                <div class="log-entry log-entry--placeholder">
                    <div class="log-icon" style="color: #17a2b8">
                        <i class="fas fa-info-circle"></i>
                    </div>
                    <div class="log-content">
                        <strong>Dashboard</strong> waiting for live stream from the Logs page...
                        <div class="log-meta">
                            <span class="log-time">${new Date().toLocaleTimeString()}</span>
                        </div>
                    </div>
                </div>
            `;
        }
        return;
    }

    container.innerHTML = '';
    logs.slice(0, 20).reverse().forEach(log => appendLog(container, log));
}

window.addEventListener('storage', (event) => {
    if (
        event.key === DASHBOARD_LIVE_STREAM_STATE_KEY ||
        event.key === DASHBOARD_LOG_STORAGE_KEY ||
        event.key === DASHBOARD_DELETED_LOG_IDS_KEY
    ) {
        refreshDashboardLiveView();
    }
});

window.addEventListener('microsoc:logs-updated', () => {
    refreshDashboardLiveView();
});

window.addEventListener('focus', () => {
    refreshDashboardLiveView();
});

if (!document.getElementById('dashboard-live-styles')) {
    const style = document.createElement('style');
    style.id = 'dashboard-live-styles';
    style.textContent = `
        .map-surface {
            position: relative;
            height: 100%;
            min-height: 250px;
            border-radius: 12px;
            overflow: hidden;
            background:
                radial-gradient(circle at 20% 20%, rgba(23,162,184,0.14), transparent 25%),
                radial-gradient(circle at 80% 30%, rgba(220,53,69,0.14), transparent 22%),
                linear-gradient(180deg, rgba(15,23,42,0.9), rgba(2,6,23,0.95));
            box-shadow: inset 0 0 0 1px rgba(255,255,255,0.04);
        }

        body[data-theme="light"] .map-surface {
            background:
                radial-gradient(circle at 20% 20%, rgba(14,116,144,0.12), transparent 25%),
                radial-gradient(circle at 80% 30%, rgba(220,53,69,0.1), transparent 22%),
                linear-gradient(180deg, rgba(247,253,255,0.98), rgba(255,255,255,0.98));
            box-shadow: inset 0 0 0 1px rgba(14,116,144,0.08);
        }

        .map-grid {
            position: absolute;
            inset: 0;
            background-image:
                linear-gradient(rgba(255,255,255,0.04) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.04) 1px, transparent 1px);
            background-size: 48px 48px;
            opacity: 0.45;
        }

        body[data-theme="light"] .map-grid {
            background-image:
                linear-gradient(rgba(14,116,144,0.08) 1px, transparent 1px),
                linear-gradient(90deg, rgba(14,116,144,0.08) 1px, transparent 1px);
            opacity: 0.6;
        }

        .map-empty-state {
            position: absolute;
            inset: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            color: rgba(226, 232, 240, 0.78);
            font-weight: 700;
            letter-spacing: 0.2px;
            z-index: 1;
        }

        body[data-theme="light"] .map-empty-state {
            color: #164e63;
        }

        .map-point {
            position: absolute;
            width: 28px;
            height: 28px;
            border-radius: 999px;
            transform: translate(-50%, -50%);
            box-shadow: 0 0 0 0 rgba(255,255,255,0.18);
            animation: dashboardPulse 2s infinite;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            font-weight: 700;
        }

        .map-point.attack-marker {
            width: 10px;
            height: 10px;
            box-shadow: 0 0 0 0 rgba(255,255,255,0.14);
        }

        .map-point.attack-marker::after {
            inset: -5px;
        }

        .map-point::after {
            content: '';
            position: absolute;
            inset: -9px;
            border-radius: 999px;
            border: 1px solid rgba(255,255,255,0.15);
        }

        .map-tooltip {
            position: absolute;
            left: 50%;
            bottom: 150%;
            transform: translateX(-50%);
            background: rgba(2,6,23,0.95);
            color: #fff;
            padding: 6px 10px;
            border-radius: 999px;
            font-size: 11px;
            white-space: nowrap;
            opacity: 0;
            visibility: hidden;
            transition: 0.2s ease;
            pointer-events: none;
            border: 1px solid rgba(255,255,255,0.08);
        }

        body[data-theme="light"] .map-tooltip {
            background: rgba(255,255,255,0.96);
            color: #0f172a;
            border-color: rgba(14,116,144,0.16);
            box-shadow: 0 10px 24px rgba(15,23,42,0.08);
        }

        .map-point-count {
            position: relative;
            z-index: 1;
            font-size: 10px;
            line-height: 1;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
        }

        body[data-theme="light"] .map-point-count {
            color: #fff;
        }

        .map-point:hover .map-tooltip {
            opacity: 1;
            visibility: visible;
        }

        .attack-country-summary {
            margin-top: 12px;
            padding: 12px;
            border-radius: 12px;
            background: rgba(2, 6, 23, 0.72);
            border: 1px solid rgba(255, 255, 255, 0.06);
            max-height: 150px;
            overflow: auto;
        }

        body[data-theme="light"] .attack-country-summary {
            background: rgba(255, 255, 255, 0.9);
            border-color: rgba(14,116,144,0.14);
        }

        .attack-country-summary-title {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #94a3b8;
            margin-bottom: 8px;
        }

        body[data-theme="light"] .attack-country-summary-title {
            color: #0f172a;
        }

        .attack-country-summary-list {
            display: grid;
            gap: 8px;
        }

        .attack-country-summary-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            padding: 8px 10px;
            border-radius: 10px;
            background: rgba(255,255,255,0.06);
            color: #e2e8f0;
            font-size: 12px;
        }

        body[data-theme="light"] .attack-country-summary-item {
            background: rgba(14,116,144,0.06);
            color: #0f172a;
        }

        .attack-country-summary-item strong {
            font-family: 'Roboto Mono', monospace;
            color: #67e8f9;
        }

        body[data-theme="light"] .attack-country-summary-item strong {
            color: #0e7490;
        }

        .stat-card {
            backdrop-filter: blur(12px);
        }

        .log-entry--placeholder {
            opacity: 0.9;
            border-left: 1px solid rgba(23,162,184,0.35);
            background: linear-gradient(90deg, rgba(23,162,184,0.08), rgba(255,255,255,0.02));
        }

        .log-entry--placeholder .log-content strong {
            color: #e2f5ff;
            letter-spacing: 0.02em;
        }

        .log-entry--placeholder .log-time {
            color: #8ca3b8;
        }

        .profile-info {
            display: grid;
            grid-template-columns: 76px 1fr;
            gap: 18px;
            align-items: start;
        }

        .avatar-large {
            width: 76px;
            height: 76px;
            border-radius: 22px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            color: #fff;
            flex-shrink: 0;
            background: linear-gradient(135deg, rgba(6,182,212,0.92), rgba(239,68,68,0.88) 56%, rgba(249,115,22,0.9));
            box-shadow: 0 16px 30px rgba(6,182,212,0.2), inset 0 1px 0 rgba(255,255,255,0.2);
        }

        .profile-details h4 {
            font-size: 26px;
            margin: 0 0 8px;
            letter-spacing: -0.02em;
        }

        .profile-badges {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-bottom: 12px;
        }

        .profile-chip {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 700;
            color: var(--text-secondary);
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.08);
        }

        .profile-chip-primary {
            color: #7dd3fc;
            background: rgba(14, 165, 233, 0.12);
            border-color: rgba(14, 165, 233, 0.24);
        }

        .profile-meta {
            display: grid;
            gap: 10px;
            margin-top: 6px;
        }

        .profile-meta > div {
            display: flex;
            justify-content: space-between;
            gap: 12px;
            padding: 10px 12px;
            border-radius: 14px;
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.06);
        }

        .meta-label {
            color: var(--text-secondary);
            font-size: 12px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .meta-value {
            color: var(--text-primary);
            font-weight: 600;
            text-align: right;
        }

        .health-metrics {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
        }

        .health-metric {
            display: flex;
            flex-direction: column;
            gap: 6px;
            padding: 14px;
            border-radius: 16px;
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.06);
        }

        .metric-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-secondary);
        }

        .metric-value {
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 700;
        }

        .health-actions {
            margin-top: 14px;
            display: flex;
            justify-content: flex-end;
        }

        .health-actions .btn {
            min-width: 170px;
        }

        .profile-details p {
            margin: 0;
        }

        .profile-details #profile-email,
        .profile-details #profile-role,
        .profile-details #profile-last-login {
            display: block;
        }

        .data-table tbody tr td {
            vertical-align: middle;
        }

        .data-table tbody tr td:first-child {
            font-weight: 700;
            color: #e8f7ff;
        }

        .data-table tbody tr td:last-child {
            color: #96aec6;
        }

        @keyframes dashboardPulse {
            0% { box-shadow: 0 0 0 0 rgba(255,255,255,0.18); }
            70% { box-shadow: 0 0 0 14px rgba(255,255,255,0); }
            100% { box-shadow: 0 0 0 0 rgba(255,255,255,0); }
        }
    `;
    document.head.appendChild(style);
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

async function checkSystemHealth() {
    const backendStatus = document.getElementById('backend-status');
    const backendResponse = document.getElementById('backend-response');
    const dbStatus = document.getElementById('db-status');
    const dbResponse = document.getElementById('db-response');
    ensureAiHealthMetric();
    const aiStatus = document.getElementById('ai-status');
    const aiResponse = document.getElementById('ai-response');

    try {
        const { response, payload } = await fetchJsonWithTimeout(`${getApiBaseUrl()}/health`, {}, 3000);
        if (response.ok) {
            if (backendStatus) backendStatus.className = 'status-indicator status-good';
            if (backendResponse) backendResponse.textContent = payload?.status === 'ok' ? 'Connected' : 'Available';
        } else {
            if (backendStatus) backendStatus.className = 'status-indicator status-warning';
            if (backendResponse) backendResponse.textContent = 'Unavailable';
        }
    } catch (error) {
        if (backendStatus) backendStatus.className = 'status-indicator status-bad';
        if (backendResponse) backendResponse.textContent = 'Offline';
    }

    try {
        const response = await fetch(`${getApiBaseUrl()}/logs/stats`, {
            headers: getAuthHeaders()
        });
        if (response.ok) {
            if (dbStatus) dbStatus.className = 'status-indicator status-good';
            if (dbResponse) dbResponse.textContent = 'Connected';
        } else {
            if (dbStatus) dbStatus.className = 'status-indicator status-warning';
            if (dbResponse) dbResponse.textContent = 'Issues detected';
        }
    } catch (error) {
        if (dbStatus) dbStatus.className = 'status-indicator status-bad';
        if (dbResponse) dbResponse.textContent = 'Offline';
    }

    try {
        const { response, payload } = await fetchJsonWithTimeout(`${getApiBaseUrl()}/ai/status`, {
            headers: getAuthHeaders()
        }, 3000);
        if (response.ok && payload.success) {
            const healthy = payload.healthy !== false && payload.hasProviderKey !== false;
            if (aiStatus) aiStatus.className = healthy ? 'status-indicator status-good' : 'status-indicator status-warning';
            if (aiResponse) {
                aiResponse.textContent = healthy
                    ? `${payload.provider || 'ai'} ready`
                    : `${payload.provider || 'ai'} needs key`;
            }
        } else {
            if (aiStatus) aiStatus.className = 'status-indicator status-warning';
            if (aiResponse) aiResponse.textContent = 'Unavailable';
        }
    } catch (error) {
        if (aiStatus) aiStatus.className = 'status-indicator status-bad';
        if (aiResponse) aiResponse.textContent = 'Offline';
    }
}

function ensureAiHealthMetric() {
    const metrics = document.querySelector('.health-metrics');
    if (!metrics || metrics.querySelector('#ai-status')) return;

    const metric = document.createElement('div');
    metric.className = 'health-metric';
    metric.innerHTML = `
        <div class="metric-label">AI Provider</div>
        <div class="metric-value">
            <span class="status-indicator" id="ai-status"></span>
            <span id="ai-response">Checking...</span>
        </div>
    `;
    metrics.appendChild(metric);
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

    const card = document.querySelector('.profile-info');
    if (card) {
        const lastLogin = localStorage.getItem('lastLogin') || new Date().toISOString();
        card.innerHTML = `
            <div class="avatar-large">
                <i class="fas fa-user-secret"></i>
            </div>
            <div class="profile-details">
                <h4>${user.name || 'User'}</h4>
                <div class="profile-badges">
                    <span class="profile-chip profile-chip-primary">${(user.role || 'analyst').toUpperCase()}</span>
                    <span class="profile-chip">${user.email || 'No email'}</span>
                </div>
                <div class="profile-meta">
                    <div><span class="meta-label">Last Login</span><span class="meta-value" id="profile-last-login">${formatDateTime(lastLogin)}</span></div>
                    <div><span class="meta-label">Email</span><span class="meta-value" id="profile-email">${user.email || 'Not available'}</span></div>
                    <div><span class="meta-label">Role</span><span class="meta-value" id="profile-role">Role: ${user.role ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : 'User'}</span></div>
                </div>
            </div>
        `;
        localStorage.setItem('lastLogin', new Date().toISOString());
    }
}

// Export functions
window.loadStats = loadStats;
window.loadAttackTrends = loadAttackTrends;
window.loadTopAttackers = loadTopAttackers;
window.refreshAttackMap = refreshAttackMap;
window.startLogStream = startLogStream;
window.clearLogs = clearLogs;
window.updateChart = updateChart;
window.initDashboard = initDashboard;
