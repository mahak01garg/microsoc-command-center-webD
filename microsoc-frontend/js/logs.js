// Logs Page JavaScript

let allLogs = [];
let filteredLogs = [];
let currentLogs = [];
let selectedLogs = new Set();
let isLiveStreaming = false;
let isLiveStreamStarting = false;
let liveStreamInterval = null;
let liveStreamFirstTimer = null;
let liveRenderTimer = null;
let liveStreamThresholdSettings = null;
let liveAttackScenario = null;
let liveAttackScenarioCursor = 0;
let liveStreamGeneration = 0;
let pendingLiveLogs = [];
let autoConvertedLiveLogIds = new Set();
let autoAlertCorrelationState = {};
let currentPage = 1;
let itemsPerPage = 25;
let totalPages = 1;
const LOG_STORAGE_KEY = 'microsocSecurityLogs';
const LOG_TOTAL_COUNT_KEY = 'microsocSecurityLogsTotalCount';
const DELETED_LOG_IDS_KEY = 'microsocDeletedLogIds';
const ARCHIVED_LOG_IDS_KEY = 'microsocArchivedLogIds';
const ARCHIVED_LOGS_KEY = 'microsocArchivedLogs';
const ALERT_CORRELATION_CACHE_KEY = 'microsocAlertCorrelationCache';
const MAX_STORED_LOGS = 1000;
const LOG_SYNC_LIMIT = 300;
const MAX_ALERT_CORRELATION_CACHE = 1000;
const LIVE_STREAM_INTERVAL_MS = 3000;
const LIVE_STREAM_FIRST_DELAY_MS = 1200;
const LIVE_RENDER_DEBOUNCE_MS = 250;
const LIVE_STREAM_STATE_KEY = 'microsocLiveStreamState';
const LIVE_STREAM_TAB_ID_KEY = 'microsocLiveStreamTabId';
const DEFAULT_INCIDENT_THRESHOLD = 3;
const DEFAULT_ALERT_SETTINGS = {
    failedLoginThreshold: 5,
    otherAlertsThreshold: 1
};
const DEFAULT_LIVE_STREAM_SETTINGS = {
    ...DEFAULT_ALERT_SETTINGS,
    createIncidentAfter: DEFAULT_INCIDENT_THRESHOLD
};
const LIVE_ATTACK_SCENARIO_TYPES = [
    'SQL Injection',
    'XSS',
    'DDoS',
    'Log4Shell Exploit',
    'Exchange Server Exploit',
    'Port Scan',
    'Brute Force',
    'Credential Stuffing',
    'Password Spraying',
    'Malware',
    'Phishing',
    'PowerShell Abuse',
    'Ransomware',
    'Microsoft Outlook Exploit',
    'Apache Struts Exploit'
];
let logsApiRefreshTimer = null;

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

function canManageLogs() {
    return isAdminUser();
}

function normalizeLogPromotionButtons() {
    document.querySelectorAll('button[onclick*="createIncidentFromSelected"]').forEach(button => {
        button.setAttribute('onclick', 'createAlertFromSelected()');
        button.innerHTML = '<i class="fas fa-bell"></i> Create Alert';
        button.title = 'Create alert from selected logs';
    });
}

function syncLogRoleUi() {
    normalizeLogPromotionButtons();
    document.querySelectorAll('#total-logs').forEach(element => {
        const title = element.closest('.stat-info')?.querySelector('h3');
        if (title) title.textContent = 'Total Logs';
    });

    document.querySelectorAll('#bulk-actions, #selected-delete-btn').forEach(element => {
        element.style.display = 'none';
    });

    const headerButtonSelectors = [
        '.log-controls .btn-danger',
        '.log-controls button[onclick*="clearLogs"]',
        '.log-controls button[onclick*="deleteSelectedLogs"]',
        '.log-controls button[onclick*="exportSelectedLogs"]'
    ];

    headerButtonSelectors.forEach(selector => {
        document.querySelectorAll(selector).forEach(button => {
            button.style.display = 'none';
        });
    });

    const headerTitle = document.querySelector('.main-header .header-left h1');
    const headerSubtitle = document.querySelector('.main-header .header-left .subtitle');
    if (headerTitle) {
        headerTitle.innerHTML = canManageLogs()
            ? '<i class="fas fa-stream"></i> Security Logs'
            : '<i class="fas fa-stream"></i> Security Logs';
    }
    if (headerSubtitle && !canManageLogs()) {
        headerSubtitle.textContent = 'View-only access for analysts';
    }

    syncSelectionColumnVisibility();
    updateSelectedCount();
}

function ensureSelectedDeleteButton() {
    document.getElementById('selected-delete-btn')?.remove();
}

function syncSelectionColumnVisibility() {
    const selectAll = document.getElementById('select-all');
    const headerCell = selectAll?.closest('th');

    if (headerCell) {
        headerCell.classList.add('log-select-header');
        headerCell.style.display = 'none';
    }

    if (selectAll) {
        selectAll.checked = false;
        selectAll.disabled = true;
        selectAll.style.display = 'none';
    }

    selectedLogs.clear();
    document.querySelectorAll('.log-select-cell').forEach(cell => {
        cell.style.display = 'none';
    });
    document.querySelectorAll('.log-checkbox').forEach(input => {
        input.checked = false;
        input.disabled = true;
        input.style.display = 'none';
    });
}

function getLiveStreamTabId() {
    let tabId = sessionStorage.getItem(LIVE_STREAM_TAB_ID_KEY);
    if (!tabId) {
        tabId = `tab-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
        sessionStorage.setItem(LIVE_STREAM_TAB_ID_KEY, tabId);
    }
    return tabId;
}

function getLiveStreamState() {
    try {
        const state = JSON.parse(localStorage.getItem(LIVE_STREAM_STATE_KEY) || 'null');
        return state && typeof state === 'object' ? state : { active: false, owner: null, startedAt: null, lastSeenAt: null };
    } catch (error) {
        return { active: false, owner: null, startedAt: null, lastSeenAt: null };
    }
}

function setLiveStreamState(state) {
    localStorage.setItem(LIVE_STREAM_STATE_KEY, JSON.stringify({
        active: Boolean(state.active),
        owner: state.owner || null,
        startedAt: state.startedAt || null,
        lastSeenAt: state.lastSeenAt || new Date().toISOString()
    }));
}

function claimLiveStreamOwnership() {
    const tabId = getLiveStreamTabId();
    const state = getLiveStreamState();
    if (!state.active || state.owner === tabId) {
        setLiveStreamState({
            active: true,
            owner: tabId,
            startedAt: state.startedAt || new Date().toISOString(),
            lastSeenAt: new Date().toISOString()
        });
        return true;
    }
    return false;
}

function releaseLiveStreamOwnership() {
    const state = getLiveStreamState();
    const tabId = getLiveStreamTabId();
    if (state.owner !== tabId) return;
    setLiveStreamState({
        active: false,
        owner: null,
        startedAt: null,
        lastSeenAt: new Date().toISOString()
    });
}

function syncLiveStreamFromState() {
    const state = getLiveStreamState();
    const tabId = getLiveStreamTabId();
    const shouldRun = Boolean(state.active && state.owner === tabId);

    if (shouldRun && !isLiveStreaming) {
        startLiveStream({ fromSync: true });
    } else if (!shouldRun && isLiveStreaming) {
        pauseLiveStream({ fromSync: true });
    }
}

function getApiBaseUrl() {
    return window.MICROSOC_API_BASE_URL || 'https://microsoc-backend.onrender.com/api';
}

function loadStoredLogs() {
    try {
        const stored = JSON.parse(localStorage.getItem(LOG_STORAGE_KEY) || '[]');
        return filterArchivedLogs(filterDeletedLogs(Array.isArray(stored) ? stored.map(normalizeLog) : []));
    } catch (error) {
        return [];
    }
}

function getStoredLogTotal() {
    const storedTotal = Number(localStorage.getItem(LOG_TOTAL_COUNT_KEY) || 0);
    return Number.isFinite(storedTotal) && storedTotal > 0 ? storedTotal : 0;
}

function getDeletedLogIds() {
    try {
        const ids = JSON.parse(localStorage.getItem(DELETED_LOG_IDS_KEY) || '[]');
        return new Set(Array.isArray(ids) ? ids.map(String) : []);
    } catch (error) {
        return new Set();
    }
}

function rememberDeletedLogIds(ids) {
    const deletedIds = getDeletedLogIds();
    ids.filter(Boolean).map(String).forEach(id => deletedIds.add(id));
    localStorage.setItem(DELETED_LOG_IDS_KEY, JSON.stringify(Array.from(deletedIds).slice(-3000)));
}

function getArchivedLogIds() {
    try {
        const ids = JSON.parse(localStorage.getItem(ARCHIVED_LOG_IDS_KEY) || '[]');
        return new Set(Array.isArray(ids) ? ids.map(String) : []);
    } catch (error) {
        return new Set();
    }
}

function rememberArchivedLog(log) {
    const archivedIds = getArchivedLogIds();
    const logId = getLogId(log);
    archivedIds.add(logId);
    localStorage.setItem(ARCHIVED_LOG_IDS_KEY, JSON.stringify(Array.from(archivedIds).slice(-3000)));

    try {
        const archivedLogs = JSON.parse(localStorage.getItem(ARCHIVED_LOGS_KEY) || '[]');
        const normalized = { ...normalizeLog(log), archived: true, archivedAt: new Date().toISOString() };
        const nextLogs = [normalized, ...(Array.isArray(archivedLogs) ? archivedLogs : []).filter(item => getLogId(item) !== logId)];
        localStorage.setItem(ARCHIVED_LOGS_KEY, JSON.stringify(nextLogs.slice(0, MAX_STORED_LOGS)));
    } catch (error) {
        console.warn('Could not store archived log locally:', error);
    }
}

function filterDeletedLogs(logs) {
    const deletedIds = getDeletedLogIds();
    return (Array.isArray(logs) ? logs : []).filter(log => !deletedIds.has(getLogId(log)));
}

function filterArchivedLogs(logs) {
    const archivedIds = getArchivedLogIds();
    return (Array.isArray(logs) ? logs : []).filter(log => !archivedIds.has(getLogId(log)) && log.archived !== true);
}

function saveStoredLogs(totalOverride = null) {
    const sortedLogs = filterArchivedLogs(filterDeletedLogs([...allLogs])).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    allLogs = sortedLogs;
    const explicitTotal = Number(totalOverride);
    const nextTotal = totalOverride !== null && totalOverride !== undefined && Number.isFinite(explicitTotal)
        ? Math.max(0, explicitTotal)
        : Math.max(getStoredLogTotal(), sortedLogs.length);
    localStorage.setItem(LOG_TOTAL_COUNT_KEY, String(nextTotal));
    localStorage.setItem(LOG_STORAGE_KEY, JSON.stringify(sortedLogs.slice(0, MAX_STORED_LOGS)));
    window.dispatchEvent(new CustomEvent('microsoc:logs-updated', { detail: { logs: allLogs } }));
}

function getLogId(log) {
    return String(log?._id || log?.id || `${log?.timestamp || ''}-${log?.sourceIP || ''}-${log?.attackType || ''}`);
}

function isBackendLogId(id) {
    return /^[a-f0-9]{24}$/i.test(String(id || ''));
}

function getThreatContextForAttack(attackType) {
    const key = String(attackType || '').toLowerCase();
    const contexts = [
        {
            match: ['microsoft outlook exploit', 'outlook exploit', 'outlook elevation'],
            cves: ['CVE-2023-23397'],
            mitre: 'T1203 - Exploitation for Client Execution'
        },
        {
            match: ['apache struts exploit', 'struts exploit'],
            cves: ['CVE-2017-5638'],
            mitre: 'T1190 - Exploit Public-Facing Application'
        },
        {
            match: ['exchange server exploit', 'exchange exploit', 'proxylogon', 'proxyshell'],
            cves: ['CVE-2021-26855', 'CVE-2021-34473'],
            mitre: 'T1190 - Exploit Public-Facing Application'
        },
        {
            match: ['log4shell exploit', 'log4j exploit', 'log4shell'],
            cves: ['CVE-2021-44228'],
            mitre: 'T1190 - Exploit Public-Facing Application'
        },
        {
            match: ['sql injection', 'sqli'],
            cves: [],
            mitre: 'T1190 - Exploit Public-Facing Application'
        },
        {
            match: ['xss', 'cross-site scripting'],
            cves: [],
            mitre: 'T1190 - Exploit Public-Facing Application'
        },
        {
            match: ['password spraying', 'password spray'],
            cves: [],
            mitre: 'T1110.003 - Password Spraying'
        },
        {
            match: ['brute force', 'credential stuffing', 'credential'],
            cves: [],
            mitre: 'T1110 - Brute Force'
        },
        {
            match: ['ddos', 'dos'],
            cves: [],
            mitre: 'T1499 - Endpoint Denial of Service'
        },
        {
            match: ['port scan', 'scan'],
            cves: [],
            mitre: 'T1046 - Network Service Discovery'
        },
        {
            match: ['phishing', 'phish'],
            cves: [],
            mitre: 'T1566 - Phishing'
        },
        {
            match: ['malware'],
            cves: [],
            mitre: 'T1204 - User Execution'
        },
        {
            match: ['powershell abuse', 'powershell'],
            cves: [],
            mitre: 'T1059.001 - PowerShell'
        },
        {
            match: ['ransomware'],
            cves: [],
            mitre: 'T1486 - Data Encrypted for Impact'
        }
    ];
    return contexts.find(context => context.match.some(value => key.includes(value))) || {
        cves: [],
        mitre: 'T1190 - Exploit Public-Facing Application'
    };
}

function getRelatedCves(item) {
    const existing = item?.relatedCves || item?.cves || item?.evidence?.relatedCves || item?.metadata?.relatedCves;
    if (Array.isArray(existing) && existing.length) return existing;
    const context = getThreatContextForAttack(item?.attackType || item?.title || item?.description);
    return context.cves;
}

function renderCveChips(item) {
    return getRelatedCves(item)
        .map(cve => `<span class="badge badge-info">${escapeHtml(cve)}</span>`)
        .join('');
}

function normalizeLog(log) {
    const threatContext = getThreatContextForAttack(log.attackType || log.description);
    return {
        ...log,
        id: getLogId(log),
        timestamp: log.timestamp || log.createdAt || new Date().toISOString(),
        attackType: log.attackType || 'Other',
        sourceIP: log.sourceIP || '0.0.0.0',
        targetSystem: log.targetSystem || 'unknown',
        severity: log.severity || 'medium',
        country: log.country || 'Unknown',
        description: log.description || 'Security event detected',
        isBlocked: Boolean(log.isBlocked),
        userAgent: log.userAgent || 'Unknown',
        port: log.port || '-',
        protocol: log.protocol || 'Other',
        mitreTechnique: log.mitreTechnique || threatContext.mitre,
        metadata: log.metadata || {}
    };
}

function escapeJsString(value) {
    return String(value ?? '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function mergeLogs(...groups) {
    const merged = new Map();
    groups.flat().filter(Boolean).forEach(log => {
        const normalized = normalizeLog(log);
        merged.set(getLogId(normalized), { ...(merged.get(getLogId(normalized)) || {}), ...normalized });
    });
    return Array.from(merged.values()).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

function syncFilteredLogs() {
    filterLogs({ skipApi: true });
}

function getSelectedFilterValues(selectId) {
    const select = document.getElementById(selectId);
    if (!select) return [];

    const options = Array.from(select.options || []);
    const selected = Array.from(select.selectedOptions || []).map(option => option.value);

    // If every known option is selected, treat it as "All" so new/unknown values are not hidden.
    if (options.length > 0 && selected.length >= options.length) {
        return [];
    }

    return selected;
}

function clearDefaultMultiSelectFilters() {
    ['filter-severity', 'filter-type'].forEach((selectId) => {
        const select = document.getElementById(selectId);
        if (!select) return;
        Array.from(select.options || []).forEach(option => {
            option.selected = false;
        });
        select.selectedIndex = -1;
    });
}

// Initialize Logs
function initLogs() {
    const state = getLiveStreamState();
    isLiveStreaming = Boolean(state.active && state.owner === getLiveStreamTabId());
    stopLiveStreamTimers();
    pendingLiveLogs = [];

    allLogs = loadStoredLogs().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    filteredLogs = [...allLogs];
    
    // Setup multi-select styling
    setupMultiSelect();
    clearDefaultMultiSelectFilters();
    const timeFilter = document.getElementById('filter-time');
    if (timeFilter) {
        timeFilter.value = 'all';
    }

    updateLiveStreamControls();
    syncLiveStreamFromState();
    
    // Update stats
    updateLogStats();
    syncLogRoleUi();
    
    // Load logs for first page
    loadLogsForPage();
    refreshLogsFromApi();
}

// Generate Mock Logs
function generateMockLogs(count) {
    const attackTypes = ['XSS', 'SQL Injection', 'Port Scan', 'Brute Force', 'DDoS', 'Malware', 'Phishing', 'Insider Threat'];
    const severities = ['critical', 'high', 'medium', 'low'];
    const countries = ['USA', 'China', 'Russia', 'Germany', 'India', 'Brazil', 'Japan', 'South Korea', 'UK', 'France'];
    const targetSystems = ['web-server-01', 'db-server-01', 'auth-server-01', 'api-gateway', 'firewall-01', 'load-balancer-01'];
    
    const now = Date.now();
    const oneDay = 24 * 60 * 60 * 1000;
    
    for (let i = 0; i < count; i++) {
        const log = {
            id: i + 1,
            timestamp: new Date(now - Math.random() * 7 * oneDay).toISOString(),
            attackType: attackTypes[Math.floor(Math.random() * attackTypes.length)],
            sourceIP: generateIP(),
            targetSystem: targetSystems[Math.floor(Math.random() * targetSystems.length)],
            severity: severities[Math.floor(Math.random() * severities.length)],
            country: countries[Math.floor(Math.random() * countries.length)],
            description: generateLogDescription(),
            isBlocked: Math.random() > 0.3,
            userAgent: `Mozilla/5.0 (${['Windows', 'Linux', 'Mac OS'][Math.floor(Math.random() * 3)]})`,
            port: Math.floor(Math.random() * 65535),
            protocol: ['TCP', 'UDP', 'HTTP', 'HTTPS'][Math.floor(Math.random() * 4)]
        };
        
        allLogs.push(log);
    }
    
    // Sort by timestamp (newest first)
    allLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    filteredLogs = [...allLogs];
    saveStoredLogs();
}

// Generate Log Description
function generateLogDescription() {
    const actions = [
        'attempted to inject malicious script',
        'scanned for open ports',
        'tried SQL injection payload',
        'attempted brute force attack',
        'sent phishing email',
        'downloaded suspicious file',
        'accessed restricted resource',
        'modified system configuration',
        'attempted privilege escalation',
        'bypassed security controls'
    ];
    
    const targets = [
        'login form',
        'database server',
        'administrative panel',
        'API endpoint',
        'file upload system',
        'user session',
        'network firewall',
        'authentication system',
        'payment gateway',
        'web application'
    ];
    
    const action = actions[Math.floor(Math.random() * actions.length)];
    const target = targets[Math.floor(Math.random() * targets.length)];
    
    return `${action} on ${target}`;
}

// Load Logs for Current Page
function loadLogsForPage() {
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    currentLogs = filteredLogs.slice(startIndex, endIndex);
    
    renderLogs();
    updateLogStats();
    updatePagination();
    updateSelectedCount();
}

// Render Logs Table
function renderLogs() {
    const container = document.getElementById('logs-container');
    if (!container) return;
    syncSelectionColumnVisibility();
    
    if (!currentLogs.length) {
        container.innerHTML = `
            <tr>
                <td colspan="8" style="text-align: center; padding: 24px;">
                    No logs match the current filters. Start live stream to detect new attacks.
                </td>
            </tr>
        `;
    } else {
        container.innerHTML = currentLogs.map(log => {
        const logId = getLogId(log);
        const jsLogId = escapeJsString(logId);
        return `
        <tr class="log-row" data-id="${escapeHtml(logId)}">
            <td class="timestamp-cell">
                <div class="log-time">${formatDate(log.timestamp)}</div>
                <div class="log-date">${new Date(log.timestamp).toLocaleDateString()}</div>
            </td>
            <td>
                <div class="attack-type">
                    <i class="fas ${escapeHtml(getAttackTypeIcon(log.attackType))}"></i>
                    ${escapeHtml(log.attackType)}
                </div>
            </td>
            <td>
                <div class="source-ip">
                    <i class="fas fa-network-wired"></i>
                    ${escapeHtml(log.sourceIP)}
                </div>
            </td>
            <td>${escapeHtml(log.targetSystem)}</td>
            <td>
                <span class="badge severity-${log.severity}" 
                      style="background: ${getSeverityColor(log.severity)}">
                    <i class="fas ${log.severity === 'critical' ? 'fa-skull-crossbones' : 
                                    log.severity === 'high' ? 'fa-exclamation-circle' : 
                                    'fa-exclamation-triangle'}"></i>
                    ${escapeHtml(log.severity.toUpperCase())}
                </span>
            </td>
            <td>
                <div class="country-info">
                    <i class="fas fa-globe-americas"></i>
                    ${escapeHtml(log.country)}
                </div>
            </td>
            <td class="description-cell">
                ${escapeHtml(log.description)}
                ${log.isBlocked ? '<span class="badge badge-success">Blocked</span>' : ''}
            </td>
            <td>
                <div class="log-actions">
                    <button class="btn-icon" onclick="viewLogDetail('${jsLogId}')" title="View Details">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn-icon" onclick="showRemediation('${jsLogId}')" title="AI Prevention">
                        <i class="fas fa-lightbulb"></i>
                    </button>
                    <button class="btn-icon ai-action-btn" onclick="explainLogWithAI('${jsLogId}')" title="AI Explain">
                        <i class="fas fa-brain"></i>
                    </button>
                    ${canManageLogs() ? `<button class="btn-icon" onclick="createAlertFromLog('${jsLogId}')" title="Create Alert"><i class="fas fa-bell"></i></button>` : ''}
                    ${canManageLogs() ? `<button class="btn-icon" onclick="archiveLog('${jsLogId}')" title="Archive Log"><i class="fas fa-archive"></i></button>` : ''}
                </div>
            </td>
        </tr>
    `;
    }).join('');
    }
    
    // Update counts
    document.getElementById('showing-count').textContent = currentLogs.length;
    document.getElementById('total-count').textContent = filteredLogs.length;
}

// Update Log Statistics
function updateLogStats() {
    const statsLogs = allLogs.length ? allLogs : (filteredLogs.length ? filteredLogs : currentLogs);
    const totalLogs = Math.max(getStoredLogTotal(), statsLogs.length);
    const criticalLogs = statsLogs.filter(log => String(log.severity || '').toLowerCase() === 'critical').length;
    const blockedAttacks = statsLogs.filter(log => log.isBlocked).length;
    const uniqueSources = new Set(
        statsLogs.map(log => log.sourceIP).filter(Boolean)
    ).size;

    const setText = (id, value) => {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    };

    setText('total-logs', totalLogs);
    setText('critical-logs', criticalLogs);
    setText('blocked-attacks', blockedAttacks);
    setText('unique-sources', uniqueSources);
    setText('log-count', totalLogs);
    localStorage.setItem(LOG_TOTAL_COUNT_KEY, String(totalLogs));

    const updateCardMeta = (valueId, text, tone = 'neutral') => {
        const valueElement = document.getElementById(valueId);
        const meta = valueElement?.closest('.stat-info')?.querySelector('.stat-change');
        if (!meta) return;
        meta.classList.remove('positive', 'negative');
        if (tone !== 'neutral') meta.classList.add(tone);
        meta.innerHTML = text;
    };

    updateCardMeta('total-logs', '<i class="fas fa-database"></i> All-time logs', 'neutral');
    updateCardMeta('critical-logs', `<i class="fas fa-skull-crossbones"></i> ${criticalLogs} critical`, criticalLogs > 0 ? 'negative' : 'positive');
    updateCardMeta('blocked-attacks', `<i class="fas fa-shield-alt"></i> ${blockedAttacks} blocked`, blockedAttacks > 0 ? 'positive' : 'neutral');
    updateCardMeta('unique-sources', `<i class="fas fa-network-wired"></i> ${uniqueSources} sources`, uniqueSources > 0 ? 'negative' : 'neutral');
}

window.refreshLogStats = updateLogStats;

if (!window.__logStatsThemeRepairInstalled) {
    window.__logStatsThemeRepairInstalled = true;
    window.addEventListener('microsoc:theme-changed', () => {
        window.setTimeout(() => {
            if (document.getElementById('total-logs') && typeof updateLogStats === 'function') {
                updateLogStats();
            }
        }, 0);
    });
}

function buildLogApiQuery(options = {}) {
    const includeFilters = options.includeFilters !== false;
    const params = new URLSearchParams();
    params.set('page', '1');
    params.set('limit', String(LOG_SYNC_LIMIT));
    params.set('timeRange', includeFilters ? (document.getElementById('filter-time')?.value || 'all') : 'all');

    if (!includeFilters) {
        return params;
    }

    getSelectedFilterValues('filter-severity').forEach(value => params.append('severity', value));

    getSelectedFilterValues('filter-type').forEach(value => params.append('attackType', value));

    const sourceIP = document.getElementById('filter-ip')?.value?.trim();
    if (sourceIP) params.set('sourceIP', sourceIP);

    const search = document.getElementById('search-logs')?.value?.trim();
    if (search) params.set('search', search);

    return params;
}

async function refreshLogsFromApi() {
    const token = localStorage.getItem('token') || '';
    if (!token) return;

    try {
        const response = await fetch(`${getApiBaseUrl()}/logs?${buildLogApiQuery({ includeFilters: false }).toString()}`, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'Log history sync failed');
        }

        allLogs = filterDeletedLogs(mergeLogs(payload.logs || [], loadStoredLogs()));
        saveStoredLogs(payload.total);
        filterLogs({ skipApi: true });
    } catch (error) {
        console.warn('Log history sync failed:', error);
        if (!allLogs.length) {
            allLogs = loadStoredLogs().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            filterLogs({ skipApi: true });
        }
    }
}

function queueLogsApiRefresh() {
    clearTimeout(logsApiRefreshTimer);
    logsApiRefreshTimer = setTimeout(refreshLogsFromApi, 350);
}

async function persistLiveLogsToBackend(logs) {
    const token = localStorage.getItem('token') || '';
    if (!token || !Array.isArray(logs) || logs.length === 0) {
        return { logs: [], pipeline: null };
    }

    const response = await fetch(`${getApiBaseUrl()}/logs/bulk`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(logs.map(log => ({
            attackType: log.attackType,
            sourceIP: log.sourceIP,
            targetSystem: log.targetSystem,
            severity: log.severity,
            country: log.country,
            description: log.description,
            isBlocked: log.isBlocked,
            userAgent: log.userAgent,
            port: log.port,
            protocol: log.protocol,
            metadata: log.metadata || {},
            mitreTechnique: log.mitreTechnique || getThreatContextForAttack(log.attackType).mitre
        })))
    });

    const payload = await response.json();
    if (!response.ok || !payload.success) {
        throw new Error(payload.message || 'Failed to sync live logs');
    }

    return {
        logs: Array.isArray(payload.logs) ? payload.logs : [],
        pipeline: payload.pipeline || null
    };
}

async function deleteLogsFromBackend(ids) {
    const backendIds = ids.filter(isBackendLogId);
    if (!backendIds.length) {
        return { deletedCount: 0 };
    }

    const token = localStorage.getItem('token') || '';
    if (!token) {
        throw new Error('Login token missing. Please login again before deleting synced logs.');
    }

    const response = await fetch(`${getApiBaseUrl()}/logs`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ ids: backendIds })
    });
    const payload = await response.json().catch(() => ({}));

    if (!response.ok || !payload.success) {
        throw new Error(payload.message || 'Failed to delete logs from server');
    }

    return {
        deletedCount: Number(payload.deletedCount) || backendIds.length
    };
}

// Filter Logs
function filterLogs(options = {}) {
    const severityFilter = getSelectedFilterValues('filter-severity');
    const typeFilter = getSelectedFilterValues('filter-type');
    const ipFilter = document.getElementById('filter-ip')?.value.toLowerCase() || '';
    const timeFilter = document.getElementById('filter-time')?.value || 'all';
    
    const now = Date.now();
    let timeLimit = now;
    
    switch(timeFilter) {
        case '1h': timeLimit = now - (60 * 60 * 1000); break;
        case '24h': timeLimit = now - (24 * 60 * 60 * 1000); break;
        case '7d': timeLimit = now - (7 * 24 * 60 * 60 * 1000); break;
        case '30d': timeLimit = now - (30 * 24 * 60 * 60 * 1000); break;
        case 'all': timeLimit = 0; break;
    }
    
    filteredLogs = allLogs.filter(log => {
        if (log.archived === true) {
            return false;
        }

        // Filter by severity
        if (severityFilter.length > 0 && !severityFilter.includes(log.severity)) {
            return false;
        }
        
        // Filter by type
        if (typeFilter.length > 0 && !typeFilter.includes(log.attackType)) {
            return false;
        }
        
        // Filter by IP
        if (ipFilter && !log.sourceIP.toLowerCase().includes(ipFilter)) {
            return false;
        }

        const searchTerm = document.getElementById('search-logs').value.toLowerCase();
        if (searchTerm && ![
            log.description,
            log.sourceIP,
            log.targetSystem,
            log.attackType,
            log.country
        ].some(value => String(value || '').toLowerCase().includes(searchTerm))) {
            return false;
        }
        
        // Filter by time
        if (timeLimit > 0 && new Date(log.timestamp).getTime() < timeLimit) {
            return false;
        }
        
        return true;
    });
    
    // Reset to first page
    currentPage = 1;
    loadLogsForPage();
    if (!options.skipApi) {
        queueLogsApiRefresh();
    }
}

// Search Logs
function searchLogs() {
    filterLogs();
}

// Apply Filters (explicit)
function applyFilters() {
    filterLogs();
}

// Reset Filters
function resetFilters() {
    document.getElementById('filter-severity').selectedIndex = -1;
    document.getElementById('filter-type').selectedIndex = -1;
    document.getElementById('filter-ip').value = '';
    document.getElementById('filter-time').value = 'all';
    document.getElementById('search-logs').value = '';
    
    currentPage = 1;
    filterLogs();
}

// Pagination Functions
function updatePagination() {
    totalPages = Math.max(1, Math.ceil(filteredLogs.length / itemsPerPage));
    
    document.getElementById('current-page').textContent = currentPage;
    document.getElementById('total-pages').textContent = totalPages;
    
    document.getElementById('prev-btn').disabled = currentPage === 1;
    document.getElementById('next-btn').disabled = currentPage === totalPages;
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        loadLogsForPage();
    }
}

function nextPage() {
    if (currentPage < totalPages) {
        currentPage++;
        loadLogsForPage();
    }
}

function changeItemsPerPage() {
    itemsPerPage = parseInt(document.getElementById('items-per-page').value);
    currentPage = 1;
    loadLogsForPage();
}

// Live Stream Functions
async function startLiveStream(options = {}) {
    if (isLiveStreaming || isLiveStreamStarting) return;
    isLiveStreamStarting = true;
    const generation = liveStreamGeneration + 1;
    liveStreamGeneration = generation;
    updateLiveStreamControls();

    const claimed = claimLiveStreamOwnership();
    if (!claimed && !options.fromSync) {
        isLiveStreamStarting = false;
        showNotification('Live stream is already running in another tab.', 'warning', {
            title: 'Live Stream'
        });
        return;
    }

    liveStreamThresholdSettings = await getAlertThresholdSettings();
    if (generation !== liveStreamGeneration || !isLiveStreamStarting) return;
    liveAttackScenario = buildLiveAttackScenario(liveStreamThresholdSettings);
    
    isLiveStreaming = true;
    isLiveStreamStarting = false;
    updateLiveStreamControls();
    setLiveStreamState({
        active: true,
        owner: getLiveStreamTabId(),
        startedAt: getLiveStreamState().startedAt || new Date().toISOString(),
        lastSeenAt: new Date().toISOString()
    });
    
    liveStreamFirstTimer = setTimeout(() => {
        addNewLiveLog(generation);
    }, LIVE_STREAM_FIRST_DELAY_MS);

    liveStreamInterval = setInterval(() => {
        addNewLiveLog(generation);
    }, LIVE_STREAM_INTERVAL_MS);

    if (!options.fromSync) {
        showNotification('Live stream started. First event will appear in a moment.', 'info', {
            title: 'Live Stream'
        });
    }
}

function pauseLiveStream(options = {}) {
    if (!isLiveStreaming && !isLiveStreamStarting) return;
    
    liveStreamGeneration += 1;
    isLiveStreaming = false;
    isLiveStreamStarting = false;
    stopLiveStreamTimers();
    liveAttackScenario = null;
    pendingLiveLogs = [];
    updateLiveStreamControls();
    releaseLiveStreamOwnership();

    if (!options.fromSync) {
        showNotification('Live stream paused.', 'info', {
            title: 'Live Stream'
        });
    }
}

function updateLiveStreamControls() {
    const liveBtn = document.getElementById('live-btn');
    const pauseBtn = document.getElementById('pause-btn');

    if (liveBtn) {
        liveBtn.disabled = isLiveStreaming || isLiveStreamStarting;
        liveBtn.innerHTML = isLiveStreaming
            ? '<i class="fas fa-circle"></i> Live'
            : isLiveStreamStarting
                ? '<i class="fas fa-spinner fa-spin"></i> Starting'
            : '<i class="fas fa-play"></i> Start Live Stream';
    }

    if (pauseBtn) {
        pauseBtn.disabled = !isLiveStreaming && !isLiveStreamStarting;
    }
}

function stopLiveStreamTimers() {
    clearInterval(liveStreamInterval);
    clearTimeout(liveStreamFirstTimer);
    clearTimeout(liveRenderTimer);
    liveStreamInterval = null;
    liveStreamFirstTimer = null;
    liveRenderTimer = null;
}

window.addEventListener('storage', (event) => {
    if (event.key === LIVE_STREAM_STATE_KEY) {
        syncLiveStreamFromState();
    }
});

window.addEventListener('beforeunload', () => {
    if (isLiveStreaming) {
        const state = getLiveStreamState();
        if (state.owner === getLiveStreamTabId()) {
            setLiveStreamState({
                active: true,
                owner: state.owner,
                startedAt: state.startedAt,
                lastSeenAt: new Date().toISOString()
            });
        }
    }
});

function addNewLiveLog(generation = liveStreamGeneration) {
    if (!isLiveStreaming || generation !== liveStreamGeneration) return;

    const severities = ['critical', 'high', 'medium', 'low'];
    if (!liveAttackScenario || liveAttackScenario.remaining <= 0) {
        liveAttackScenario = buildLiveAttackScenario(liveStreamThresholdSettings || DEFAULT_LIVE_STREAM_SETTINGS);
    }

    const attackType = liveAttackScenario.attackType;
    const targetSystem = liveAttackScenario.targetSystem;
    const sequenceNumber = liveAttackScenario.total - liveAttackScenario.remaining + 1;
    const isEscalating = sequenceNumber >= Math.max(1, Number(liveStreamThresholdSettings?.createIncidentAfter) || DEFAULT_INCIDENT_THRESHOLD);
    
    const newLog = {
        id: `${Date.now()}-${sequenceNumber}`,
        timestamp: new Date().toISOString(),
        attackType,
        sourceIP: liveAttackScenario.sourceIP,
        targetSystem,
        severity: isEscalating
            ? (['SQL Injection', 'XSS', 'Malware', 'Ransomware', 'Log4Shell Exploit', 'Exchange Server Exploit'].includes(attackType) ? 'critical' : 'high')
            : severities[Math.floor(Math.random() * severities.length)],
        country: liveAttackScenario.country,
        description: buildLiveDescription(attackType, targetSystem),
        isBlocked: Math.random() > 0.5,
        userAgent: 'Live Stream',
        port: Math.floor(Math.random() * 65535),
        protocol: 'TCP',
        mitreTechnique: getThreatContextForAttack(attackType).mitre,
        metadata: {
            source: 'live-stream',
            scenarioId: `${liveAttackScenario.attackType}-${liveAttackScenario.sourceIP}-${liveAttackScenario.targetSystem}`,
            sequenceNumber,
            sequenceTotal: liveAttackScenario.total,
            incidentThreshold: liveStreamThresholdSettings?.createIncidentAfter || DEFAULT_INCIDENT_THRESHOLD
        }
    };

    liveAttackScenario.remaining -= 1;
    
    pendingLiveLogs.unshift(newLog);
    scheduleLiveLogFlush(generation);
}

function scheduleLiveLogFlush(generation = liveStreamGeneration) {
    clearTimeout(liveRenderTimer);
    liveRenderTimer = setTimeout(() => flushLiveLogs(generation), LIVE_RENDER_DEBOUNCE_MS);
}

async function getAlertThresholdSettings() {
    try {
        const response = await fetch(`${getApiBaseUrl()}/settings`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
            }
        });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.message || 'Settings unavailable');
        return {
            failedLoginThreshold: Math.max(1, Number(data.settings?.alertConfig?.failedLoginThreshold) || DEFAULT_ALERT_SETTINGS.failedLoginThreshold),
            otherAlertsThreshold: Math.max(1, Number(data.settings?.alertConfig?.otherAlertsThreshold) || DEFAULT_ALERT_SETTINGS.otherAlertsThreshold),
            createIncidentAfter: Math.max(1, Number(data.settings?.incidentConfig?.createIncidentAfter) || DEFAULT_INCIDENT_THRESHOLD)
        };
    } catch (error) {
        console.warn('Alert threshold fallback:', error);
        return { ...DEFAULT_LIVE_STREAM_SETTINGS };
    }
}

function getAlertThresholdForLog(log, settings) {
    const attackType = String(log?.attackType || '').toLowerCase();
    if (attackType.includes('brute force')) return settings.failedLoginThreshold;
    return settings.otherAlertsThreshold;
}

function getLiveAlertCorrelationKey(log) {
    const scope = getAlertCorrelationScope(log);
    return [
        String(log?.attackType || 'unknown').toLowerCase(),
        scope.field || 'scope',
        scope.value || 'any'
    ].join('|');
}

function buildLiveAttackScenario(settings = DEFAULT_LIVE_STREAM_SETTINGS) {
    const targetSystems = ['web-server-01', 'db-server-01', 'auth-server-01', 'api-gateway', 'firewall-01'];
    const countries = ['USA', 'China', 'Russia', 'Germany', 'India', 'Brazil'];
    const attackType = LIVE_ATTACK_SCENARIO_TYPES[liveAttackScenarioCursor % LIVE_ATTACK_SCENARIO_TYPES.length];
    liveAttackScenarioCursor += 1;
    const alertThreshold = getAlertThresholdForLog({ attackType }, settings);
    const burstTarget = Math.max(
        1,
        Number(settings.createIncidentAfter) || DEFAULT_INCIDENT_THRESHOLD,
        Number(alertThreshold) || 1
    );

    return {
        attackType,
        sourceIP: generateIP(),
        targetSystem: targetSystems[Math.floor(Math.random() * targetSystems.length)],
        country: countries[Math.floor(Math.random() * countries.length)],
        remaining: burstTarget,
        total: burstTarget
    };
}

function countSimilarLiveLogs(log) {
    const key = getLiveAlertCorrelationKey(log);
    return allLogs.filter(item => getLiveAlertCorrelationKey(item) === key).length;
}

async function maybePromoteLiveLogToAlert(logsToMerge) {
    // Backend threat analysis already creates alerts for live logs.
    // Keeping this hook as a no-op prevents duplicate alert creation from the UI.
    void logsToMerge;
    return null;
}

function showLiveLogNotification(log) {
    if (!log) return;
    const severity = String(log.severity || 'medium').toLowerCase();
    const notificationType = ['critical', 'high'].includes(severity) ? 'error' : 'warning';
    showNotification(`${severity.toUpperCase()} ${log.attackType || 'Attack'} from ${log.sourceIP || 'unknown source'}`, notificationType, {
        title: log.isBlocked ? 'Attack Detected and Blocked' : 'Active Attack Detected',
        meta: `${log.targetSystem || 'Unknown target'} | ${log.protocol || 'TCP'}/${log.port || '-'} | ${log.country || 'Unknown'}`
    });
}

function showLivePipelineNotifications(pipeline = {}) {
    const alerts = Array.isArray(pipeline.alerts) ? pipeline.alerts : [];
    const incidents = Array.isArray(pipeline.incidents) ? pipeline.incidents : [];
    const detectionCount = Number(pipeline.detections || 0);

    if (alerts.length) {
        alerts.forEach(alert => {
            const severity = String(alert.severity || 'medium').toLowerCase();
            showNotification(alert.title || `${severity.toUpperCase()} alert generated`, ['critical', 'high'].includes(severity) ? 'error' : 'warning', {
                title: 'Alert Generated',
                meta: `${alert.sourceIP || 'unknown source'} -> ${alert.targetSystem || 'unknown target'}`
            });
        });
        updateAlertCount(alerts.length);
    } else if (detectionCount > 0) {
        showNotification(`${detectionCount} alert${detectionCount === 1 ? '' : 's'} generated from live stream`, 'warning', {
            title: 'Alert Generated',
            meta: 'Threat pipeline matched live log activity'
        });
        updateAlertCount(detectionCount);
    }

    incidents.forEach(incident => {
        showNotification(incident.title || 'Live stream incident correlation updated', incident.created ? 'error' : 'warning', {
            title: incident.created ? 'Incident Created' : 'Incident Updated',
            meta: incident.incidentId ? `Incident ${incident.incidentId}` : 'Incident correlation'
        });
    });

    const createdIncidentCount = incidents.filter(incident => incident.created).length;
    if (createdIncidentCount > 0) {
        updateIncidentCount(createdIncidentCount);
    }
}

function flushLiveLogs(generation = liveStreamGeneration) {
    if (!isLiveStreaming || generation !== liveStreamGeneration || pendingLiveLogs.length === 0) return;

    const newLogs = pendingLiveLogs.splice(0);
    persistLiveLogsToBackend(newLogs)
        .then(async (syncResult) => {
            if (!isLiveStreaming || generation !== liveStreamGeneration) return;
            const savedLogs = Array.isArray(syncResult?.logs) ? syncResult.logs : [];
            const logsToMerge = savedLogs.length ? savedLogs : newLogs;
            const previousTotal = getStoredLogTotal();
            const previousLogIds = new Set(allLogs.map(getLogId));
            const newUniqueCount = logsToMerge.filter(log => !previousLogIds.has(getLogId(log))).length;
            allLogs = mergeLogs(logsToMerge, allLogs);
            saveStoredLogs(Math.max(previousTotal + newUniqueCount, allLogs.length));
            syncFilteredLogs();
            updateLogStats();

            logsToMerge.forEach(showLiveLogNotification);
            showLivePipelineNotifications(syncResult?.pipeline || {});
        })
        .catch((error) => {
            if (!isLiveStreaming || generation !== liveStreamGeneration) return;
            console.warn('Live log sync failed, keeping local copy only:', error);
            const previousTotal = getStoredLogTotal();
            const previousLogIds = new Set(allLogs.map(getLogId));
            const newUniqueCount = newLogs.filter(log => !previousLogIds.has(getLogId(log))).length;
            allLogs = mergeLogs(newLogs, allLogs);
            saveStoredLogs(Math.max(previousTotal + newUniqueCount, allLogs.length));
            syncFilteredLogs();
            updateLogStats();
            newLogs.forEach(showLiveLogNotification);
        });
}

function buildLiveDescription(attackType, targetSystem) {
    const descriptions = {
        'XSS': `Script injection payload detected against ${targetSystem}`,
        'SQL Injection': `SQL payload detected in request targeting ${targetSystem}`,
        'Port Scan': `Sequential port probe detected against ${targetSystem}`,
        'Brute Force': `Repeated authentication attempts detected on ${targetSystem}`,
        'DDoS': `Traffic burst consistent with DDoS detected against ${targetSystem}`,
        'Phishing': `Phishing lure and credential capture attempt detected against ${targetSystem}`,
        'Credential Stuffing': `Credential stuffing attempts detected against ${targetSystem}`,
        'Password Spraying': `Password spraying pattern detected against ${targetSystem}`,
        'Malware': `Malware execution signal detected on ${targetSystem}`,
        'PowerShell Abuse': `Suspicious PowerShell command execution detected on ${targetSystem}`,
        'Ransomware': `File encryption activity consistent with ransomware detected on ${targetSystem}`,
        'Microsoft Outlook Exploit': `Suspicious Outlook calendar invite exploit attempt detected against ${targetSystem}`,
        'Apache Struts Exploit': `Apache Struts OGNL payload exploit attempt detected against ${targetSystem}`,
        'Exchange Server Exploit': `Exchange Server exploitation pattern detected against ${targetSystem}`,
        'Log4Shell Exploit': `Log4Shell JNDI lookup exploit attempt detected against ${targetSystem}`
    };

    return descriptions[attackType] || `Suspicious activity detected against ${targetSystem}`;
}

// Log Selection Functions
function toggleLogSelection(logId) {
    selectedLogs.clear();
    updateSelectedCount();
}

function selectAllLogs() {
    selectedLogs.clear();
    syncSelectionColumnVisibility();
    updateSelectedCount();
}

function updateSelectedCount() {
    selectedLogs.clear();
    const bulkActions = document.getElementById('bulk-actions');
    const selectedCount = document.getElementById('selected-count');
    const selectedDeleteButton = document.getElementById('selected-delete-btn');
    
    if (selectedCount) {
        selectedCount.textContent = '0';
    }

    if (selectedDeleteButton) {
        selectedDeleteButton.remove();
    }
    
    if (!bulkActions) return;

    bulkActions.style.display = 'none';
}

function clearSelection() {
    selectedLogs.clear();
    const selectAll = document.getElementById('select-all');
    if (selectAll) {
        selectAll.checked = false;
    }
    document.querySelectorAll('.log-checkbox').forEach(cb => cb.checked = false);
    updateSelectedCount();
}

// View Log Details
function viewLogDetail(logId) {
    const log = allLogs.find(l => getLogId(l) === String(logId));
    if (!log) return;
    const jsLogId = escapeJsString(getLogId(log));
    
    const content = document.getElementById('log-detail-content');
    content.innerHTML = `
        <div class="log-detail-grid">
            <div class="log-detail-section">
                <h4>Basic Information</h4>
                <div class="log-detail-item">
                    <span class="log-detail-label">Log ID:</span>
                    ${escapeHtml(getLogId(log))}
                </div>
                <div class="log-detail-item">
                    <span class="log-detail-label">Timestamp:</span>
                    ${new Date(log.timestamp).toLocaleString()}
                </div>
                <div class="log-detail-item">
                    <span class="log-detail-label">Attack Type:</span>
                    <span class="badge" style="background: ${getSeverityColor(log.severity)}">
                        ${escapeHtml(log.attackType)}
                    </span>
                </div>
                <div class="log-detail-item">
                    <span class="log-detail-label">Severity:</span>
                    <span class="badge severity-${log.severity}" 
                          style="background: ${getSeverityColor(log.severity)}">
                        ${escapeHtml(log.severity.toUpperCase())}
                    </span>
                </div>
                <div class="log-detail-item">
                    <span class="log-detail-label">MITRE:</span>
                    ${escapeHtml(log.mitreTechnique || getThreatContextForAttack(log.attackType).mitre)}
                </div>
            </div>
            
            <div class="log-detail-section">
                <h4>Network Information</h4>
                <div class="log-detail-item">
                    <span class="log-detail-label">Source IP:</span>
                    ${escapeHtml(log.sourceIP)}
                </div>
                <div class="log-detail-item">
                    <span class="log-detail-label">Target System:</span>
                    ${escapeHtml(log.targetSystem)}
                </div>
                <div class="log-detail-item">
                    <span class="log-detail-label">Country:</span>
                    <i class="fas fa-globe-americas"></i> ${escapeHtml(log.country)}
                </div>
                <div class="log-detail-item">
                    <span class="log-detail-label">Port:</span>
                    ${escapeHtml(log.port)}
                </div>
                <div class="log-detail-item">
                    <span class="log-detail-label">Protocol:</span>
                    ${escapeHtml(log.protocol)}
                </div>
            </div>
            
            <div class="log-detail-section">
                <h4>Attack Details</h4>
                <div class="log-detail-item">
                    <span class="log-detail-label">Description:</span>
                    ${escapeHtml(log.description)}
                </div>
                <div class="log-detail-item">
                    <span class="log-detail-label">Status:</span>
                    ${log.isBlocked ? 
                        '<span class="badge badge-success">Blocked</span>' : 
                        '<span class="badge badge-danger">Active</span>'}
                </div>
                <div class="log-detail-item">
                    <span class="log-detail-label">User Agent:</span>
                    ${escapeHtml(log.userAgent)}
                </div>
            </div>
            
            <div class="log-detail-section">
                <h4>Actions</h4>
                <div style="display: flex; flex-direction: column; gap: 10px;">
                    ${canManageLogs() ? `<button class="btn btn-primary" onclick="createAlertFromLog('${jsLogId}'); closeLogModal()"><i class="fas fa-bell"></i> Create Alert</button>` : ''}
                    <button class="btn btn-outline" onclick="showRemediation('${jsLogId}')">
                        <i class="fas fa-lightbulb"></i> AI Prevention
                    </button>
                    ${canManageLogs() ? `<button class="btn btn-outline" onclick="exportSingleLog('${jsLogId}')">
                        <i class="fas fa-download"></i> Export Log
                    </button>` : ''}
                </div>
            </div>
        </div>
    `;
    
    document.getElementById('log-detail-modal').classList.remove('hidden');
}

// Close Log Modal
function closeLogModal() {
    document.getElementById('log-detail-modal').classList.add('hidden');
}

// Show Remediation Suggestions
async function showRemediation(logId) {
    const log = allLogs.find(l => String(l.id) === String(logId)) || allLogs.find(l => String(l._id) === String(logId));
    if (!log) return;

    const content = document.getElementById('remediation-content');
    content.innerHTML = `
        <h4>AI prevention analysis for ${escapeHtml(log.attackType)}</h4>
        <p><i class="fas fa-spinner fa-spin"></i> Asking MicroSOC AI how to prevent this attack...</p>
    `;
    document.getElementById('remediation-modal').classList.remove('hidden');

    try {
        const response = await fetch(`${getApiBaseUrl()}/ai/explain-log`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
            },
            body: JSON.stringify({ log })
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'AI remediation failed');
        }

        const result = payload.data || {};
        const actions = normalizeAIList(result.recommendedActions || result.actions);
        const containment = normalizeAIList(result.containment);
        const evidence = normalizeAIList(result.evidenceNeeded || result.evidence);
        const modeLabel = payload.mode === 'ai' ? 'Model assisted' : 'Local guidance';

        content.innerHTML = `
            <div class="ai-result-meta"><span class="ai-chip">${escapeHtml(modeLabel)}</span></div>
            <h4>${escapeHtml(result.title || `${log.attackType} prevention`)}</h4>
            <p>${escapeHtml(result.summary || result.likelyIntent || log.description)}</p>
            ${actions.length ? `<strong>Prevention actions</strong><ul class="remediation-list">${actions.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : ''}
            ${containment.length ? `<strong>Immediate containment</strong><ul class="remediation-list">${containment.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : ''}
            ${evidence.length ? `<strong>Evidence to review</strong><ul class="remediation-list">${evidence.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : ''}
            <div class="mt-20">
                <button class="btn btn-primary" onclick="closeRemediationModal()">
                    <i class="fas fa-check"></i> Understood
                </button>
            </div>
        `;
    } catch (error) {
        console.error('AI remediation failed:', error);
        content.innerHTML = `
            <h4>AI service unavailable</h4>
            <p>MicroSOC did not use local guidance. The AI provider failed to generate a response.</p>
            <p class="text-warning"><i class="fas fa-info-circle"></i> ${escapeHtml(error.message || 'Check backend AI provider configuration.')}</p>
            <div class="mt-20">
                <button class="btn btn-primary" onclick="showRemediation('${escapeHtml(log.id || log._id)}')">
                    <i class="fas fa-sync"></i> Retry AI
                </button>
                <button class="btn btn-outline" onclick="closeRemediationModal()">Close</button>
            </div>
        `;
    }
}

// Close Remediation Modal
function closeRemediationModal() {
    document.getElementById('remediation-modal').classList.add('hidden');
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function normalizeAIList(value) {
    if (Array.isArray(value)) {
        return value.flatMap(item => normalizeAIList(item)).filter(Boolean);
    }
    if (value && typeof value === 'object') {
        return Object.values(value).flatMap(item => normalizeAIList(item)).filter(Boolean);
    }
    if (typeof value === 'string') {
        return value
            .split(/\n|(?:^|\s)\d+\.\s+|[;•]/)
            .map(item => item.replace(/^[-*]\s*/, '').trim())
            .filter(Boolean);
    }
    if (value === null || value === undefined) return [];
    return [String(value)];
}

function ensureAIResultModal() {
    let modal = document.getElementById('ai-result-modal');
    if (modal) return modal;

    modal = document.createElement('div');
    modal.id = 'ai-result-modal';
    modal.className = 'modal hidden';
    modal.innerHTML = `
        <div class="modal-content modal-lg ai-result-panel">
            <div class="modal-header">
                <h3><i class="fas fa-brain"></i> MicroSOC AI Analysis</h3>
                <button class="close-modal" onclick="closeAIResultModal()">&times;</button>
            </div>
            <div class="modal-body" id="ai-result-content"></div>
            <div class="modal-footer">
                <button class="btn btn-outline" onclick="closeAIResultModal()">Close</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    return modal;
}

function showAIResult(title, result, mode = 'fallback') {
    const modal = ensureAIResultModal();
    const content = document.getElementById('ai-result-content');
    const recommendations = normalizeAIList(result.recommendedActions || result.actions);
    const containment = normalizeAIList(result.containment);
    const evidence = normalizeAIList(result.evidenceNeeded || result.evidence);
    const mitre = normalizeAIList(result.mitre || result.mitreMapping);

    content.innerHTML = `
        <div class="ai-result-meta">
            <span class="ai-chip">${escapeHtml(mode === 'ai' ? 'Model Assisted' : 'Local Fallback')}</span>
            ${result.risk ? `<span class="ai-chip danger">Risk ${escapeHtml(result.risk)}/100</span>` : ''}
        </div>
        <h4>${escapeHtml(title || result.title || 'AI Analysis')}</h4>
        <p class="ai-summary">${escapeHtml(result.summary || result.likelyIntent || 'Analysis generated successfully.')}</p>
        ${result.likelyIntent ? `<p><strong>Likely intent:</strong> ${escapeHtml(result.likelyIntent)}</p>` : ''}
        ${mitre.length ? `<div class="ai-section"><strong>MITRE:</strong><div>${mitre.map(item => `<span class="ai-chip">${escapeHtml(item)}</span>`).join('')}</div></div>` : ''}
        ${recommendations.length ? `<div class="ai-section"><strong>Recommended actions:</strong><ul>${recommendations.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul></div>` : ''}
        ${containment.length ? `<div class="ai-section"><strong>Containment:</strong><ul>${containment.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul></div>` : ''}
        ${evidence.length ? `<div class="ai-section"><strong>Evidence needed:</strong><ul>${evidence.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul></div>` : ''}
    `;

    modal.classList.remove('hidden');
}

function showAIResultLoading(title, message = 'AI is thinking through the evidence...') {
    const modal = ensureAIResultModal();
    const content = document.getElementById('ai-result-content');
    content.innerHTML = `
        <div class="ai-loading-state">
            <div class="ai-loading-orb"><i class="fas fa-brain"></i></div>
            <h4>${escapeHtml(title || 'AI Analysis')}</h4>
            <p>${escapeHtml(message)}</p>
            <div class="ai-loading-steps">
                <span>Reading log evidence</span>
                <span>Mapping threat behavior</span>
                <span>Drafting response plan</span>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
}

function showAIResultError(title, message) {
    const modal = ensureAIResultModal();
    const content = document.getElementById('ai-result-content');
    content.innerHTML = `
        <div class="ai-loading-state ai-error-state">
            <div class="ai-loading-orb"><i class="fas fa-triangle-exclamation"></i></div>
            <h4>${escapeHtml(title || 'AI Analysis Failed')}</h4>
            <p>${escapeHtml(message || 'AI provider could not complete this explanation right now.')}</p>
        </div>
    `;
    modal.classList.remove('hidden');
}

function closeAIResultModal() {
    document.getElementById('ai-result-modal')?.classList.add('hidden');
}

async function explainLogWithAI(logId) {
    const log = allLogs.find(l => getLogId(l) === String(logId));
    if (!log) return;

    showAIResultLoading(`Log #${getLogId(log)} AI Explanation`, 'AI is explaining this log...');
    showNotification('AI is explaining this log...', 'info');

    try {
        const response = await fetch(`${getApiBaseUrl()}/ai/explain-log`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ log })
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'AI analysis failed');
        }

        showAIResult(`Log #${getLogId(log)} AI Explanation`, payload.data, payload.mode);
    } catch (error) {
        console.error('AI log explanation failed:', error);
        showAIResultError(`Log #${getLogId(log)} AI Explanation`, error.message || 'AI provider could not explain this log right now.');
        showNotification(error.message || 'AI provider could not explain this log right now.', 'error');
    }
}

function getStoredIncidents() {
    try {
        return JSON.parse(localStorage.getItem('microsocLocalIncidents') || '[]');
    } catch (error) {
        return [];
    }
}

function storeLocalIncident(incident) {
    const incidents = getStoredIncidents();
    incidents.unshift(incident);
    localStorage.setItem('microsocLocalIncidents', JSON.stringify(incidents.slice(0, 50)));
}

function buildIncidentFromLog(log) {
    const relatedCves = getRelatedCves(log);
    const mitreTechnique = log.mitreTechnique || getThreatContextForAttack(log.attackType).mitre;
    const cveText = relatedCves.length ? `\nRelated CVEs: ${relatedCves.join(', ')}` : '';
    return {
        id: `local-${Date.now()}-${log.id}`,
        title: `Incident: ${log.attackType} from ${log.sourceIP}`,
        description: `${log.description}\n\nSource IP: ${log.sourceIP}\nTarget: ${log.targetSystem}\nProtocol: ${log.protocol}\nPort: ${log.port}\nBlocked: ${log.isBlocked ? 'Yes' : 'No'}\nMITRE: ${mitreTechnique}${cveText}`,
        severity: log.severity,
        status: 'open',
        assignedTo: null,
        createdAt: new Date().toISOString(),
        logs: [log.id],
        sourceIP: log.sourceIP,
        affectedSystems: [log.targetSystem],
        relatedCves,
        threatIntel: {
            mitreTechnique
        },
        tags: ['from-log', log.attackType.toLowerCase().replace(/\s+/g, '-')]
    };
}

async function persistIncident(incident) {
    const token = localStorage.getItem('token') || '';
    const payload = {
        title: incident.title,
        description: incident.description,
        severity: incident.severity,
        status: incident.status,
        sourceIP: incident.sourceIP && incident.sourceIP !== 'Multiple' ? incident.sourceIP : undefined,
        affectedSystems: incident.affectedSystems || [],
        relatedCves: incident.relatedCves || getRelatedCves(incident),
        threatIntel: incident.threatIntel || {
            mitreTechnique: incident.mitreTechnique || getThreatContextForAttack(incident.title || incident.description).mitre
        },
        tags: incident.tags || [],
        category: 'other',
        priority: incident.severity,
        impact: incident.severity
    };

    const response = await fetch(`${getApiBaseUrl()}/incidents`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(payload)
    });

    const data = await response.json();
    if (!response.ok || !data.success) {
        throw new Error(data.message || data.error || 'Incident save failed');
    }

    return data.incident;
}

function updateIncidentCount(delta = 1) {
    const incidentCount = document.getElementById('incident-count');
    if (incidentCount) {
        let count = parseInt(incidentCount.textContent) || 0;
        count += delta;
        incidentCount.textContent = count;
    }
}

function updateAlertCount(delta = 1) {
    const alertCount = document.getElementById('notification-count');
    if (alertCount) {
        let count = parseInt(alertCount.textContent) || 0;
        count += delta;
        alertCount.textContent = count;
    }
}

function buildAlertFromLog(log) {
    const logId = getLogId(log);
    const alert = {
        title: `Alert: ${log.attackType} from ${log.sourceIP}`,
        description: `${log.description}\n\nSource IP: ${log.sourceIP}\nTarget: ${log.targetSystem}\nProtocol: ${log.protocol}\nPort: ${log.port}\nBlocked: ${log.isBlocked ? 'Yes' : 'No'}`,
        severity: log.severity,
        status: 'new',
        sourceIP: log.sourceIP,
        targetSystem: log.targetSystem,
        attackType: log.attackType,
        mitreTechnique: log.mitreTechnique || getThreatContextForAttack(log.attackType).mitre,
        ruleId: 'manual_log_promotion',
        correlationKey: `manual-log-alert:${logId}`,
        evidence: {
            logId,
            timestamp: log.timestamp,
            country: log.country,
            protocol: log.protocol,
            port: log.port,
            isBlocked: log.isBlocked
        },
        metadata: {
            source: 'security-log-action',
            promotedFromLog: true,
            systemGenerated: false
        },
        tags: ['from-log', 'manual-alert', String(log.attackType || 'threat').toLowerCase().replace(/\s+/g, '-')]
    };

    const backendLogId = log._id || log.id;
    if (/^[a-f\d]{24}$/i.test(String(backendLogId || ''))) {
        alert.log = backendLogId;
    }

    return alert;
}

async function persistAlert(alert) {
    const token = localStorage.getItem('token') || '';
    const response = await fetch(`${getApiBaseUrl()}/alerts`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(alert)
    });

    const data = await response.json();
    if (!response.ok || !data.success) {
        throw new Error(data.message || data.error || 'Alert save failed');
    }

    return data;
}

function getAlertCorrelationKey(alert) {
    return [
        String(alert?.ruleId || 'manual-alert').toLowerCase(),
        String(alert?.attackType || 'other').toLowerCase()
    ].join('|');
}

function loadAlertCorrelationCache() {
    try {
        const cached = JSON.parse(localStorage.getItem(ALERT_CORRELATION_CACHE_KEY) || '[]');
        return Array.isArray(cached) ? cached : [];
    } catch (error) {
        return [];
    }
}

function saveAlertCorrelationCache(alerts) {
    localStorage.setItem(
        ALERT_CORRELATION_CACHE_KEY,
        JSON.stringify((Array.isArray(alerts) ? alerts : []).slice(-MAX_ALERT_CORRELATION_CACHE))
    );
}

function rememberAlertCorrelationCandidate(alert, savedAlert = {}) {
    const cache = loadAlertCorrelationCache();
    const normalized = {
        id: String(savedAlert._id || savedAlert.id || alert.correlationKey || `${Date.now()}-${Math.random()}`),
        title: savedAlert.title || alert.title,
        severity: savedAlert.severity || alert.severity,
        sourceIP: savedAlert.sourceIP || alert.sourceIP,
        targetSystem: savedAlert.targetSystem || alert.targetSystem,
        attackType: savedAlert.attackType || alert.attackType,
        ruleId: savedAlert.ruleId || alert.ruleId,
        log: savedAlert.log || alert.log,
        evidence: savedAlert.evidence || alert.evidence || {},
        createdAt: savedAlert.createdAt || new Date().toISOString()
    };
    const deduped = cache.filter(item => item.id !== normalized.id);
    deduped.push(normalized);
    saveAlertCorrelationCache(deduped);
    return normalized;
}

async function getIncidentThresholdSetting() {
    try {
        const response = await fetch(`${getApiBaseUrl()}/settings`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
            }
        });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.message || 'Settings unavailable');
        return Math.max(1, Number(data.settings?.incidentConfig?.createIncidentAfter) || DEFAULT_INCIDENT_THRESHOLD);
    } catch (error) {
        console.warn('Incident threshold fallback:', error);
        return DEFAULT_INCIDENT_THRESHOLD;
    }
}

function alertsAreSimilar(alert, candidate) {
    if (!candidate) return false;
    if (alert.ruleId && candidate.ruleId && alert.ruleId !== candidate.ruleId) return false;
    if (String(alert.attackType || '').toLowerCase() !== String(candidate.attackType || '').toLowerCase()) return false;
    const scope = getAlertCorrelationScope(alert);
    if (!scope.field || !scope.value) return true;
    return String(candidate[scope.field] || '').trim() === scope.value;
}

function getAlertCorrelationScope(alert = {}) {
    const attackType = String(alert.attackType || alert.title || '').toLowerCase();
    const targetSystem = String(alert.targetSystem || '').trim();
    const sourceIP = String(alert.sourceIP || '').trim();
    const targetScopedAttacks = [
        'sql injection',
        'xss',
        'cross-site scripting',
        'ddos',
        'microsoft outlook exploit',
        'outlook exploit',
        'apache struts exploit',
        'exchange server exploit',
        'log4shell exploit',
        'log4j exploit'
    ];
    const sourceScopedAttacks = ['brute force', 'port scan', 'credential stuffing', 'password spraying'];

    if (targetScopedAttacks.some(type => attackType.includes(type)) && targetSystem) {
        return {
            field: 'targetSystem',
            value: targetSystem,
            label: attackType.includes('xss') || attackType.includes('cross-site scripting') ? 'web application/endpoint'
                : attackType.includes('sql') ? 'API/endpoint'
                    : attackType.includes('outlook') ? 'mail server'
                        : attackType.includes('struts') ? 'web server'
                            : attackType.includes('exchange') ? 'Exchange server'
                                : 'target server/service'
        };
    }

    if (sourceScopedAttacks.some(type => attackType.includes(type)) && sourceIP) {
        return { field: 'sourceIP', value: sourceIP, label: 'source IP' };
    }

    if (targetSystem) return { field: 'targetSystem', value: targetSystem, label: 'target system' };
    if (sourceIP) return { field: 'sourceIP', value: sourceIP, label: 'source IP' };
    return { field: null, value: '', label: 'source or target' };
}

function normalizeIncidentSeverity(severity) {
    const value = String(severity || 'medium').toLowerCase();
    return ['critical', 'high', 'medium', 'low'].includes(value) ? value : 'medium';
}

function incidentCategoryFromAttack(attackType) {
    const value = String(attackType || '').toLowerCase();
    if (value.includes('malware') || value.includes('ransomware')) return 'malware';
    if (value.includes('phishing') || value.includes('credential')) return 'phishing';
    if (value.includes('ddos')) return 'ddos';
    if (value.includes('insider')) return 'insider_threat';
    if (value.includes('data') || value.includes('exfiltration')) return 'data_breach';
    if (value.includes('scan') || value.includes('injection') || value.includes('xss')) return 'vulnerability';
    return 'other';
}

async function createIncidentFromAlertFallback(alert, similarAlerts, threshold) {
    const sourceIPs = [...new Set(similarAlerts.map(item => item.sourceIP).filter(Boolean))];
    const affectedSystems = [...new Set(similarAlerts.map(item => item.targetSystem).filter(Boolean))];
    const relatedLogs = [...new Set(similarAlerts.map(item => item.log?._id || item.log || item.evidence?.logId).filter(id => /^[a-f\d]{24}$/i.test(String(id))))];
    const highestSeverity = similarAlerts.some(item => item.severity === 'critical')
        ? 'critical'
        : similarAlerts.some(item => item.severity === 'high')
            ? 'high'
            : normalizeIncidentSeverity(alert.severity);
    const singleSource = sourceIPs.length === 1 ? sourceIPs[0] : undefined;
    const relatedCves = [...new Set(similarAlerts.flatMap(getRelatedCves))];
    const cveLines = relatedCves.length ? [`Related CVEs: ${relatedCves.join(', ')}`] : [];
    const mitreTechnique = alert.mitreTechnique || getThreatContextForAttack(alert.attackType || alert.title).mitre;
    const scope = getAlertCorrelationScope(alert);
    const scopeText = scope.value ? `${scope.label} ${scope.value}` : 'matched source/target';
    const incident = {
        title: `Repeated ${alert.attackType || alert.ruleId || 'security'} alerts for ${scopeText}`,
        description: [
            `${similarAlerts.length} similar alerts reached the incident threshold (${threshold}).`,
            '',
            `Attack Type: ${alert.attackType || 'Unknown'}`,
            `Rule: ${alert.ruleId || 'N/A'}`,
            `Correlation: same ${scope.label}${scope.value ? ` (${scope.value})` : ''}`,
            `MITRE: ${mitreTechnique}`,
            ...cveLines,
            `Source IPs: ${sourceIPs.join(', ') || 'Unknown'}`,
            `Affected Systems: ${affectedSystems.join(', ') || 'Unknown'}`
        ].join('\n'),
        severity: highestSeverity,
        status: 'open',
        category: incidentCategoryFromAttack(alert.attackType),
        sourceIP: singleSource,
        affectedSystems,
        relatedCves,
        relatedLogs,
        threatIntel: {
            mitreTechnique
        },
        impact: highestSeverity,
        priority: highestSeverity,
        tags: ['auto-alert-correlation', 'frontend-fallback', String(alert.attackType || 'alert').toLowerCase().replace(/\s+/g, '-')]
    };

    const response = await fetch(`${getApiBaseUrl()}/incidents`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
        },
        body: JSON.stringify(incident)
    });
    const data = await response.json();
    if (!response.ok || !data.success) {
        throw new Error(data.message || 'Incident fallback creation failed');
    }
    return data.incident;
}

async function ensureIncidentForSimilarAlerts(alert, result = {}) {
    if (result.incident || result.incidentCreated) return result;

    const threshold = await getIncidentThresholdSetting();
    const localCandidate = rememberAlertCorrelationCandidate(alert, result.alert || {});
    let backendAlerts = [];

    try {
        const response = await fetch(`${getApiBaseUrl()}/alerts/recent?limit=500&timeRange=all`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
            },
            cache: 'no-store'
        });
        const data = await response.json();
        if (response.ok && data.success) {
            backendAlerts = data.alerts || [];
        }
    } catch (error) {
        console.warn('Backend alert correlation lookup failed, using local alert cache:', error);
    }

    const combinedAlerts = [...backendAlerts, ...loadAlertCorrelationCache(), localCandidate];
    const uniqueAlerts = Array.from(new Map(combinedAlerts.map(item => [
        String(item._id || item.id || item.correlationKey || `${item.createdAt}-${item.sourceIP}-${item.attackType}`),
        item
    ])).values());
    const similarAlerts = uniqueAlerts.filter(candidate => alertsAreSimilar(alert, candidate));

    if (similarAlerts.length < threshold) return result;

    const incident = await createIncidentFromAlertFallback(alert, similarAlerts, threshold);
    return {
        ...result,
        incident,
        incidentCreated: true,
        similarAlertCount: similarAlerts.length,
        incidentThreshold: threshold
    };
}

// Create Alert from Log
async function createAlertFromLog(logId, options = {}) {
    if (!canManageLogs()) {
        showNotification('Only admins can create alerts from logs.', 'warning');
        return;
    }
    const log = allLogs.find(l => getLogId(l) === String(logId));
    if (!log) return;

    const alert = buildAlertFromLog(log);
    if (options.systemGenerated) {
        alert.metadata = {
            ...(alert.metadata || {}),
            source: options.source || 'system-auto-threshold',
            systemGenerated: true
        };
        alert.tags = [...new Set([...(alert.tags || []), 'system-generated'])];
    }

    try {
        let result = await persistAlert(alert);
        try {
            result = await ensureIncidentForSimilarAlerts(alert, result);
        } catch (correlationError) {
            console.warn('Alert-to-incident correlation failed:', correlationError);
        }
        const savedAlert = result.alert;
        updateAlertCount(1);
        if (result.incident) {
            updateIncidentCount(result.incidentCreated ? 1 : 0);
        }
        if (!options.silent) {
            showNotification(options.message || `Alert ${savedAlert._id || savedAlert.id || ''} added to Alerts tab`, 'success', {
                title: options.title || 'Alert Created',
                meta: options.meta || `${log.attackType} | ${log.sourceIP}`
            });
            if (result.incident) {
                showNotification(`Incident auto-created: threshold ${result.incidentThreshold || DEFAULT_INCIDENT_THRESHOLD} reached`, 'success', {
                    title: result.incidentCreated ? 'Incident Auto-Created' : 'Incident Auto-Updated',
                    meta: result.incident?.title || `${log.attackType} | ${log.sourceIP}`
                });
            }
        }
    } catch (error) {
        console.error('Backend alert save failed:', error);
        if (!options.silent) {
            showNotification(error.message || 'Alert creation failed', 'error', {
                title: 'Alert Not Created',
                meta: `${log.attackType} | backend unavailable`
            });
        }
        throw error;
    }
}

// Backward-compatible alias for older inline handlers.
async function createIncidentFromLog(logId) {
    return createAlertFromLog(logId);
}

// Create Alert from Selected Logs
async function createAlertFromSelected() {
    if (!canManageLogs()) {
        showNotification('Only admins can create alerts from selected logs.', 'warning');
        return;
    }
    if (selectedLogs.size === 0) return;
    
    const selectedLogIds = Array.from(selectedLogs);
    const selectedLogData = allLogs.filter(log => selectedLogs.has(getLogId(log)));
    const highestSeverity = ['critical', 'high', 'medium', 'low'].find(level =>
        selectedLogData.some(log => log.severity === level)
    ) || 'medium';
    const alert = {
        title: `Bulk Alert: ${selectedLogIds.length} related logs`,
        description: `Created from ${selectedLogIds.length} selected security logs.\n\nSources: ${selectedLogData.map(log => log.sourceIP).join(', ')}`,
        severity: highestSeverity,
        status: 'new',
        sourceIP: selectedLogData.length === 1 ? selectedLogData[0].sourceIP : 'Multiple',
        targetSystem: selectedLogData.length === 1 ? selectedLogData[0].targetSystem : 'Multiple',
        attackType: selectedLogData.length === 1 ? selectedLogData[0].attackType : 'Multiple',
        ruleId: 'manual_bulk_log_promotion',
        correlationKey: `manual-bulk-log-alert:${Date.now()}`,
        evidence: {
            logIds: selectedLogIds,
            sourceIPs: [...new Set(selectedLogData.map(log => log.sourceIP))],
            targetSystems: [...new Set(selectedLogData.map(log => log.targetSystem))],
            attackTypes: [...new Set(selectedLogData.map(log => log.attackType))]
        },
        metadata: {
            source: 'security-log-bulk-action',
            promotedFromLogs: true,
            selectedCount: selectedLogIds.length
        },
        tags: ['from-logs', 'manual-alert', 'bulk']
    };

    try {
        let result = await persistAlert(alert);
        try {
            result = await ensureIncidentForSimilarAlerts(alert, result);
        } catch (correlationError) {
            console.warn('Bulk alert-to-incident correlation failed:', correlationError);
        }
        const savedAlert = result.alert;
        updateAlertCount(1);
        if (result.incidentCreated) updateIncidentCount(1);
        showNotification(`Bulk alert ${savedAlert._id || savedAlert.id || ''} added`, 'success', {
            title: 'Bulk Alert Created',
            meta: `${selectedLogIds.length} logs attached`
        });
        if (result.incident) {
            showNotification(`Incident auto-created: threshold ${result.incidentThreshold || DEFAULT_INCIDENT_THRESHOLD} reached`, 'success', {
                title: result.incidentCreated ? 'Incident Auto-Created' : 'Incident Auto-Updated',
                meta: result.incident?.title || 'Correlated alert incident'
            });
        }
    } catch (error) {
        console.error('Backend bulk alert save failed:', error);
        showNotification(error.message || 'Bulk alert creation failed', 'error', {
            title: 'Bulk Alert Not Created',
            meta: `${selectedLogIds.length} logs | backend unavailable`
        });
    }
    
    // Clear selection
    clearSelection();
}

// Backward-compatible alias for older inline handlers.
async function createIncidentFromSelected() {
    return createAlertFromSelected();
}

// Create Alert from Current Log (in modal)
function createIncidentFromCurrentLog() {
    const modal = document.getElementById('log-detail-modal');
    const logId = modal?.querySelector('.log-detail-item')?.textContent?.replace('Log ID:', '').trim();
    if (logId) createAlertFromLog(logId);
    closeLogModal();
}

// Export Functions
function exportLogs() {
    if (!canManageLogs()) {
        showNotification('Only admins can export logs from this screen.', 'warning');
        return;
    }
    const dataStr = JSON.stringify(filteredLogs, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `security-logs-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    showNotification('Logs exported successfully', 'success');
}

function exportSelectedLogs() {
    if (!canManageLogs()) {
        showNotification('Only admins can export selected logs.', 'warning');
        return;
    }
    if (selectedLogs.size === 0) {
        alert('No logs selected for export');
        return;
    }
    
    const selectedLogData = allLogs.filter(log => selectedLogs.has(getLogId(log)));
    const dataStr = JSON.stringify(selectedLogData, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `selected-logs-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    showNotification(`${selectedLogs.size} logs exported`, 'success');
    clearSelection();
}

function exportSingleLog(logId) {
    if (!canManageLogs()) {
        showNotification('Only admins can export logs.', 'warning');
        return;
    }
    const log = allLogs.find(l => getLogId(l) === String(logId));
    if (!log) return;
    
    const dataStr = JSON.stringify(log, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `log-${logId}-${new Date(log.timestamp).toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    showNotification('Log exported', 'success');
}

// Clear Logs
function clearLogs() {
    showNotification('Log deletion is disabled for audit integrity.', 'info');
}

// Delete Selected Logs
async function deleteSelectedLogs() {
    selectedLogs.clear();
    syncSelectionColumnVisibility();
    updateSelectedCount();
    showNotification('Log deletion is disabled for audit integrity.', 'info');
}

async function archiveLog(logId) {
    if (!canManageLogs()) {
        showNotification('Only admins can archive logs.', 'error');
        return;
    }

    const log = allLogs.find(item => getLogId(item) === String(logId));
    if (!log) return;
    if (!confirm('Archive this log from the active Security Logs view?')) return;

    const id = getLogId(log);
    try {
        if (isBackendLogId(id)) {
            const token = localStorage.getItem('token') || '';
            const response = await fetch(`${getApiBaseUrl()}/logs/${id}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ archived: true })
            });
            const payload = await response.json();
            if (!response.ok || !payload.success) {
                throw new Error(payload.message || 'Could not archive log');
            }
        }

        rememberArchivedLog(log);
        allLogs = allLogs.filter(item => getLogId(item) !== id);
        filteredLogs = filteredLogs.filter(item => getLogId(item) !== id);
        saveStoredLogs();
        loadLogsForPage();
        updateLogStats();
        showNotification('Log archived', 'success');
    } catch (error) {
        console.error('Archive log failed:', error);
        showNotification(error.message || 'Could not archive log.', 'error');
    }
}

// Setup Multi-Select
function setupMultiSelect() {
    // Add styles for multi-select
    const style = document.createElement('style');
    style.textContent = `
        select[multiple] {
            min-height: 100px;
        }
        
        select[multiple] option {
            padding: 8px 12px;
            margin: 2px 0;
            border-radius: 4px;
            cursor: pointer;
        }
        
        select[multiple] option:hover {
            background: rgba(34, 211, 238, 0.14) !important;
            color: var(--text-primary) !important;
        }
        
        select[multiple] option:checked {
            background: rgba(34, 211, 238, 0.18) !important;
            color: var(--text-primary) !important;
            font-weight: 600;
        }
    `;
    document.head.appendChild(style);
}

// Show Notification
function showNotification(message, type = 'info', options = {}) {
    const containerId = 'toast-stack';
    let stack = document.getElementById(containerId);
    if (!stack) {
        stack = document.createElement('div');
        stack.id = containerId;
        stack.className = 'toast-stack';
        document.body.appendChild(stack);
    }

    const notification = document.createElement('div');
    notification.className = `custom-notification notification-${type}`;

    const icons = {
        success: 'fa-check-circle',
        error: 'fa-shield-virus',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };
    const icon = icons[type] || icons.info;
    
    notification.innerHTML = `
        <div class="toast-icon"><i class="fas ${icon}"></i></div>
        <div class="toast-copy">
            <strong>${escapeHtml(options.title || (type === 'error' ? 'Security Alert' : 'MicroSOC'))}</strong>
            <span>${escapeHtml(message)}</span>
            ${options.meta ? `<small>${escapeHtml(options.meta)}</small>` : ''}
        </div>
        <button class="toast-close" onclick="this.closest('.custom-notification').remove()" aria-label="Close notification">
            &times;
        </button>
    `;
    
    stack.appendChild(notification);
    
    setTimeout(() => {
        if (notification.parentElement) {
            notification.classList.add('leaving');
            notification.remove();
        }
    }, 5200);
}

// Export functions
window.initLogs = initLogs;
window.filterLogs = filterLogs;
window.searchLogs = searchLogs;
window.applyFilters = applyFilters;
window.resetFilters = resetFilters;
window.prevPage = prevPage;
window.nextPage = nextPage;
window.changeItemsPerPage = changeItemsPerPage;
window.startLiveStream = startLiveStream;
window.pauseLiveStream = pauseLiveStream;
window.toggleLogSelection = toggleLogSelection;
window.selectAllLogs = selectAllLogs;
window.clearSelection = clearSelection;
window.viewLogDetail = viewLogDetail;
window.closeLogModal = closeLogModal;
window.showRemediation = showRemediation;
window.closeRemediationModal = closeRemediationModal;
window.explainLogWithAI = explainLogWithAI;
window.closeAIResultModal = closeAIResultModal;
window.createAlertFromLog = createAlertFromLog;
window.createIncidentFromLog = createIncidentFromLog;
window.createAlertFromSelected = createAlertFromSelected;
window.createIncidentFromSelected = createIncidentFromSelected;
window.createIncidentFromCurrentLog = createIncidentFromCurrentLog;
window.exportLogs = exportLogs;
window.exportSelectedLogs = exportSelectedLogs;
window.clearLogs = clearLogs;
window.deleteSelectedLogs = deleteSelectedLogs;
window.archiveLog = archiveLog;
