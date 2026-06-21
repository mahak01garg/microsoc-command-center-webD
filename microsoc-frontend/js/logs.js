// Logs Page JavaScript

let allLogs = [];
let filteredLogs = [];
let currentLogs = [];
let selectedLogs = new Set();
let isLiveStreaming = false;
let liveStreamInterval = null;
let liveStreamFirstTimer = null;
let liveRenderTimer = null;
let pendingLiveLogs = [];
let lastLiveNotificationAt = 0;
let currentPage = 1;
let itemsPerPage = 25;
let totalPages = 1;
const LOG_STORAGE_KEY = 'microsocSecurityLogs';
const MAX_STORED_LOGS = 1000;
const LIVE_STREAM_INTERVAL_MS = 3000;
const LIVE_STREAM_FIRST_DELAY_MS = 1200;
const LIVE_RENDER_DEBOUNCE_MS = 250;
const LIVE_NOTIFICATION_MIN_GAP_MS = 9000;
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

function getApiBaseUrl() {
    return window.MICROSOC_API_BASE_URL || 'https://microsoc-backend.onrender.com/api';
}

function loadStoredLogs() {
    try {
        const stored = JSON.parse(localStorage.getItem(LOG_STORAGE_KEY) || '[]');
        return Array.isArray(stored) ? stored : [];
    } catch (error) {
        return [];
    }
}

function saveStoredLogs() {
    const sortedLogs = [...allLogs].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    allLogs = sortedLogs;
    localStorage.setItem(LOG_STORAGE_KEY, JSON.stringify(sortedLogs.slice(0, MAX_STORED_LOGS)));
    window.dispatchEvent(new CustomEvent('microsoc:logs-updated', { detail: { logs: allLogs } }));
}

function getLogId(log) {
    return String(log?._id || log?.id || `${log?.timestamp || ''}-${log?.sourceIP || ''}-${log?.attackType || ''}`);
}

function normalizeLog(log) {
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
        protocol: log.protocol || 'Other'
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

// Initialize Logs
function initLogs() {
    isLiveStreaming = false;
    stopLiveStreamTimers();
    pendingLiveLogs = [];

    allLogs = loadStoredLogs().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    filteredLogs = [...allLogs];
    
    // Setup multi-select styling
    setupMultiSelect();
    document.querySelectorAll('#filter-severity option, #filter-type option').forEach(option => {
        option.selected = true;
    });

    updateLiveStreamControls();
    
    // Update stats
    updateLogStats();
    
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
    updatePagination();
    updateSelectedCount();
}

// Render Logs Table
function renderLogs() {
    const container = document.getElementById('logs-container');
    if (!container) return;
    
    if (!currentLogs.length) {
        container.innerHTML = `
            <tr>
                <td colspan="9" style="text-align: center; padding: 24px;">
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
            <td>
                <input type="checkbox" class="log-checkbox" 
                       onchange="toggleLogSelection('${jsLogId}')" 
                       ${selectedLogs.has(logId) ? 'checked' : ''}>
            </td>
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
                    <button class="btn-icon" onclick="createIncidentFromLog('${jsLogId}')" title="Create Incident">
                        <i class="fas fa-exclamation-triangle"></i>
                    </button>
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
    const now = Date.now();
    const oneDay = 24 * 60 * 60 * 1000;
    
    const logsToday = allLogs.filter(log => 
        (now - new Date(log.timestamp)) < oneDay
    ).length;
    
    const criticalLogs = allLogs.filter(log => 
        log.severity === 'critical' && (now - new Date(log.timestamp)) < oneDay
    ).length;
    
    const blockedAttacks = allLogs.filter(log => 
        log.isBlocked && (now - new Date(log.timestamp)) < oneDay
    ).length;
    
    const uniqueSources = new Set(
        allLogs.filter(log => (now - new Date(log.timestamp)) < oneDay)
               .map(log => log.sourceIP)
    ).size;
    
    document.getElementById('total-logs').textContent = logsToday;
    document.getElementById('critical-logs').textContent = criticalLogs;
    document.getElementById('blocked-attacks').textContent = blockedAttacks;
    document.getElementById('unique-sources').textContent = uniqueSources;
    document.getElementById('log-count').textContent = allLogs.length;
}

function buildLogApiQuery() {
    const params = new URLSearchParams();
    params.set('page', '1');
    params.set('limit', '5000');
    params.set('timeRange', document.getElementById('filter-time')?.value || '24h');

    Array.from(document.getElementById('filter-severity')?.selectedOptions || [])
        .map(option => option.value)
        .forEach(value => params.append('severity', value));

    Array.from(document.getElementById('filter-type')?.selectedOptions || [])
        .map(option => option.value)
        .forEach(value => params.append('attackType', value));

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
        const response = await fetch(`${getApiBaseUrl()}/logs?${buildLogApiQuery().toString()}`, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'Log history sync failed');
        }

        allLogs = mergeLogs(payload.logs || [], loadStoredLogs());
        saveStoredLogs();
        filterLogs({ skipApi: true });
    } catch (error) {
        console.warn('Log history sync failed:', error);
    }
}

function queueLogsApiRefresh() {
    clearTimeout(logsApiRefreshTimer);
    logsApiRefreshTimer = setTimeout(refreshLogsFromApi, 350);
}

// Filter Logs
function filterLogs(options = {}) {
    const severityFilter = Array.from(document.getElementById('filter-severity').selectedOptions)
        .map(option => option.value);
    
    const typeFilter = Array.from(document.getElementById('filter-type').selectedOptions)
        .map(option => option.value);
    
    const ipFilter = document.getElementById('filter-ip').value.toLowerCase();
    const timeFilter = document.getElementById('filter-time').value;
    
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
    document.getElementById('filter-time').value = '24h';
    document.getElementById('search-logs').value = '';
    
    document.querySelectorAll('#filter-severity option, #filter-type option').forEach(option => {
        option.selected = true;
    });
    
    filteredLogs = [...allLogs];
    currentPage = 1;
    loadLogsForPage();
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
function startLiveStream() {
    if (isLiveStreaming) return;
    
    isLiveStreaming = true;
    updateLiveStreamControls();
    
    liveStreamFirstTimer = setTimeout(() => {
        addNewLiveLog();
    }, LIVE_STREAM_FIRST_DELAY_MS);

    liveStreamInterval = setInterval(() => {
        addNewLiveLog();
    }, LIVE_STREAM_INTERVAL_MS);

    showNotification('Live stream started. First event will appear in a moment.', 'info', {
        title: 'Live Stream'
    });
}

function pauseLiveStream() {
    if (!isLiveStreaming) return;
    
    isLiveStreaming = false;
    stopLiveStreamTimers();
    pendingLiveLogs = [];
    updateLiveStreamControls();

    showNotification('Live stream paused.', 'info', {
        title: 'Live Stream'
    });
}

function updateLiveStreamControls() {
    const liveBtn = document.getElementById('live-btn');
    const pauseBtn = document.getElementById('pause-btn');

    if (liveBtn) {
        liveBtn.disabled = isLiveStreaming;
        liveBtn.innerHTML = isLiveStreaming
            ? '<i class="fas fa-circle"></i> Live'
            : '<i class="fas fa-play"></i> Start Live Stream';
    }

    if (pauseBtn) {
        pauseBtn.disabled = !isLiveStreaming;
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

function addNewLiveLog() {
    if (!isLiveStreaming) return;

    const attackTypes = ['XSS', 'SQL Injection', 'Port Scan', 'Brute Force', 'DDoS'];
    const severities = ['critical', 'high', 'medium', 'low'];
    const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
    const targetSystem = ['web-server-01', 'db-server-01', 'auth-server-01', 'api-gateway', 'firewall-01'][Math.floor(Math.random() * 5)];
    
    const newLog = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        attackType,
        sourceIP: generateIP(),
        targetSystem,
        severity: severities[Math.floor(Math.random() * severities.length)],
        country: ['USA', 'China', 'Russia', 'Germany', 'India', 'Brazil'][Math.floor(Math.random() * 6)],
        description: buildLiveDescription(attackType, targetSystem),
        isBlocked: Math.random() > 0.5,
        userAgent: 'Live Stream',
        port: Math.floor(Math.random() * 65535),
        protocol: 'TCP'
    };
    
    pendingLiveLogs.unshift(newLog);
    scheduleLiveLogFlush();
}

function scheduleLiveLogFlush() {
    clearTimeout(liveRenderTimer);
    liveRenderTimer = setTimeout(flushLiveLogs, LIVE_RENDER_DEBOUNCE_MS);
}

function flushLiveLogs() {
    if (!isLiveStreaming || pendingLiveLogs.length === 0) return;

    const newLogs = pendingLiveLogs.splice(0);
    allLogs = mergeLogs(newLogs, allLogs);
    saveStoredLogs();
    syncFilteredLogs();
    
    updateLogStats();

    const notableLog = newLogs.find(log => ['critical', 'high'].includes(log.severity)) || newLogs[0];
    const now = Date.now();
    if (notableLog && now - lastLiveNotificationAt > LIVE_NOTIFICATION_MIN_GAP_MS) {
        lastLiveNotificationAt = now;
        const notificationType = ['critical', 'high'].includes(notableLog.severity) ? 'error' : 'warning';
        showNotification(`${notableLog.severity.toUpperCase()} ${notableLog.attackType} from ${notableLog.sourceIP}`, notificationType, {
            title: notableLog.isBlocked ? 'Attack Detected and Blocked' : 'Active Attack Detected',
            meta: `${notableLog.targetSystem} | ${notableLog.protocol}/${notableLog.port} | ${notableLog.country}`
        });
    }
}

function buildLiveDescription(attackType, targetSystem) {
    const descriptions = {
        'XSS': `Script injection payload detected against ${targetSystem}`,
        'SQL Injection': `SQL payload detected in request targeting ${targetSystem}`,
        'Port Scan': `Sequential port probe detected against ${targetSystem}`,
        'Brute Force': `Repeated authentication attempts detected on ${targetSystem}`,
        'DDoS': `Traffic burst consistent with DDoS detected against ${targetSystem}`
    };

    return descriptions[attackType] || `Suspicious activity detected against ${targetSystem}`;
}

// Log Selection Functions
function toggleLogSelection(logId) {
    const id = String(logId);
    if (selectedLogs.has(id)) {
        selectedLogs.delete(id);
    } else {
        selectedLogs.add(id);
    }
    
    updateSelectedCount();
}

function selectAllLogs() {
    const selectAll = document.getElementById('select-all').checked;
    const checkboxes = document.querySelectorAll('.log-checkbox');
    
    if (selectAll) {
        currentLogs.forEach(log => selectedLogs.add(getLogId(log)));
        checkboxes.forEach(cb => cb.checked = true);
    } else {
        currentLogs.forEach(log => selectedLogs.delete(getLogId(log)));
        checkboxes.forEach(cb => cb.checked = false);
    }
    
    updateSelectedCount();
}

function updateSelectedCount() {
    const count = selectedLogs.size;
    const bulkActions = document.getElementById('bulk-actions');
    const selectedCount = document.getElementById('selected-count');
    
    selectedCount.textContent = count;
    
    if (count > 0) {
        bulkActions.style.display = 'block';
    } else {
        bulkActions.style.display = 'none';
    }
}

function clearSelection() {
    selectedLogs.clear();
    document.getElementById('select-all').checked = false;
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
                    <button class="btn btn-primary" onclick="createIncidentFromLog('${jsLogId}'); closeLogModal()">
                        <i class="fas fa-exclamation-triangle"></i> Create Incident
                    </button>
                    <button class="btn btn-outline" onclick="showRemediation('${jsLogId}')">
                        <i class="fas fa-lightbulb"></i> AI Prevention
                    </button>
                    <button class="btn btn-outline" onclick="exportSingleLog('${jsLogId}')">
                        <i class="fas fa-download"></i> Export Log
                    </button>
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

function closeAIResultModal() {
    document.getElementById('ai-result-modal')?.classList.add('hidden');
}

async function explainLogWithAI(logId) {
    const log = allLogs.find(l => getLogId(l) === String(logId));
    if (!log) return;

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
    return {
        id: `local-${Date.now()}-${log.id}`,
        title: `Incident: ${log.attackType} from ${log.sourceIP}`,
        description: `${log.description}\n\nSource IP: ${log.sourceIP}\nTarget: ${log.targetSystem}\nProtocol: ${log.protocol}\nPort: ${log.port}\nBlocked: ${log.isBlocked ? 'Yes' : 'No'}`,
        severity: log.severity,
        status: 'open',
        assignedTo: null,
        createdAt: new Date().toISOString(),
        logs: [log.id],
        sourceIP: log.sourceIP,
        affectedSystems: [log.targetSystem],
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

// Create Incident from Log
async function createIncidentFromLog(logId) {
    const log = allLogs.find(l => getLogId(l) === String(logId));
    if (!log) return;

    const incident = buildIncidentFromLog(log);

    try {
        const savedIncident = await persistIncident(incident);
        updateIncidentCount(1);
        showNotification(`Incident ${savedIncident._id || savedIncident.id || ''} added to Incidents tab`, 'success', {
            title: 'Incident Created',
            meta: `${log.attackType} | ${log.sourceIP}`
        });
    } catch (error) {
        console.error('Backend incident save failed, saving locally:', error);
        storeLocalIncident(incident);
        updateIncidentCount(1);
        showNotification('Incident saved locally and will show in Incidents tab', 'warning', {
            title: 'Incident Added Locally',
            meta: `${log.attackType} | backend unavailable`
        });
    }
}

// Create Incident from Selected Logs
async function createIncidentFromSelected() {
    if (selectedLogs.size === 0) return;
    
    const selectedLogIds = Array.from(selectedLogs);
    const selectedLogData = allLogs.filter(log => selectedLogs.has(getLogId(log)));
    const highestSeverity = ['critical', 'high', 'medium', 'low'].find(level =>
        selectedLogData.some(log => log.severity === level)
    ) || 'medium';

    const incident = {
        id: `local-${Date.now()}-bulk`,
        title: `Bulk Incident: ${selectedLogIds.length} related logs`,
        description: `Created from ${selectedLogIds.length} selected security logs.\n\nSources: ${selectedLogData.map(log => log.sourceIP).join(', ')}`,
        severity: highestSeverity,
        status: 'open',
        assignedTo: null,
        createdAt: new Date().toISOString(),
        logs: selectedLogIds,
        sourceIP: 'Multiple',
        affectedSystems: [...new Set(selectedLogData.map(log => log.targetSystem))],
        tags: ['bulk-from-logs']
    };

    try {
        const savedIncident = await persistIncident(incident);
        updateIncidentCount(1);
        showNotification(`Bulk incident ${savedIncident._id || savedIncident.id || ''} added`, 'success', {
            title: 'Bulk Incident Created',
            meta: `${selectedLogIds.length} logs attached`
        });
    } catch (error) {
        console.error('Backend bulk incident save failed, saving locally:', error);
        storeLocalIncident(incident);
        updateIncidentCount(1);
        showNotification('Bulk incident saved locally and will show in Incidents tab', 'warning', {
            title: 'Bulk Incident Added Locally',
            meta: `${selectedLogIds.length} logs attached`
        });
    }
    
    // Clear selection
    clearSelection();
}

// Create Incident from Current Log (in modal)
function createIncidentFromCurrentLog() {
    const modal = document.getElementById('log-detail-modal');
    const logId = modal?.querySelector('.log-detail-item')?.textContent?.replace('Log ID:', '').trim();
    if (logId) createIncidentFromLog(logId);
    closeLogModal();
}

// Export Functions
function exportLogs() {
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
    if (!canManageLogs()) {
        showNotification('Only admins can clear logs.', 'error');
        return;
    }

    if (confirm('Are you sure you want to clear all logs? This action cannot be undone.')) {
        allLogs = [];
        filteredLogs = [];
        selectedLogs.clear();
        currentPage = 1;
        saveStoredLogs();
        loadLogsForPage();
        updateLogStats();
        
        showNotification('Logs cleared', 'info');
    }
}

// Delete Selected Logs
function deleteSelectedLogs() {
    if (!canManageLogs()) {
        showNotification('Only admins can delete logs.', 'error');
        return;
    }

    if (selectedLogs.size === 0) {
        alert('No logs selected for deletion');
        return;
    }
    
    if (confirm(`Are you sure you want to delete ${selectedLogs.size} selected logs?`)) {
        // Remove selected logs
        allLogs = allLogs.filter(log => !selectedLogs.has(getLogId(log)));
        filteredLogs = filteredLogs.filter(log => !selectedLogs.has(getLogId(log)));
        const deletedCount = selectedLogs.size;
        saveStoredLogs();
        
        // Clear selection
        clearSelection();
        
        // Reload
        loadLogsForPage();
        updateLogStats();
        
        showNotification(`${deletedCount} logs deleted`, 'success');
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
            background: var(--primary-color) !important;
            color: white !important;
        }
        
        select[multiple] option:checked {
            background: var(--primary-color) !important;
            color: white !important;
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
window.createIncidentFromLog = createIncidentFromLog;
window.createIncidentFromSelected = createIncidentFromSelected;
window.createIncidentFromCurrentLog = createIncidentFromCurrentLog;
window.exportLogs = exportLogs;
window.exportSelectedLogs = exportSelectedLogs;
window.clearLogs = clearLogs;
window.deleteSelectedLogs = deleteSelectedLogs;
