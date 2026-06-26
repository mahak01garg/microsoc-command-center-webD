// Incidents Page JavaScript

let incidents = [];
let assignableUsersCache = [];
const ARCHIVED_INCIDENTS_KEY = 'microsocArchivedIncidentIds';

function getApiBaseUrl() {
    return window.MICROSOC_API_BASE_URL || 'http://localhost:5001/api';
}

function getAuthHeaders() {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
    };
}

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

function getStoredLocalIncidents() {
    try {
        const saved = JSON.parse(localStorage.getItem('microsocLocalIncidents') || '[]');
        return Array.isArray(saved) ? saved : [];
    } catch (error) {
        return [];
    }
}

function getArchivedIncidentIds() {
    try {
        const ids = JSON.parse(localStorage.getItem(ARCHIVED_INCIDENTS_KEY) || '[]');
        return new Set(Array.isArray(ids) ? ids.map(String) : []);
    } catch (error) {
        return new Set();
    }
}

function rememberArchivedIncidentId(id) {
    const archivedIds = getArchivedIncidentIds();
    archivedIds.add(String(id));
    localStorage.setItem(ARCHIVED_INCIDENTS_KEY, JSON.stringify(Array.from(archivedIds).slice(-1000)));
}

function filterArchivedIncidents(list) {
    const archivedIds = getArchivedIncidentIds();
    return (Array.isArray(list) ? list : []).filter(incident => !archivedIds.has(String(incident.id || incident._id)) && incident.archived !== true);
}

function getThreatContextForIncident(incident = {}) {
    const key = [incident.attackType, incident.title, incident.description].filter(Boolean).join(' ').toLowerCase();
    const contexts = [
        { match: ['microsoft outlook exploit', 'outlook exploit', 'outlook elevation'], cves: ['CVE-2023-23397'], mitre: 'T1203 - Exploitation for Client Execution' },
        { match: ['apache struts exploit', 'struts exploit'], cves: ['CVE-2017-5638'], mitre: 'T1190 - Exploit Public-Facing Application' },
        { match: ['exchange server exploit', 'exchange exploit', 'proxylogon', 'proxyshell'], cves: ['CVE-2021-26855', 'CVE-2021-34473'], mitre: 'T1190 - Exploit Public-Facing Application' },
        { match: ['log4shell exploit', 'log4j exploit', 'log4shell'], cves: ['CVE-2021-44228'], mitre: 'T1190 - Exploit Public-Facing Application' },
        { match: ['sql injection', 'sqli'], cves: [], mitre: 'T1190 - Exploit Public-Facing Application' },
        { match: ['xss', 'cross-site scripting'], cves: [], mitre: 'T1190 - Exploit Public-Facing Application' },
        { match: ['password spraying', 'password spray'], cves: [], mitre: 'T1110.003 - Password Spraying' },
        { match: ['brute force', 'credential stuffing', 'credential'], cves: [], mitre: 'T1110 - Brute Force' },
        { match: ['ddos', 'dos'], cves: [], mitre: 'T1499 - Endpoint Denial of Service' },
        { match: ['port scan', 'scan'], cves: [], mitre: 'T1046 - Network Service Discovery' },
        { match: ['phishing', 'phish'], cves: [], mitre: 'T1566 - Phishing' },
        { match: ['malware'], cves: [], mitre: 'T1204 - User Execution' },
        { match: ['powershell abuse', 'powershell'], cves: [], mitre: 'T1059.001 - PowerShell' },
        { match: ['ransomware'], cves: [], mitre: 'T1486 - Data Encrypted for Impact' }
    ];
    return contexts.find(context => context.match.some(value => key.includes(value))) || {
        cves: [],
        mitre: 'T1190 - Exploit Public-Facing Application'
    };
}

function getRelatedCves(incident = {}) {
    const existing = incident.relatedCves || incident.cves || incident.evidence?.relatedCves || incident.metadata?.relatedCves;
    if (Array.isArray(existing) && existing.length) return existing;

    const descriptionMatch = String(incident.description || '').match(/Related CVEs:\s*([^\n]+)/i);
    if (descriptionMatch) {
        return descriptionMatch[1].split(',').map(value => value.trim()).filter(Boolean);
    }

    return getThreatContextForIncident(incident).cves;
}

function getIncidentMitre(incident = {}) {
    const descriptionMatch = String(incident.description || '').match(/MITRE:\s*([^\n]+)/i);
    const candidates = [
        incident.mitreTechnique,
        incident.threatIntel?.mitreTechnique,
        incident.evidence?.mitreTechnique,
        incident.metadata?.mitreTechnique,
        descriptionMatch?.[1]?.trim()
    ];
    const stored = candidates.find(value => {
        const text = String(value || '').trim();
        return text && !/^unknown$/i.test(text) && !/^mitre unknown$/i.test(text);
    });
    return stored
        || getThreatContextForIncident(incident).mitre
        || 'T1190 - Exploit Public-Facing Application';
}

function renderCveBadges(incident = {}) {
    return getRelatedCves(incident)
        .map(cve => `<span class="badge badge-info">${escapeHtml(cve)}</span>`)
        .join('');
}

function syncIncidentRoleUi() {
    const createButton = document.querySelector('.main-header .btn.btn-primary[onclick*="openNewIncidentModal"]');
    if (createButton) {
        createButton.style.display = isAdminUser() ? '' : 'none';
    }

    const headerTitle = document.querySelector('.main-header .header-left h1');
    const headerSubtitle = document.querySelector('.main-header .header-left .subtitle');
    if (headerTitle) {
        headerTitle.innerHTML = isAdminUser()
            ? '<i class="fas fa-exclamation-triangle"></i> Incident Management'
            : '<i class="fas fa-user-shield"></i> My Incidents';
    }
    if (headerSubtitle) {
        headerSubtitle.textContent = isAdminUser()
            ? 'Monitor and manage security incidents'
            : 'Only assigned incidents can be updated from this view';
    }
}

async function loadAssignableUsers() {
    if (assignableUsersCache.length) {
        return assignableUsersCache;
    }

    const res = await fetch(`${getApiBaseUrl()}/users`, {
        headers: getAuthHeaders()
    });
    const data = await res.json();

    if (!res.ok) {
        throw new Error(data.message || 'Failed to load users');
    }

    assignableUsersCache = (data.users || [])
        .filter(user => user && user.role !== 'viewer' && user.isActive !== false && user.approvalStatus === 'approved')
        .sort((a, b) => {
            if (a.role !== b.role) {
                return a.role === 'admin' ? -1 : 1;
            }
            return String(a.name || a.email || '').localeCompare(String(b.name || b.email || ''));
        });

    return assignableUsersCache;
}

function ensureAssignIncidentModal() {
    let modal = document.getElementById('assign-incident-modal');
    if (modal) return modal;

    modal = document.createElement('div');
    modal.id = 'assign-incident-modal';
    modal.className = 'modal hidden';
    modal.innerHTML = `
        <div class="modal-content modal-lg">
            <div class="modal-header">
                <h3><i class="fas fa-user-plus"></i> Assign Incident</h3>
                <button class="close-modal" onclick="closeAssignIncidentModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div id="assign-incident-summary" class="timeline-incident-summary" style="margin-bottom:16px;"></div>
                <div class="form-group">
                    <label for="assign-incident-user">Assign to</label>
                    <select id="assign-incident-user">
                        <option value="">Loading users...</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="assign-incident-note">Note</label>
                    <textarea id="assign-incident-note" rows="4" placeholder="Optional note for assignment timeline"></textarea>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-outline" onclick="closeAssignIncidentModal()">Cancel</button>
                <button class="btn btn-primary" onclick="submitIncidentAssignment()">
                    <i class="fas fa-user-check"></i> Save Assignment
                </button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    return modal;
}

function renderAssignIncidentSummary(incident) {
    const summary = document.getElementById('assign-incident-summary');
    if (!summary) return;

    summary.innerHTML = `
        <h4>${escapeHtml(incident.title || 'Incident')}</h4>
        <p>${escapeHtml(incident.description || 'No description')}</p>
        <div class="timeline-incident-meta">
            <span class="badge badge-danger">${escapeHtml((incident.severity || 'medium').toUpperCase())}</span>
            <span class="status-badge status-${escapeHtml(incident.status || 'open')}">${escapeHtml((incident.status || 'open').replace('_', ' ').toUpperCase())}</span>
            <span>Current assignee: ${escapeHtml(incident.assignedToLabel || incident.assignedTo || 'Unassigned')}</span>
        </div>
    `;
}

async function openAssignIncidentModal(id) {
    if (!isAdminUser()) {
        showNotification('Only admins can assign incidents.', 'warning');
        return;
    }

    const incident = incidents.find(i => String(i.id) === String(id));
    if (!incident) {
        showNotification('Incident not found.', 'error');
        return;
    }

    if (String(incident.id).startsWith('local-')) {
        showNotification('Local incidents can only be viewed until they are synced with the backend.', 'warning');
        return;
    }

    const modal = ensureAssignIncidentModal();
    modal.dataset.incidentId = String(incident.id);
    renderAssignIncidentSummary(incident);

    const userSelect = document.getElementById('assign-incident-user');
    const noteField = document.getElementById('assign-incident-note');
    if (userSelect) {
        userSelect.innerHTML = '<option value="">Unassigned</option>';
        userSelect.disabled = true;
        userSelect.insertAdjacentHTML('beforeend', '<option value="">Loading users...</option>');
    }
    if (noteField) {
        noteField.value = '';
    }

    try {
        const users = await loadAssignableUsers();
        if (userSelect) {
            userSelect.innerHTML = '<option value="">Unassigned</option>';
            if (users.length) {
                    users.forEach((user) => {
                        const option = document.createElement('option');
                        option.value = user.id || user._id;
                        option.textContent = `${user.name || user.email} (${String(user.role || '').toUpperCase()})`;
                        if (
                            String(incident.assignedToId || '') === String(user.id || user._id) ||
                            String(incident.assignedToLabel || '').toLowerCase().includes(String(user.email || user.name || '').toLowerCase())
                        ) {
                            option.selected = true;
                        }
                        userSelect.appendChild(option);
                    });
            } else {
                userSelect.insertAdjacentHTML('beforeend', '<option value="" disabled>No active approved users found</option>');
            }
            userSelect.disabled = false;
        }
    } catch (error) {
        console.error('Failed to load assignable users:', error);
        if (userSelect) {
            userSelect.innerHTML = '<option value="">Unassigned</option><option value="" disabled>Unable to load users</option>';
            userSelect.disabled = false;
        }
        showNotification(error.message || 'Failed to load users', 'error');
    }

    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
}

function closeAssignIncidentModal() {
    const modal = document.getElementById('assign-incident-modal');
    if (modal) {
        delete modal.dataset.incidentId;
        modal.classList.add('hidden');
    }
    document.body.style.overflow = '';
}

async function submitIncidentAssignment() {
    const modal = document.getElementById('assign-incident-modal');
    const incidentId = modal?.dataset?.incidentId;
    if (!incidentId) return;

    const userSelect = document.getElementById('assign-incident-user');
    const noteField = document.getElementById('assign-incident-note');
    const userId = userSelect?.value || '';
    const note = noteField?.value?.trim() || '';

    try {
        const response = await fetch(`${getApiBaseUrl()}/incidents/${incidentId}/assign`, {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({
                userId: userId || null,
                note: note || undefined
            })
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'Incident assignment failed');
        }

        closeAssignIncidentModal();
        await loadIncidents();
        showNotification('Incident assignment saved successfully.', 'success');
    } catch (error) {
        console.error('Assign incident failed:', error);
        showNotification(error.message || 'Incident assignment failed', 'error');
    }
}

// Load Incidents
async function loadIncidents() {
    try {
        const query = '?limit=50';
        const res = await fetch(`${getApiBaseUrl()}/incidents${query}`, {
            headers: getAuthHeaders()
        });

        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.message || 'Failed to load incidents');
        }

        const backendIncidents = Array.isArray(data.incidents) ? data.incidents.map(normalizeIncident) : [];
        const localIncidents = getStoredLocalIncidents().map(normalizeIncident);
        const mergedIncidents = [...backendIncidents];
        const seenIds = new Set(backendIncidents.map(incident => String(incident.id)));

        localIncidents.forEach((incident) => {
            const key = String(incident.id);
            if (!seenIds.has(key)) {
                seenIds.add(key);
                mergedIncidents.push(incident);
            }
        });

        incidents = filterArchivedIncidents(mergedIncidents).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        syncIncidentRoleUi();
        renderInciments(incidents);
        renderIncidentStats(data.stats, incidents);
    } catch (err) {
        console.error("Failed to load incidents", err);
        incidents = filterArchivedIncidents(getStoredLocalIncidents().map(normalizeIncident));
        syncIncidentRoleUi();
        if (incidents.length) {
            renderInciments(incidents);
            renderIncidentStats(null, incidents);
        } else {
            renderIncidentError(err.message || 'No live incident data available.');
            renderIncidentStats();
        }
    }
}

function normalizeIncident(incident) {
    const assignedTo = incident.assignedTo && typeof incident.assignedTo === 'object'
        ? incident.assignedTo.name || incident.assignedTo.email
        : incident.assignedTo;
    const relatedCves = getRelatedCves(incident);

    return {
        ...incident,
        id: incident.id || incident._id,
        assignedToId: incident.assignedTo && typeof incident.assignedTo === 'object'
            ? (incident.assignedTo.id || incident.assignedTo._id || '')
            : (incident.assignedToId || ''),
        assignedToLabel: incident.assignedTo && typeof incident.assignedTo === 'object'
            ? `${incident.assignedTo.name || ''}${incident.assignedTo.name && incident.assignedTo.email ? ' · ' : ''}${incident.assignedTo.email || ''}`.trim() || incident.assignedTo.name || incident.assignedTo.email
            : (incident.assignedToLabel || assignedTo),
        assignedTo,
        logs: Array.isArray(incident.logs)
            ? incident.logs.length
            : Array.isArray(incident.relatedLogs)
                ? incident.relatedLogs.length
                : incident.logs || 0,
        createdAt: incident.createdAt || incident.updatedAt || new Date().toISOString(),
        sourceIP: incident.sourceIP || 'N/A',
        relatedCves,
        mitreTechnique: getIncidentMitre(incident)
    };
}

function renderIncidentError(message) {
    const tbody = document.querySelector('#incidents-table tbody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="7">${escapeHtml(message)}</td></tr>`;
}

function renderIncidentStats(stats, incidentList = incidents) {
    const grid = document.querySelector('.main-content .stats-grid');
    if (!grid) return;

    const statusCounts = Object.fromEntries((stats?.statusCounts || []).map(item => [item._id, item.count]));
    const severityCounts = Object.fromEntries((stats?.severityCounts || []).map(item => [item._id, item.count]));
    const localStatusCounts = incidentList.reduce((acc, incident) => {
        acc[incident.status] = (acc[incident.status] || 0) + 1;
        return acc;
    }, {});
    const localSeverityCounts = incidentList.reduce((acc, incident) => {
        acc[incident.severity] = (acc[incident.severity] || 0) + 1;
        return acc;
    }, {});
    const open = statusCounts.open || localStatusCounts.open || 0;
    const inProgress = statusCounts.in_progress || localStatusCounts.in_progress || 0;
    const resolved = statusCounts.resolved || localStatusCounts.resolved || 0;
    const critical = severityCounts.critical || localSeverityCounts.critical || 0;

    const cards = [
        { icon: 'fa-exclamation-circle', title: 'Open Incidents', value: open, color: '#dc3545' },
        { icon: 'fa-skull-crossbones', title: 'Critical', value: critical, color: '#fd7e14' },
        { icon: 'fa-user-clock', title: 'In Progress', value: inProgress, color: '#007bff' },
        { icon: 'fa-check-circle', title: 'Resolved', value: resolved, color: '#28a745' }
    ];

    grid.innerHTML = cards.map(card => `
        <div class="stat-card">
            <div class="stat-icon" style="background: ${card.color}20; color: ${card.color}">
                <i class="fas ${card.icon}"></i>
            </div>
            <div class="stat-info">
                <h3>${card.title}</h3>
                <div class="stat-value">${card.value}</div>
                <div class="stat-change positive">
                    <i class="fas fa-database"></i> Live
                </div>
            </div>
        </div>
    `).join('');

    document.querySelectorAll('.sidebar-nav .badge-danger').forEach(badge => {
        badge.textContent = open + inProgress;
    });
}


// Render Incidents Table
function renderInciments(filteredIncidents = incidents) {
    const tbody = document.querySelector('#incidents-table tbody');
    if (!tbody) return;
    const admin = isAdminUser();

    if (!filteredIncidents.length) {
        tbody.innerHTML = '<tr><td colspan="7">No incidents found.</td></tr>';
        return;
    }
    
    tbody.innerHTML = filteredIncidents.map(incident => `
        ${(() => {
            const isLocal = String(incident.id).startsWith('local-');
            const disabledAttr = isLocal ? 'disabled title="Local incident - read only until backend syncs"' : '';
            const localBadge = isLocal ? '<span class="badge badge-warning" style="margin-left:8px;">LOCAL</span>' : '';
            const cveBadges = renderCveBadges(incident);
            const cveRow = cveBadges ? `
                <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:6px;">
                    <span style="font-size:11px;color:var(--text-secondary);">Related CVEs:</span>
                    ${cveBadges}
                </div>
            ` : '';
            const mitre = getIncidentMitre(incident);
            return `
        <tr data-id="${incident.id}">
            <td class="incident-id-cell">#${incident.id}</td>
            <td>
                <strong>${incident.title}</strong>${localBadge}
                <div class="incident-description">${incident.description}</div>
                <div style="font-size:11px;color:var(--text-secondary);margin-top:6px;">
                    MITRE: <strong>${escapeHtml(mitre)}</strong>
                </div>
                ${cveRow}
            </td>
            <td>
                <span class="badge" style="background: ${getSeverityColor(incident.severity)}">
                    ${incident.severity.toUpperCase()}
                </span>
            </td>
            <td>
                <span class="status-badge status-${incident.status}">
                    ${incident.status.replace('_', ' ').toUpperCase()}
                </span>
            </td>
            <td>${incident.assignedTo || 'Unassigned'}</td>
            <td>${formatDate(incident.createdAt)}</td>
            <td>
                <button class="btn btn-sm btn-outline" onclick="viewIncident('${incident.id}')" ${disabledAttr}>
                    <i class="fas fa-eye"></i>
                </button>
                <button class="btn btn-sm btn-outline" onclick="viewIncidentTimeline('${incident.id}')" ${disabledAttr} title="View full timeline">
                    <i class="fas fa-stream"></i>
                </button>
                <button class="btn btn-sm btn-outline ai-action-btn" onclick="triageIncidentWithAI('${incident.id}')" ${disabledAttr} title="AI Triage">
                    <i class="fas fa-brain"></i>
                </button>
                ${admin ? `<button class="btn btn-sm btn-outline" onclick="openAssignIncidentModal('${incident.id}')" ${disabledAttr} title="Assign incident"><i class="fas fa-user-plus"></i></button>` : ''}
                ${admin ? `<button class="btn btn-sm btn-outline" onclick="editIncident('${incident.id}')" ${disabledAttr}><i class="fas fa-edit"></i></button>` : `<button class="btn btn-sm btn-outline" onclick="editIncident('${incident.id}')" ${disabledAttr} title="Update Status"><i class="fas fa-pen"></i></button>`}
                ${admin ? `<button class="btn btn-sm btn-outline" onclick="archiveIncident('${incident.id}')" ${disabledAttr} title="Archive incident"><i class="fas fa-archive"></i></button>` : ''}
            </td>
        </tr>
            `;
        })()}
    `).join('');
}

// Filter Incidents
function filterIncidents() {
    const statusFilter = document.getElementById('filter-status').value;
    const severityFilter = document.getElementById('filter-severity').value;
    
    let filtered = incidents;
    
    if (statusFilter !== 'all') {
        filtered = filtered.filter(incident => incident.status === statusFilter);
    }
    
    if (severityFilter !== 'all') {
        filtered = filtered.filter(incident => incident.severity === severityFilter);
    }
    
    renderInciments(filtered);
}

// Search Incidents
function searchIncidents() {
    const searchTerm = document.getElementById('search-incidents').value.toLowerCase();
    
    if (!searchTerm) {
        renderInciments(incidents);
        return;
    }
    
    const filtered = incidents.filter(incident => 
        incident.title.toLowerCase().includes(searchTerm) ||
        incident.description.toLowerCase().includes(searchTerm) ||
        (incident.assignedTo && incident.assignedTo.toLowerCase().includes(searchTerm))
    );
    
    renderInciments(filtered);
}

// Open New Incident Modal
function openNewIncidentModal() {
    if (!isAdminUser()) {
        showNotification('Only admins can create incidents from this screen.', 'warning');
        return;
    }
    const modal = document.getElementById('new-incident-modal');
    if (!modal) return;
    const assigneeSelect = document.getElementById('incident-assignee');
    if (assigneeSelect) {
        const assigneeGroup = assigneeSelect.closest('.form-group') || assigneeSelect.parentElement;
        if (!isAdminUser()) {
            assigneeSelect.value = '';
            if (assigneeGroup) assigneeGroup.style.display = 'none';
        } else if (assigneeGroup) {
            assigneeGroup.style.display = '';
        }
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        const userId = user.id || user._id;
        assigneeSelect.innerHTML = '<option value="">Unassigned</option>';
        if (userId) {
            const option = document.createElement('option');
            option.value = userId;
            option.textContent = user.name || user.email || 'Me';
            assigneeSelect.appendChild(option);
        }
    }
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    setTimeout(() => document.getElementById('incident-title')?.focus(), 50);
}

// Close Modal
function closeModal() {
    const modal = document.getElementById('new-incident-modal');
    const form = document.getElementById('new-incident-form');
    if (modal) modal.classList.add('hidden');
    if (form) form.reset();
    document.body.style.overflow = '';
}

// Create New Incident
async function createNewIncident() {
    if (!isAdminUser()) {
        alert('Only admins can create incidents.');
        return;
    }
    const title = document.getElementById('incident-title').value;
    const description = document.getElementById('incident-description').value;
    const severity = document.getElementById('incident-severity').value;
    const assignee = document.getElementById('incident-assignee').value;
    const relatedCves = getRelatedCves({ title, description });
    const mitreTechnique = getIncidentMitre({ title, description });
    const cveText = relatedCves.length ? `\n\nRelated CVEs: ${relatedCves.join(', ')}` : '';
    const incidentPayload = {
        title,
        description: `${description}\n\nMITRE: ${mitreTechnique}${cveText}`,
        severity,
        status: 'open',
        category: 'other',
        priority: severity,
        impact: severity,
        relatedCves,
        threatIntel: {
            mitreTechnique
        }
    };

    if (isAdminUser() && /^[a-f\d]{24}$/i.test(assignee)) {
        incidentPayload.assignedTo = assignee;
    }

    if (!title.trim() || !description.trim()) {
        alert('Please enter a title and description.');
        return;
    }

    try {
        const response = await fetch(`${getApiBaseUrl()}/incidents`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify(incidentPayload)
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || payload.error || 'Incident creation failed');
        }
        closeModal();
        await loadIncidents();
        alert('Incident created successfully!');
    } catch (error) {
        console.error('Create incident failed:', error);
        alert(error.message || 'Incident creation failed');
    }
}

// View Incident Details
function viewIncident(id) {
    const incident = incidents.find(i => String(i.id) === String(id));
    if (!incident) return;
    const relatedCves = getRelatedCves(incident);
    const cveText = relatedCves.length ? `\n        Related CVEs: ${relatedCves.join(', ')}` : '';
    const mitreTechnique = getIncidentMitre(incident);
    
    const details = `
        Incident #${incident.id}: ${incident.title}
        
        Description: ${incident.description}
        
        Severity: ${incident.severity.toUpperCase()}
        Status: ${incident.status.toUpperCase()}
        Assigned To: ${incident.assignedToLabel || incident.assignedTo || 'Unassigned'}
        Created: ${formatDate(incident.createdAt)}
        Source IP: ${incident.sourceIP}
        MITRE: ${mitreTechnique}
        ${cveText}
        Related Logs: ${incident.logs}
    `;
    
    alert(details);
}

function ensureIncidentTimelineModal() {
    let modal = document.getElementById('incident-timeline-modal');
    if (modal) return modal;

    modal = document.createElement('div');
    modal.id = 'incident-timeline-modal';
    modal.className = 'modal hidden';
    modal.innerHTML = `
        <div class="modal-content modal-lg">
            <div class="modal-header">
                <h3><i class="fas fa-stream"></i> Incident Timeline</h3>
                <button class="close-modal" onclick="closeIncidentTimelineModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div id="incident-timeline-content" class="incident-timeline-content"></div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-outline" onclick="closeIncidentTimelineModal()">Close</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    return modal;
}

function formatTimelineTimestamp(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString();
}

function renderIncidentTimeline(incident) {
    const content = document.getElementById('incident-timeline-content');
    if (!content) return;

    const events = Array.isArray(incident.timelineEvents) ? incident.timelineEvents : [];
    const relatedLogs = Array.isArray(incident.relatedLogs) ? incident.relatedLogs : [];

    const eventList = events.length
        ? events.map(event => `
            <article class="timeline-entry ${event.type || 'timeline_event'}">
                <div class="timeline-entry-head">
                    <strong>${escapeHtml(event.action || 'Timeline event')}</strong>
                    <span>${escapeHtml(formatTimelineTimestamp(event.timestamp))}</span>
                </div>
                <p>${escapeHtml(event.note || 'No details available')}</p>
                ${event.user && (event.user.name || event.user.email) ? `<span class="timeline-meta">By ${escapeHtml(event.user.name || event.user.email)}</span>` : ''}
                ${event.log ? `<span class="timeline-meta">Log: ${escapeHtml(event.log.attackType || 'n/a')} from ${escapeHtml(event.log.sourceIP || 'n/a')}</span>` : ''}
            </article>
        `).join('')
        : '<p class="empty-state">No timeline events found for this incident.</p>';

    content.innerHTML = `
        <div class="timeline-incident-summary">
            <h4>${escapeHtml(incident.title || 'Incident')}</h4>
            <p>${escapeHtml(incident.description || 'No description')}</p>
            <div class="timeline-incident-meta">
                <span class="badge badge-danger">${escapeHtml((incident.severity || 'medium').toUpperCase())}</span>
                <span class="status-badge status-${escapeHtml(incident.status || 'open')}">${escapeHtml((incident.status || 'open').replace('_', ' ').toUpperCase())}</span>
                <span>${escapeHtml(incident.sourceIP || 'N/A')}</span>
                <span>${escapeHtml(incident.targetSystem || 'Unknown target')}</span>
            </div>
        </div>
        <div class="timeline-stats">
            <div class="timeline-stat"><strong>${events.length}</strong><span>timeline events</span></div>
            <div class="timeline-stat"><strong>${relatedLogs.length}</strong><span>related logs</span></div>
            <div class="timeline-stat"><strong>${incident.remediationSteps?.length || 0}</strong><span>remediation steps</span></div>
        </div>
        <div class="timeline-feed">
            ${eventList}
        </div>
    `;
}

async function viewIncidentTimeline(id) {
    try {
        const response = await fetch(`${getApiBaseUrl()}/incidents/${id}/timeline`, {
            headers: getAuthHeaders()
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'Could not load incident timeline');
        }

        const modal = ensureIncidentTimelineModal();
        renderIncidentTimeline(payload.incident || {});
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    } catch (error) {
        console.error('Failed to load incident timeline:', error);
        alert(error.message || 'Could not load incident timeline');
    }
}

function closeIncidentTimelineModal() {
    document.getElementById('incident-timeline-modal')?.classList.add('hidden');
    document.body.style.overflow = '';
}

// Edit Incident
async function editIncident(id) {
    const incident = incidents.find(i => String(i.id) === String(id));
    if (!incident) return;
    
    const newStatus = prompt('Enter new status (open/in_progress/resolved/closed):', incident.status);
    if (newStatus && ['open', 'in_progress', 'resolved', 'closed'].includes(newStatus)) {
        try {
            const response = await fetch(`${getApiBaseUrl()}/incidents/${id}/status`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify({ status: newStatus, note: `Status changed to ${newStatus}` })
            });
            const payload = await response.json();
            if (!response.ok || !payload.success) {
                throw new Error(payload.message || 'Status update failed');
            }
            await loadIncidents();
            alert(isAdminUser() ? 'Incident updated!' : 'Incident status updated!');
        } catch (error) {
            console.error('Incident status update failed:', error);
            alert(error.message || 'Incident status update failed');
        }
    }
}

async function archiveIncident(id) {
    if (!isAdminUser()) {
        showNotification('Only admins can archive incidents.', 'error');
        return;
    }

    const incident = incidents.find(item => String(item.id) === String(id));
    if (!incident) return;
    if (!confirm('Archive this incident from the active Incidents view?')) return;

    const isLocal = String(id).startsWith('local-');
    try {
        if (!isLocal) {
            const response = await fetch(`${getApiBaseUrl()}/incidents/${id}`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify({ archived: true })
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.message || 'Could not archive incident');
            }
        } else {
            const localIncidents = getStoredLocalIncidents().map(item =>
                String(item.id) === String(id) ? { ...item, archived: true, archivedAt: new Date().toISOString() } : item
            );
            localStorage.setItem('microsocLocalIncidents', JSON.stringify(localIncidents));
        }

        rememberArchivedIncidentId(id);
        incidents = incidents.filter(item => String(item.id) !== String(id));
        renderInciments(incidents);
        renderIncidentStats(null, incidents);
        showNotification('Incident archived', 'success');
    } catch (error) {
        console.error('Archive incident failed:', error);
        showNotification(error.message || 'Could not archive incident.', 'error');
    }
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

function notifyIncidentAI(message, type = 'info') {
    if (typeof window.showNotification === 'function') {
        window.showNotification(message, type);
        return;
    }

    let stack = document.getElementById('toast-stack');
    if (!stack) {
        stack = document.createElement('div');
        stack.id = 'toast-stack';
        stack.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 10000; display: flex; flex-direction: column; gap: 10px; max-width: 380px;';
        document.body.appendChild(stack);
    }

    const colors = {
        info: '#2563eb',
        success: '#16a34a',
        warning: '#f59e0b',
        error: '#dc2626'
    };
    const icons = {
        info: 'fa-info-circle',
        success: 'fa-check-circle',
        warning: 'fa-exclamation-triangle',
        error: 'fa-shield-virus'
    };

    const notification = document.createElement('div');
    notification.style.cssText = `
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 12px 14px;
        border-radius: 8px;
        background: rgba(15, 23, 42, 0.96);
        color: #fff;
        border-left: 4px solid ${colors[type] || colors.info};
        box-shadow: 0 10px 30px rgba(0,0,0,0.28);
        font-size: 14px;
        line-height: 1.4;
    `;
    notification.innerHTML = `
        <i class="fas ${icons[type] || icons.info}" style="color: ${colors[type] || colors.info};"></i>
        <span>${escapeHtml(message)}</span>
    `;

    stack.appendChild(notification);
    setTimeout(() => notification.remove(), 5200);
}

function ensureAITriageModal() {
    let modal = document.getElementById('ai-triage-modal');
    if (modal) return modal;

    modal = document.createElement('div');
    modal.id = 'ai-triage-modal';
    modal.className = 'modal hidden';
    modal.innerHTML = `
        <div class="modal-content modal-lg ai-result-panel">
            <div class="modal-header">
                <h3><i class="fas fa-brain"></i> AI Incident Triage</h3>
                <button class="close-modal" onclick="closeAITriageModal()">&times;</button>
            </div>
            <div class="modal-body" id="ai-triage-content"></div>
            <div class="modal-footer">
                <button class="btn btn-outline" onclick="closeAITriageModal()">Close</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    return modal;
}

function renderAITriage(result, mode = 'fallback') {
    const modal = ensureAITriageModal();
    const content = document.getElementById('ai-triage-content');
    const actions = normalizeAIList(result.recommendedActions || result.actions);
    const containment = normalizeAIList(result.containment);
    const evidence = normalizeAIList(result.evidenceNeeded || result.evidence);
    const mitre = normalizeAIList(result.mitre || result.mitreMapping);

    content.innerHTML = `
        <div class="ai-result-meta">
            <span class="ai-chip">${escapeHtml(mode === 'ai' ? 'Model Assisted' : 'Local Fallback')}</span>
            <span class="ai-chip danger">Priority ${escapeHtml(result.priorityScore || '--')}/100</span>
            <span class="ai-chip">${escapeHtml(result.severity || 'medium').toUpperCase()}</span>
        </div>
        <p class="ai-summary">${escapeHtml(result.summary || 'AI triage generated successfully.')}</p>
        ${result.businessImpact ? `<p><strong>Business impact:</strong> ${escapeHtml(result.businessImpact)}</p>` : ''}
        ${mitre.length ? `<div class="ai-section"><strong>MITRE:</strong><div>${mitre.map(item => `<span class="ai-chip">${escapeHtml(item)}</span>`).join('')}</div></div>` : ''}
        ${actions.length ? `<div class="ai-section"><strong>Recommended actions:</strong><ul>${actions.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul></div>` : ''}
        ${containment.length ? `<div class="ai-section"><strong>Containment:</strong><ul>${containment.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul></div>` : ''}
        ${evidence.length ? `<div class="ai-section"><strong>Evidence needed:</strong><ul>${evidence.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul></div>` : ''}
    `;

    modal.classList.remove('hidden');
}

function renderAITriageLoading(title = 'AI Incident Triage', message = 'AI is thinking through the incident...') {
    const modal = ensureAITriageModal();
    const content = document.getElementById('ai-triage-content');
    content.innerHTML = `
        <div class="ai-loading-state">
            <div class="ai-loading-orb"><i class="fas fa-brain"></i></div>
            <h4>${escapeHtml(title)}</h4>
            <p>${escapeHtml(message)}</p>
            <div class="ai-loading-steps">
                <span>Reviewing incident context</span>
                <span>Checking severity and impact</span>
                <span>Preparing response actions</span>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
}

function renderAITriageError(title = 'AI Incident Triage Failed', message = 'AI triage failed. Please check backend login/session.') {
    const modal = ensureAITriageModal();
    const content = document.getElementById('ai-triage-content');
    content.innerHTML = `
        <div class="ai-loading-state ai-error-state">
            <div class="ai-loading-orb"><i class="fas fa-triangle-exclamation"></i></div>
            <h4>${escapeHtml(title)}</h4>
            <p>${escapeHtml(message)}</p>
        </div>
    `;
    modal.classList.remove('hidden');
}

function closeAITriageModal() {
    document.getElementById('ai-triage-modal')?.classList.add('hidden');
}

async function triageIncidentWithAI(id) {
    const incident = incidents.find(i => String(i.id) === String(id));
    if (!incident) return;

    renderAITriageLoading(`AI Triage: ${incident.title || 'Incident'}`, 'AI is explaining this incident...');
    notifyIncidentAI('AI is explaining this incident...', 'info');

    try {
        const response = await fetch(`${getApiBaseUrl()}/ai/triage-incident`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ incident })
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'AI triage failed');
        }

        renderAITriage(payload.data, payload.mode);
    } catch (error) {
        console.error('AI incident triage failed:', error);
        renderAITriageError(`AI Triage: ${incident.title || 'Incident'}`, error.message || 'AI triage failed. Please check backend login/session.');
        notifyIncidentAI(error.message || 'AI triage failed. Please check backend login/session.', 'error');
    }
}

// Export functions
window.loadIncidents = loadIncidents;
window.filterIncidents = filterIncidents;
window.searchIncidents = searchIncidents;
window.openNewIncidentModal = openNewIncidentModal;
window.closeModal = closeModal;
window.createNewIncident = createNewIncident;
window.openAssignIncidentModal = openAssignIncidentModal;
window.closeAssignIncidentModal = closeAssignIncidentModal;
window.submitIncidentAssignment = submitIncidentAssignment;
window.viewIncident = viewIncident;
window.viewIncidentTimeline = viewIncidentTimeline;
window.closeIncidentTimelineModal = closeIncidentTimelineModal;
window.editIncident = editIncident;
window.archiveIncident = archiveIncident;
window.triageIncidentWithAI = triageIncidentWithAI;
window.closeAITriageModal = closeAITriageModal;
