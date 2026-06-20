// Incidents Page JavaScript

let incidents = [];

function getApiBaseUrl() {
    return window.MICROSOC_API_BASE_URL || 'http://localhost:5001/api';
}

function getAuthHeaders() {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
    };
}

// Load Incidents
async function loadIncidents() {
    try {
        const res = await fetch(`${getApiBaseUrl()}/incidents?limit=50`, {
            headers: getAuthHeaders()
        });

        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.message || 'Failed to load incidents');
        }

        const backendIncidents = Array.isArray(data.incidents) ? data.incidents.map(normalizeIncident) : [];
        incidents = backendIncidents;
        renderInciments(incidents);
        renderIncidentStats(data.stats);
    } catch (err) {
        console.error("Failed to load incidents", err);
        incidents = [];
        renderIncidentError(err.message || 'No live incident data available.');
        renderIncidentStats();
    }
}

function normalizeIncident(incident) {
    const assignedTo = incident.assignedTo && typeof incident.assignedTo === 'object'
        ? incident.assignedTo.name || incident.assignedTo.email
        : incident.assignedTo;

    return {
        ...incident,
        id: incident.id || incident._id,
        assignedTo,
        logs: Array.isArray(incident.logs)
            ? incident.logs.length
            : Array.isArray(incident.relatedLogs)
                ? incident.relatedLogs.length
                : incident.logs || 0,
        createdAt: incident.createdAt || incident.updatedAt || new Date().toISOString(),
        sourceIP: incident.sourceIP || 'N/A'
    };
}

function renderIncidentError(message) {
    const tbody = document.querySelector('#incidents-table tbody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="7">${escapeHtml(message)}</td></tr>`;
}

function renderIncidentStats(stats) {
    const grid = document.querySelector('.main-content .stats-grid');
    if (!grid) return;

    const statusCounts = Object.fromEntries((stats?.statusCounts || []).map(item => [item._id, item.count]));
    const severityCounts = Object.fromEntries((stats?.severityCounts || []).map(item => [item._id, item.count]));
    const open = statusCounts.open || 0;
    const inProgress = statusCounts.in_progress || 0;
    const resolved = statusCounts.resolved || 0;
    const critical = severityCounts.critical || 0;

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

    if (!filteredIncidents.length) {
        tbody.innerHTML = '<tr><td colspan="7">No incidents found.</td></tr>';
        return;
    }
    
    tbody.innerHTML = filteredIncidents.map(incident => `
        <tr data-id="${incident.id}">
            <td>#${incident.id}</td>
            <td>
                <strong>${incident.title}</strong>
                <div class="incident-description">${incident.description}</div>
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
                <button class="btn btn-sm btn-outline" onclick="viewIncident('${incident.id}')">
                    <i class="fas fa-eye"></i>
                </button>
                <button class="btn btn-sm btn-outline ai-action-btn" onclick="triageIncidentWithAI('${incident.id}')" title="AI Triage">
                    <i class="fas fa-brain"></i>
                </button>
                <button class="btn btn-sm btn-outline" onclick="editIncident('${incident.id}')">
                    <i class="fas fa-edit"></i>
                </button>
            </td>
        </tr>
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
    const modal = document.getElementById('new-incident-modal');
    if (!modal) return;
    const assigneeSelect = document.getElementById('incident-assignee');
    if (assigneeSelect) {
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
    const title = document.getElementById('incident-title').value;
    const description = document.getElementById('incident-description').value;
    const severity = document.getElementById('incident-severity').value;
    const assignee = document.getElementById('incident-assignee').value;

    if (!title.trim() || !description.trim()) {
        alert('Please enter a title and description.');
        return;
    }

    try {
        const response = await fetch(`${getApiBaseUrl()}/incidents`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({
                title,
                description,
                severity,
                status: 'open',
                assignedTo: /^[a-f\d]{24}$/i.test(assignee) ? assignee : undefined,
                category: 'other',
                priority: severity,
                impact: severity
            })
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
    
    const details = `
        Incident #${incident.id}: ${incident.title}
        
        Description: ${incident.description}
        
        Severity: ${incident.severity.toUpperCase()}
        Status: ${incident.status.toUpperCase()}
        Assigned To: ${incident.assignedTo || 'Unassigned'}
        Created: ${formatDate(incident.createdAt)}
        Source IP: ${incident.sourceIP}
        Related Logs: ${incident.logs}
    `;
    
    alert(details);
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
            alert('Incident status updated!');
        } catch (error) {
            console.error('Incident status update failed:', error);
            alert(error.message || 'Incident status update failed');
        }
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

function closeAITriageModal() {
    document.getElementById('ai-triage-modal')?.classList.add('hidden');
}

async function triageIncidentWithAI(id) {
    const incident = incidents.find(i => String(i.id) === String(id));
    if (!incident) return;

    try {
        const response = await fetch(`${getApiBaseUrl()}/ai/triage-incident`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ incident })
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
            throw new Error(payload.message || 'AI triage failed');
        }

        renderAITriage(payload.data, payload.mode);
    } catch (error) {
        console.error('AI incident triage failed:', error);
        alert('AI triage failed. Please check backend login/session.');
    }
}

// Export functions
window.loadIncidents = loadIncidents;
window.filterIncidents = filterIncidents;
window.searchIncidents = searchIncidents;
window.openNewIncidentModal = openNewIncidentModal;
window.closeModal = closeModal;
window.createNewIncident = createNewIncident;
window.viewIncident = viewIncident;
window.editIncident = editIncident;
window.triageIncidentWithAI = triageIncidentWithAI;
window.closeAITriageModal = closeAITriageModal;
