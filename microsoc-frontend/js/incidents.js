// Incidents Page JavaScript

let incidents = [];

function getDemoIncidents() {
    return [
        {
            id: 101,
            title: 'Critical SQL Injection Attempt',
            description: 'Repeated SQL payloads detected against the auth gateway.',
            severity: 'critical',
            status: 'open',
            assignedTo: 'Mahak Garg',
            createdAt: new Date(Date.now() - 22 * 60000).toISOString(),
            logs: 14,
            sourceIP: '203.0.113.42'
        },
        {
            id: 102,
            title: 'Brute Force Login Pattern',
            description: 'High-volume failed login attempts from rotating source IPs.',
            severity: 'high',
            status: 'in_progress',
            assignedTo: 'Honey Tiwari',
            createdAt: new Date(Date.now() - 2 * 3600000).toISOString(),
            logs: 37,
            sourceIP: '198.51.100.18'
        },
        {
            id: 103,
            title: 'Suspicious Port Scan',
            description: 'Reconnaissance activity detected across production subnets.',
            severity: 'medium',
            status: 'resolved',
            assignedTo: 'Green Ranger',
            createdAt: new Date(Date.now() - 8 * 3600000).toISOString(),
            logs: 9,
            sourceIP: '192.0.2.91'
        }
    ];
}

// Load Incidents
async function loadIncidents() {
    const localIncidents = getLocalIncidents();

    try {
        const token = localStorage.getItem("token");

        const res = await fetch("https://microsoc-backend.onrender.com/api/incidents", {
            headers: {
                "Authorization": `Bearer ${token}`
            }
        });

        const data = await res.json();

        if (!res.ok) {
            console.error(data.message);
            incidents = localIncidents.length ? localIncidents : getDemoIncidents();
            renderInciments(incidents);
            return;
        }

        const backendIncidents = Array.isArray(data.incidents) ? data.incidents.map(normalizeIncident) : [];
        incidents = [...localIncidents, ...backendIncidents];
        if (!incidents.length) incidents = getDemoIncidents();
        renderInciments(incidents);
    } catch (err) {
        console.error("Failed to load incidents", err);
        incidents = localIncidents.length ? localIncidents : getDemoIncidents();
        renderInciments(incidents);
    }
}

function getLocalIncidents() {
    try {
        return JSON.parse(localStorage.getItem('microsocLocalIncidents') || '[]').map(normalizeIncident);
    } catch (error) {
        return [];
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


// Render Incidents Table
function renderInciments(filteredIncidents = incidents) {
    const tbody = document.querySelector('#incidents-table tbody');
    if (!tbody) return;
    
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
                <button class="btn btn-sm btn-outline" onclick="viewIncident(${incident.id})">
                    <i class="fas fa-eye"></i>
                </button>
                <button class="btn btn-sm btn-outline ai-action-btn" onclick="triageIncidentWithAI(${incident.id})" title="AI Triage">
                    <i class="fas fa-brain"></i>
                </button>
                <button class="btn btn-sm btn-outline" onclick="editIncident(${incident.id})">
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
function createNewIncident() {
    const title = document.getElementById('incident-title').value;
    const description = document.getElementById('incident-description').value;
    const severity = document.getElementById('incident-severity').value;
    const assignee = document.getElementById('incident-assignee').value;

    if (!title.trim() || !description.trim()) {
        alert('Please enter a title and description.');
        return;
    }
    
    const newIncident = {
        id: `local-${Date.now()}`,
        title: title,
        description: description,
        severity: severity,
        status: 'open',
        assignedTo: assignee || null,
        createdAt: new Date().toISOString(),
        logs: 0,
        sourceIP: 'N/A'
    };
    
    const localIncidents = getLocalIncidents();
    localIncidents.unshift(newIncident);
    localStorage.setItem('microsocLocalIncidents', JSON.stringify(localIncidents.slice(0, 50)));

    incidents.unshift(newIncident);
    renderInciments();
    closeModal();
    
    // Show success message
    alert('Incident created successfully!');
}

// View Incident Details
function viewIncident(id) {
    const incident = incidents.find(i => i.id === id);
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
function editIncident(id) {
    const incident = incidents.find(i => i.id === id);
    if (!incident) return;
    
    const newStatus = prompt('Enter new status (open/in_progress/resolved/closed):', incident.status);
    if (newStatus && ['open', 'in_progress', 'resolved', 'closed'].includes(newStatus)) {
        incident.status = newStatus;
        renderInciments();
        alert('Incident status updated!');
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
    const actions = result.recommendedActions || [];
    const containment = result.containment || [];
    const evidence = result.evidenceNeeded || [];
    const mitre = result.mitre || [];

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
    const incident = incidents.find(i => i.id === id);
    if (!incident) return;

    try {
        const response = await fetch('https://microsoc-backend.onrender.com/api/ai/triage-incident', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
            },
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
