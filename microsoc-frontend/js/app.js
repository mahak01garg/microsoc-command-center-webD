// app.js - Main Application JavaScript for MicroSOC Command Center

// ============================================================================
// GLOBAL VARIABLES AND CONSTANTS
// ============================================================================

const ATTACK_TYPES = {
    XSS: 'XSS',
    SQL_INJECTION: 'SQL Injection',
    PORT_SCAN: 'Port Scan',
    BRUTE_FORCE: 'Brute Force',
    DDoS: 'DDoS',
    MALWARE: 'Malware',
    PHISHING: 'Phishing',
    INSIDER_THREAT: 'Insider Threat'
};

const SEVERITY_LEVELS = {
    LOW: { level: 'low', color: '#28a745', label: 'Low', icon: 'fa-info-circle' },
    MEDIUM: { level: 'medium', color: '#ffc107', label: 'Medium', icon: 'fa-exclamation-triangle' },
    HIGH: { level: 'high', color: '#fd7e14', label: 'High', icon: 'fa-exclamation-circle' },
    CRITICAL: { level: 'critical', color: '#dc3545', label: 'Critical', icon: 'fa-skull-crossbones' }
};

const INCIDENT_STATUS = {
    OPEN: 'open',
    IN_PROGRESS: 'in_progress',
    RESOLVED: 'resolved',
    CLOSED: 'closed'
};

const USER_ROLES = {
    ADMIN: 'admin',
    ANALYST: 'analyst'
};

const ASSET_VERSION = '20260623t';

const ROLE_NAVIGATION = {
    admin: [
        { key: 'dashboard', label: 'Dashboard', icon: 'fa-tachometer-alt', href: 'dashboard.html' },
        { key: 'logs', label: 'Security Logs', icon: 'fa-stream', href: 'logs.html', badge: { id: 'log-count', className: 'badge-warning' } },
        { key: 'alerts', label: 'Alerts', icon: 'fa-bell', href: 'alerts.html', badge: { id: 'notification-count', className: 'badge-danger' } },
        { key: 'incidents', label: 'Incidents', icon: 'fa-exclamation-triangle', href: 'incidents.html', badge: { id: 'incident-count', className: 'badge-danger' } },
        { key: 'analytics', label: 'Analytics', icon: 'fa-chart-line', href: 'analytics.html' },
        { key: 'user-management', label: 'User Management', icon: 'fa-users-cog', href: '#/user-management' },
        { key: 'audit-logs', label: 'Audit Logs', icon: 'fa-clipboard-list', href: '#/audit-logs' },
        { key: 'settings', label: 'Settings', icon: 'fa-cogs', href: '#/settings' }
    ],
    analyst: [
        { key: 'dashboard', label: 'Dashboard', icon: 'fa-tachometer-alt', href: 'dashboard.html' },
        { key: 'logs', label: 'Security Logs', icon: 'fa-stream', href: 'logs.html', badge: { id: 'log-count', className: 'badge-warning' } },
        { key: 'alerts', label: 'Alerts', icon: 'fa-bell', href: 'alerts.html', badge: { id: 'notification-count', className: 'badge-danger' } },
        { key: 'incidents', label: 'Incidents', icon: 'fa-exclamation-triangle', href: 'incidents.html', badge: { id: 'incident-count', className: 'badge-danger' } },
        { key: 'analytics', label: 'Analytics', icon: 'fa-chart-line', href: 'analytics.html' }
    ]
};

let sidebarRepairTimer = null;
const sidebarObservers = new WeakMap();
let pageIntegrityObserver = null;

// ============================================================================
// CORE APPLICATION FUNCTIONS
// ============================================================================

/**
 * Initialize the application
 */
function initApp() {
    console.log('Initializing MicroSOC Command Center...');
    
    // Load saved theme
    loadTheme();
    
    // Check authentication
    checkAuthentication();
    
    // Initialize current page
    initCurrentPage();
    
    // Setup event listeners
    setupEventListeners();
    
    // Initialize tooltips
    initTooltips();
    
    console.log('Application initialized successfully');
}

/**
 * Load saved theme from localStorage
 */
function loadTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    const themeStyle = document.getElementById('theme-style');
    
    if (themeStyle) {
        themeStyle.setAttribute('href', `css/${savedTheme}-theme.css?v=${ASSET_VERSION}`);
        document.body.dataset.theme = savedTheme;
        
        // Update theme toggle icon if exists
        updateThemeIcon(savedTheme);
    }
}

/**
 * Update theme toggle icon based on current theme
 */
function updateThemeIcon(currentTheme) {
    const themeIcon = document.querySelector('.theme-toggle i, [onclick*="toggleTheme"] i');
    if (themeIcon) {
        themeIcon.className = currentTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
}

function getCurrentUserRole() {
    try {
        return String(getUser()?.role || USER_ROLES.ANALYST).trim().toLowerCase();
    } catch (error) {
        return USER_ROLES.ANALYST;
    }
}

function isAdminUser() {
    return getCurrentUserRole() === USER_ROLES.ADMIN;
}

function showFeatureUnavailable(featureName) {
    const message = `${featureName} is available for admins only.`;
    if (typeof window.showNotification === 'function') {
        window.showNotification(message, 'warning');
        return;
    }
    window.alert(message);
}

function renderSidebarNavigation() {
    const sidebarNav = document.querySelector('.sidebar-nav ul');
    if (!sidebarNav) return;

    const role = getCurrentUserRole();
    const items = ROLE_NAVIGATION[role] || ROLE_NAVIGATION.analyst;
    const currentPage = (window.location.pathname.split('/').pop() || '').replace(/\.html$/, '');
    const currentHash = window.location.hash.replace(/^#\/?/, '').split('?')[0];

    sidebarNav.innerHTML = items.map(item => {
        const itemRoute = item.href.startsWith('#/')
            ? item.href.replace(/^#\//, '').split('?')[0]
            : item.href.split('#')[0].replace('.html', '');
        const isActive = itemRoute === currentPage || itemRoute === currentHash;
        const badge = item.badge
            ? `<span class="badge ${item.badge.className}" id="${item.badge.id}">0</span>`
            : '';

        return `
            <li class="${isActive ? 'active' : ''}" data-sidebar-key="${item.key}">
                <a href="${item.href}" ${item.title ? `title="${item.title}"` : ''}>
                    <i class="fas ${item.icon}"></i>
                    <span>${item.label}</span>
                    ${badge}
                </a>
            </li>
        `;
    }).join('') + `
        <li>
            <a href="javascript:void(0)" onclick="toggleTheme(); return false;">
                <i class="fas fa-moon" id="theme-icon"></i>
                <span>Theme</span>
            </a>
        </li>
        <li>
            <a href="#" onclick="logout()">
                <i class="fas fa-sign-out-alt"></i>
                <span>Logout</span>
            </a>
        </li>
    `;

    scheduleSidebarRepair();

    sidebarNav.querySelectorAll('[data-admin-feature]').forEach((element) => {
        element.addEventListener('click', (event) => {
            event.preventDefault();
            showFeatureUnavailable(element.querySelector('span')?.textContent || 'This feature');
        });
    });

    observeSidebarNavigation();
}

function scheduleSidebarRepair() {
    if (sidebarRepairTimer) return;
    sidebarRepairTimer = setTimeout(() => {
        sidebarRepairTimer = null;
        enforceSidebarNavigationIntegrity();
    }, 0);
}

function observeSidebarNavigation() {
    const sidebarNav = document.querySelector('.sidebar-nav ul');
    if (!sidebarNav || sidebarObservers.has(sidebarNav)) return;

    const observer = new MutationObserver(() => {
        enforceSidebarNavigationIntegrity();
    });
    observer.observe(sidebarNav, { childList: true, subtree: true });
    sidebarObservers.set(sidebarNav, observer);

    observePageIntegrity();
}

function enforceSidebarNavigationIntegrity() {
    const sidebarNav = document.querySelector('.sidebar-nav ul');
    if (!sidebarNav) return;

    const expectedKeys = (ROLE_NAVIGATION[getCurrentUserRole()] || ROLE_NAVIGATION.analyst).map(item => item.key);
    const currentKeys = Array.from(sidebarNav.querySelectorAll('li[data-sidebar-key]')).map(item => item.dataset.sidebarKey);
    const hasExpectedLogs = sidebarNav.querySelector('a[href*="logs.html"]');

    if (!hasExpectedLogs || expectedKeys.join('|') !== currentKeys.join('|')) {
        renderSidebarNavigation();
    }
}

function observePageIntegrity() {
    if (pageIntegrityObserver) return;
    pageIntegrityObserver = new MutationObserver(() => {
        enforceSidebarNavigationIntegrity();
    });
    pageIntegrityObserver.observe(document.body, { childList: true, subtree: true });
}

/**
 * Check if user is authenticated
 */
function checkAuthentication() {
    const protectedPages = ['dashboard.html', 'incidents.html', 'logs.html', 'alerts.html', 'analytics.html'];
    const currentPage = window.location.pathname.split('/').pop();
    
    if (protectedPages.includes(currentPage)) {
        const user = getUser();
        const token = localStorage.getItem("token"); // ✅ FIX
        
        if (!token) {
            window.location.href = 'login.html';
            return false;
        }
        
        // Update UI with user info
        updateUserInfo(user);
        renderSidebarNavigation();
        return true;
    }
    
    return false;
}


/**
 * Get current user from localStorage
 */
function getUser() {
    try {
        return JSON.parse(localStorage.getItem('user'));
    } catch (e) {
        return null;
    }
}

/**
 * Update user information in the UI
 */
function updateUserInfo(user) {
    const userNameElements = document.querySelectorAll('#user-name, .user-name');
    const userRoleElements = document.querySelectorAll('#user-role, .user-role');
    
    if (user) {
        userNameElements.forEach(el => {
            if (el) el.textContent = user.name || 'User';
        });
        
        userRoleElements.forEach(el => {
            if (el) el.textContent = (user.role || 'analyst').charAt(0).toUpperCase() + (user.role || 'analyst').slice(1);
        });
    }
}

/**
 * Ensure Alerts appears in the sidebar across all static pages.
 */
function ensureAlertsSidebarLink() {
    renderSidebarNavigation();
}

function reorderSidebarNavigation() {
    renderSidebarNavigation();
}

/**
 * Initialize current page based on URL
 */
function initCurrentPage() {
    const currentPage = window.location.pathname.split('/').pop();
    ensureAlertsSidebarLink();
    reorderSidebarNavigation();
    scheduleSidebarRepair();
    
    switch(currentPage) {
        case 'dashboard.html':
            if (typeof initDashboard === 'function') initDashboard();
            break;
        case 'incidents.html':
            if (typeof loadIncidents === 'function') loadIncidents();
            break;
        case 'logs.html':
            if (typeof initLogs === 'function') initLogs();
            break;
        case 'alerts.html':
            if (typeof initAlerts === 'function') initAlerts();
            break;
        case 'analytics.html':
            if (typeof initAnalytics === 'function') initAnalytics();
            break;
        case 'login.html':
            initLoginPage();
            break;
    }
}

/**
 * Initialize login page
 */
function initLoginPage() {
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    
    if (emailInput && passwordInput) {
        emailInput.value = '';
        passwordInput.value = '';
    }
}

/**
 * Setup global event listeners
 */
function setupEventListeners() {
    // Global click handler for sidebar toggle
    document.addEventListener('click', function(e) {
        // Close sidebar when clicking outside on mobile
        if (window.innerWidth <= 768) {
            const sidebar = document.getElementById('sidebar');
            const toggleBtn = document.querySelector('.sidebar-toggle');
            
            if (sidebar && sidebar.classList.contains('active') && 
                !sidebar.contains(e.target) && 
                !toggleBtn.contains(e.target)) {
                sidebar.classList.remove('active');
            }
        }
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl + D for dashboard
        if (e.ctrlKey && e.key === 'd') {
            e.preventDefault();
            window.location.href = 'dashboard.html';
        }
        
        // Ctrl + I for incidents
        if (e.ctrlKey && e.key === 'i') {
            e.preventDefault();
            window.location.href = 'incidents.html';
        }
        
        // Ctrl + L for logs
        if (e.ctrlKey && e.key === 'l') {
            e.preventDefault();
            window.location.href = 'logs.html';
        }
        
        // Ctrl + T for theme toggle
        if (e.ctrlKey && e.key === 't') {
            e.preventDefault();
            toggleTheme();
        }
        
        // Escape key to close modals
        if (e.key === 'Escape') {
            closeAllModals();
        }
    });
    
    // Window resize handler
    window.addEventListener('resize', handleResize);
    
    // Before unload - save state
    window.addEventListener('beforeunload', function() {
        // Save any unsaved data if needed
    });
}

/**
 * Handle window resize
 */
function handleResize() {
    const sidebar = document.getElementById('sidebar');
    
    // Auto-close sidebar on mobile when resizing to desktop
    if (window.innerWidth > 768 && sidebar) {
        sidebar.classList.remove('active');
    }
}

// ============================================================================
// SIDEBAR FUNCTIONS
// ============================================================================

/**
 * Toggle sidebar visibility (mobile)
 */
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        sidebar.classList.toggle('active');
    }
}

/**
 * Close sidebar (mobile)
 */
function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        sidebar.classList.remove('active');
    }
}

// ============================================================================
// THEME FUNCTIONS
// ============================================================================

/**
 * Toggle between dark and light theme
 */
function toggleTheme() {
    const themeStyle = document.getElementById('theme-style');
    if (!themeStyle) return;
    const currentTheme = themeStyle.getAttribute('href').includes('dark') ? 'dark' : 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    
    // Update theme
    themeStyle.setAttribute('href', `css/${newTheme}-theme.css?v=${ASSET_VERSION}`);
    document.body.dataset.theme = newTheme;
    document.documentElement.dataset.theme = newTheme;
    localStorage.setItem('theme', newTheme);
    
    // Update icon
    updateThemeIcon(newTheme);
    window.dispatchEvent(new CustomEvent('microsoc:theme-changed', {
        detail: { theme: newTheme }
    }));
    
    // Show notification
    showNotification(`Switched to ${newTheme} theme`, 'info');
}

// ============================================================================
// TIME AND DATE FUNCTIONS
// ============================================================================

/**
 * Update current time display
 */
function updateTime() {
    const timeElements = document.querySelectorAll('#current-time, .current-time');
    
    if (timeElements.length > 0) {
        const now = new Date();
        const timeString = now.toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
        
        timeElements.forEach(el => {
            el.textContent = timeString;
        });
    }
}

/**
 * Format date for display
 */
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    // Show relative time for recent dates
    if (diffMins < 1) {
        return 'Just now';
    } else if (diffMins < 60) {
        return `${diffMins}m ago`;
    } else if (diffHours < 24) {
        return `${diffHours}h ago`;
    } else if (diffDays === 1) {
        return 'Yesterday';
    } else if (diffDays < 7) {
        return `${diffDays}d ago`;
    }
    
    // Otherwise show full date
    return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

/**
 * Format date for detailed display
 */
function formatDateTime(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// ============================================================================
// AUTHENTICATION FUNCTIONS
// ============================================================================

/**
 * Logout user
 */
function logout() {
    // Clear user data
    localStorage.removeItem('user');
    localStorage.removeItem('token');
    
    // Show logout notification
    showNotification('Logged out successfully', 'info');
    
    // Redirect to login page
    setTimeout(() => {
        window.location.href = 'login.html';
    }, 500);
}

/**
 * Check if user has specific role
 */
function hasRole(requiredRole) {
    const user = getUser();
    return user && user.role === requiredRole;
}

/**
 * Restrict access based on role
 */
function restrictToRole(requiredRole) {
    const user = getUser();
    if (!user || user.role !== requiredRole) {
        showNotification('Access denied. Insufficient permissions.', 'error');
        return false;
    }
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Generate random IP address
 */
function generateIP() {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

/**
 * Get severity color
 */
function getSeverityColor(severity) {
    const severityObj = Object.values(SEVERITY_LEVELS).find(s => s.level === severity.toLowerCase());
    return severityObj ? severityObj.color : '#6c757d';
}

/**
 * Get attack type icon
 */
function getAttackTypeIcon(attackType) {
    const icons = {
        'XSS': 'fa-code',
        'SQL Injection': 'fa-database',
        'Port Scan': 'fa-search',
        'Brute Force': 'fa-key',
        'DDoS': 'fa-broadcast-tower',
        'Malware': 'fa-virus',
        'Phishing': 'fa-fish',
        'Insider Threat': 'fa-user-secret',
        'default': 'fa-exclamation-triangle'
    };
    
    return icons[attackType] || icons['default'];
}

/**
 * Get severity icon
 */
function getSeverityIcon(severity) {
    const severityObj = Object.values(SEVERITY_LEVELS).find(s => s.level === severity.toLowerCase());
    return severityObj ? severityObj.icon : 'fa-exclamation-triangle';
}

/**
 * Generate random ID
 */
function generateId() {
    return 'id_' + Math.random().toString(36).substr(2, 9);
}

/**
 * Debounce function for performance
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Throttle function for performance
 */
function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// ============================================================================
// NOTIFICATION SYSTEM
// ============================================================================

/**
 * Show notification message
 */
function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function showNotification(message, type = 'info') {
    let stack = document.getElementById('toast-stack');
    if (!stack) {
        stack = document.createElement('div');
        stack.id = 'toast-stack';
        stack.className = 'toast-stack';
        document.body.appendChild(stack);
    }

    const notification = document.createElement('div');
    notification.className = `custom-notification notification-${type}`;

    const icons = {
        'success': 'fa-check-circle',
        'error': 'fa-shield-virus',
        'warning': 'fa-exclamation-triangle',
        'info': 'fa-info-circle'
    };
    const icon = icons[type] || icons['info'];
    const title = type === 'success' ? 'Success' : type === 'error' ? 'Security Alert' : type === 'warning' ? 'Attention' : 'MicroSOC';

    notification.innerHTML = `
        <div class="toast-icon"><i class="fas ${icon}"></i></div>
        <div class="toast-copy">
            <strong>${escapeHtml(title)}</strong>
            <span>${escapeHtml(message)}</span>
        </div>
        <button class="toast-close" onclick="this.closest('.custom-notification').remove()" aria-label="Close notification">&times;</button>
    `;

    stack.appendChild(notification);

    setTimeout(() => {
        if (notification.parentElement) {
            notification.classList.add('leaving');
            setTimeout(() => notification.remove(), 180);
        }
    }, 5001);
}

// ============================================================================
// MODAL SYSTEM
// ============================================================================

/**
 * Open modal by ID
 */
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden'; // Prevent scrolling
    }
}

/**
 * Close modal by ID
 */
function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('hidden');
        document.body.style.overflow = ''; // Restore scrolling
    }
}

/**
 * Close all modals
 */
function closeAllModals() {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.classList.add('hidden');
    });
    document.body.style.overflow = ''; // Restore scrolling
}

// ============================================================================
// TOOLTIP SYSTEM
// ============================================================================

/**
 * Initialize tooltips
 */
function initTooltips() {
    const tooltipElements = document.querySelectorAll('[data-tooltip]');
    
    tooltipElements.forEach(element => {
        element.addEventListener('mouseenter', showTooltip);
        element.addEventListener('mouseleave', hideTooltip);
        element.addEventListener('focus', showTooltip);
        element.addEventListener('blur', hideTooltip);
    });
}

/**
 * Show tooltip
 */
function showTooltip(e) {
    const tooltipText = this.getAttribute('data-tooltip');
    if (!tooltipText) return;
    
    // Remove existing tooltip
    const existingTooltip = document.querySelector('.custom-tooltip');
    if (existingTooltip) {
        existingTooltip.remove();
    }
    
    // Create tooltip element
    const tooltip = document.createElement('div');
    tooltip.className = 'custom-tooltip';
    tooltip.textContent = tooltipText;
    
    // Add styles
    tooltip.style.cssText = `
        position: fixed;
        background: rgba(0, 0, 0, 0.8);
        color: white;
        padding: 6px 12px;
        border-radius: 4px;
        font-size: 12px;
        z-index: 10001;
        pointer-events: none;
        white-space: nowrap;
        transform: translate(-50%, -100%);
        margin-top: -8px;
    `;
    
    document.body.appendChild(tooltip);
    
    // Position tooltip
    const rect = this.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    
    let left = rect.left + rect.width / 2;
    let top = rect.top - tooltipRect.height - 5;
    
    // Adjust if tooltip goes off screen
    if (left - tooltipRect.width / 2 < 0) {
        left = tooltipRect.width / 2;
    } else if (left + tooltipRect.width / 2 > window.innerWidth) {
        left = window.innerWidth - tooltipRect.width / 2;
    }
    
    if (top < 0) {
        top = rect.bottom + 5;
    }
    
    tooltip.style.left = left + 'px';
    tooltip.style.top = top + 'px';
    
    // Store reference
    this.currentTooltip = tooltip;
}

/**
 * Hide tooltip
 */
function hideTooltip() {
    if (this.currentTooltip) {
        this.currentTooltip.remove();
        this.currentTooltip = null;
    }
}

// ============================================================================
// DATA STORAGE FUNCTIONS
// ============================================================================

/**
 * Save data to localStorage
 */
function saveData(key, data) {
    try {
        localStorage.setItem(key, JSON.stringify(data));
        return true;
    } catch (e) {
        console.error('Error saving data:', e);
        showNotification('Error saving data', 'error');
        return false;
    }
}

/**
 * Load data from localStorage
 */
function loadData(key) {
    try {
        const data = localStorage.getItem(key);
        return data ? JSON.parse(data) : null;
    } catch (e) {
        console.error('Error loading data:', e);
        return null;
    }
}

/**
 * Clear specific data from localStorage
 */
function clearData(key) {
    try {
        localStorage.removeItem(key);
        return true;
    } catch (e) {
        console.error('Error clearing data:', e);
        return false;
    }
}

// ============================================================================
// FORM VALIDATION
// ============================================================================

/**
 * Validate email format
 */
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

/**
 * Validate IP address format
 */
function validateIP(ip) {
    const re = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return re.test(ip);
}

/**
 * Show form error
 */
function showFormError(input, message) {
    // Remove existing error
    const existingError = input.parentElement.querySelector('.form-error');
    if (existingError) {
        existingError.remove();
    }
    
    // Add error message
    const error = document.createElement('div');
    error.className = 'form-error';
    error.textContent = message;
    error.style.cssText = `
        color: var(--danger-color);
        font-size: 12px;
        margin-top: 5px;
    `;
    
    input.parentElement.appendChild(error);
    input.style.borderColor = 'var(--danger-color)';
    
    // Focus on the input
    input.focus();
}

/**
 * Clear form error
 */
function clearFormError(input) {
    const error = input.parentElement.querySelector('.form-error');
    if (error) {
        error.remove();
    }
    input.style.borderColor = '';
}

// ============================================================================
// API MOCK FUNCTIONS (for demo purposes)
// ============================================================================

/**
 * Mock API call with delay
 */
function mockApiCall(data, delay = 1000) {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve({
                success: true,
                data: data,
                timestamp: new Date().toISOString()
            });
        }, delay);
    });
}

/**
 * Mock API error
 */
function mockApiError(message = 'Something went wrong', delay = 1000) {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve({
                success: false,
                error: message,
                timestamp: new Date().toISOString()
            });
        }, delay);
    });
}

// ============================================================================
// CHART UTILITIES
// ============================================================================

/**
 * Generate chart colors
 */
function generateChartColors(count) {
    const colors = [
        '#dc3545', '#007bff', '#28a745', '#ffc107',
        '#6c757d', '#17a2b8', '#e83e8c', '#fd7e14'
    ];
    
    return colors.slice(0, count);
}

/**
 * Create gradient for charts
 */
function createGradient(ctx, color) {
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, color + '80');
    gradient.addColorStop(1, color + '20');
    return gradient;
}

// ============================================================================
// SECURITY FUNCTIONS
// ============================================================================

/**
 * Sanitize HTML input
 */
function sanitizeHTML(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

/**
 * Generate secure random string
 */
function generateSecureId(length = 16) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const cryptoObj = window.crypto || window.msCrypto;
    
    if (cryptoObj && cryptoObj.getRandomValues) {
        const values = new Uint32Array(length);
        cryptoObj.getRandomValues(values);
        for (let i = 0; i < length; i++) {
            result += chars[values[i] % chars.length];
        }
    } else {
        // Fallback for browsers without crypto support
        for (let i = 0; i < length; i++) {
            result += chars[Math.floor(Math.random() * chars.length)];
        }
    }
    
    return result;
}

// ============================================================================
// EXPORT FUNCTIONS
// ============================================================================

/**
 * Export data as JSON file
 */
function exportAsJson(data, filename = 'export.json') {
    try {
        const dataStr = JSON.stringify(data, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        exportBlob(dataBlob, filename);
        return true;
    } catch (e) {
        console.error('Error exporting JSON:', e);
        showNotification('Error exporting data', 'error');
        return false;
    }
}

/**
 * Export data as CSV file
 */
function exportAsCsv(data, filename = 'export.csv') {
    try {
        if (!Array.isArray(data) || data.length === 0) {
            throw new Error('No data to export');
        }
        
        // Extract headers
        const headers = Object.keys(data[0]);
        
        // Create CSV content
        let csvContent = headers.join(',') + '\n';
        
        data.forEach(item => {
            const row = headers.map(header => {
                const value = item[header];
                // Handle values that might contain commas or quotes
                if (typeof value === 'string' && (value.includes(',') || value.includes('"'))) {
                    return `"${value.replace(/"/g, '""')}"`;
                }
                return value;
            });
            csvContent += row.join(',') + '\n';
        });
        
        const dataBlob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        exportBlob(dataBlob, filename);
        return true;
    } catch (e) {
        console.error('Error exporting CSV:', e);
        showNotification('Error exporting data', 'error');
        return false;
    }
}

/**
 * Export blob as file download
 */
function exportBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    showNotification(`File "${filename}" downloaded`, 'success');
}

// ============================================================================
// INITIALIZATION
// ============================================================================

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initApp();
    
    // Start time update interval
    setInterval(updateTime, 1000);
    updateTime(); // Initial call
    
    // Add CSS for tooltips if not already present
    if (!document.getElementById('tooltip-styles')) {
        const style = document.createElement('style');
        style.id = 'tooltip-styles';
        style.textContent = `
            .custom-tooltip {
                font-family: inherit;
                font-size: 12px;
                line-height: 1.4;
                max-width: 300px;
                text-align: center;
            }
            
            .form-error {
                animation: fadeIn 0.3s ease;
            }
            
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
        `;
        document.head.appendChild(style);
    }
});

// Make functions globally available
window.toggleSidebar = toggleSidebar;
window.closeSidebar = closeSidebar;
window.toggleTheme = toggleTheme;
window.updateTime = updateTime;
window.formatDate = formatDate;
window.formatDateTime = formatDateTime;
window.logout = logout;
window.hasRole = hasRole;
window.restrictToRole = restrictToRole;
window.generateIP = generateIP;
window.getSeverityColor = getSeverityColor;
window.getAttackTypeIcon = getAttackTypeIcon;
window.getSeverityIcon = getSeverityIcon;
window.generateId = generateId;
window.showNotification = showNotification;
window.openModal = openModal;
window.closeModal = closeModal;
window.closeAllModals = closeAllModals;
window.validateEmail = validateEmail;
window.validateIP = validateIP;
window.showFormError = showFormError;
window.clearFormError = clearFormError;
window.saveData = saveData;
window.loadData = loadData;
window.clearData = clearData;
window.exportAsJson = exportAsJson;
window.exportAsCsv = exportAsCsv;

console.log('app.js loaded successfully');
