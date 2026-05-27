// utils.js - Utility Functions for MicroSOC Command Center

// DOM Utilities
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

// Generate Random IP Address
function generateIP() {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

// Generate Random MAC Address
function generateMAC() {
    const hexDigits = "0123456789ABCDEF";
    let mac = "";
    for (let i = 0; i < 6; i++) {
        mac += hexDigits.charAt(Math.floor(Math.random() * 16));
        mac += hexDigits.charAt(Math.floor(Math.random() * 16));
        if (i < 5) mac += ":";
    }
    return mac;
}

// Format Date and Time
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function formatTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    });
}

function timeAgo(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    
    const intervals = {
        year: 31536000,
        month: 2592000,
        week: 604800,
        day: 86400,
        hour: 3600,
        minute: 60,
        second: 1
    };
    
    for (const [unit, secondsInUnit] of Object.entries(intervals)) {
        const interval = Math.floor(seconds / secondsInUnit);
        if (interval >= 1) {
            return `${interval} ${unit}${interval === 1 ? '' : 's'} ago`;
        }
    }
    return 'just now';
}

// Format Numbers
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Get Severity Color
function getSeverityColor(severity) {
    const colors = {
        'critical': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#28a745',
        'info': '#17a2b8'
    };
    return colors[severity.toLowerCase()] || '#6c757d';
}

// Get Attack Type Icon
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
        'Ransomware': 'fa-lock',
        'Zero-Day': 'fa-bomb',
        'MITM': 'fa-user-friends',
        'Credential Theft': 'fa-user-shield',
        'Data Exfiltration': 'fa-file-export',
        'IoT Attack': 'fa-microchip',
        'Supply Chain': 'fa-link'
    };
    return icons[attackType] || 'fa-exclamation-triangle';
}

// Get Country Flag (emoji)
function getCountryFlag(countryCode) {
    const flags = {
        'US': '🇺🇸',
        'CN': '🇨🇳',
        'RU': '🇷🇺',
        'DE': '🇩🇪',
        'IN': '🇮🇳',
        'BR': '🇧🇷',
        'JP': '🇯🇵',
        'KR': '🇰🇷',
        'UK': '🇬🇧',
        'FR': '🇫🇷',
        'CA': '🇨🇦',
        'AU': '🇦🇺',
        'SG': '🇸🇬',
        'IL': '🇮🇱',
        'IR': '🇮🇷',
        'KP': '🇰🇵'
    };
    return flags[countryCode] || '🌍';
}

// Generate Random Data
function generateRandomLog() {
    const attackTypes = ['XSS', 'SQL Injection', 'Port Scan', 'Brute Force', 'DDoS', 'Malware', 'Phishing'];
    const severities = ['critical', 'high', 'medium', 'low'];
    const countries = ['US', 'CN', 'RU', 'DE', 'IN', 'BR', 'JP', 'KR', 'UK'];
    const targetSystems = ['web-server-01', 'db-server-01', 'auth-server-01', 'api-gateway', 'firewall-01'];
    
    return {
        id: Date.now() + Math.floor(Math.random() * 1000),
        timestamp: new Date().toISOString(),
        attackType: attackTypes[Math.floor(Math.random() * attackTypes.length)],
        sourceIP: generateIP(),
        targetSystem: targetSystems[Math.floor(Math.random() * targetSystems.length)],
        severity: severities[Math.floor(Math.random() * severities.length)],
        country: countries[Math.floor(Math.random() * countries.length)],
        description: generateRandomLogDescription(),
        isBlocked: Math.random() > 0.3,
        port: Math.floor(Math.random() * 65535),
        protocol: ['TCP', 'UDP', 'HTTP', 'HTTPS'][Math.floor(Math.random() * 4)],
        userAgent: generateRandomUserAgent()
    };
}

function generateRandomLogDescription() {
    const verbs = ['attempted', 'detected', 'prevented', 'blocked', 'logged', 'analyzed', 'escalated'];
    const actions = ['malicious payload injection', 'port scanning activity', 'brute force attempt', 
                    'data exfiltration', 'privilege escalation', 'command injection', 
                    'session hijacking', 'credential stuffing'];
    const locations = ['on login page', 'in database query', 'from external network', 
                      'via API endpoint', 'through file upload', 'using social engineering'];
    
    const verb = verbs[Math.floor(Math.random() * verbs.length)];
    const action = actions[Math.floor(Math.random() * actions.length)];
    const location = locations[Math.floor(Math.random() * locations.length)];
    
    return `${verb} ${action} ${location}`;
}

function generateRandomUserAgent() {
    const browsers = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59'
    ];
    return browsers[Math.floor(Math.random() * browsers.length)];
}

// Get Remediation Suggestions
function getRemediationSuggestions(attackType) {
    const suggestions = {
        'XSS': [
            'Implement Content Security Policy (CSP) headers',
            'Validate and sanitize all user inputs',
            'Use output encoding when displaying user data',
            'Implement proper HTTP headers (X-XSS-Protection, X-Content-Type-Options)',
            'Use modern frameworks that auto-escape XSS by default',
            'Regularly update and patch web application firewalls'
        ],
        'SQL Injection': [
            'Use prepared statements and parameterized queries',
            'Implement stored procedures',
            'Apply principle of least privilege to database accounts',
            'Regularly update and patch database software',
            'Use web application firewalls with SQLi protection',
            'Implement input validation and whitelisting',
            'Use ORM frameworks with built-in protection'
        ],
        'Port Scan': [
            'Configure firewall to block port scanning attempts',
            'Implement intrusion detection systems (IDS)',
            'Use port knocking techniques',
            'Limit exposed ports to essential services only',
            'Monitor network traffic for scanning patterns',
            'Implement rate limiting on connection attempts',
            'Use honeypots to detect scanning activity'
        ],
        'Brute Force': [
            'Implement account lockout policies (3-5 attempts)',
            'Use CAPTCHA after failed login attempts',
            'Enable multi-factor authentication (MFA)',
            'Implement rate limiting on login endpoints',
            'Use strong password policies (12+ characters, special chars)',
            'Monitor for suspicious login patterns',
            'Implement IP blacklisting for repeat offenders'
        ],
        'DDoS': [
            'Use DDoS protection services (Cloudflare, Akamai, AWS Shield)',
            'Implement rate limiting and throttling',
            'Use load balancers to distribute traffic',
            'Configure firewalls to block suspicious traffic',
            'Monitor network traffic patterns',
            'Implement Anycast DNS',
            'Use CDN for static content delivery'
        ],
        'Malware': [
            'Deploy endpoint detection and response (EDR) solutions',
            'Keep all software updated with latest security patches',
            'Use antivirus/anti-malware software',
            'Implement application whitelisting',
            'Regular security awareness training for employees',
            'Network segmentation to limit spread',
            'Regular backups with offline storage'
        ]
    };
    
    return suggestions[attackType] || [
        'Analyze attack pattern and source',
        'Update security rules and policies',
        'Monitor for similar attack patterns',
        'Review and update incident response plan'
    ];
}

// Validation Functions
function isValidIP(ip) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isValidURL(url) {
    try {
        new URL(url);
        return true;
    } catch (e) {
        return false;
    }
}

// Storage Utilities
function saveToLocalStorage(key, data) {
    try {
        localStorage.setItem(key, JSON.stringify(data));
        return true;
    } catch (e) {
        console.error('Error saving to localStorage:', e);
        return false;
    }
}

function loadFromLocalStorage(key) {
    try {
        const data = localStorage.getItem(key);
        return data ? JSON.parse(data) : null;
    } catch (e) {
        console.error('Error loading from localStorage:', e);
        return null;
    }
}

function clearLocalStorage(key = null) {
    try {
        if (key) {
            localStorage.removeItem(key);
        } else {
            localStorage.clear();
        }
        return true;
    } catch (e) {
        console.error('Error clearing localStorage:', e);
        return false;
    }
}

// Cookie Utilities
function setCookie(name, value, days = 7) {
    const date = new Date();
    date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
    const expires = "expires=" + date.toUTCString();
    document.cookie = name + "=" + value + ";" + expires + ";path=/";
}

function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

function deleteCookie(name) {
    setCookie(name, "", -1);
}

// Notification System
function showNotification(message, type = 'info', duration = 5000) {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.custom-notification');
    existingNotifications.forEach(notification => {
        notification.remove();
    });
    
    const notification = document.createElement('div');
    notification.className = `custom-notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas ${getNotificationIcon(type)}"></i>
            <span>${message}</span>
            <button class="notification-close" onclick="this.parentElement.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    // Add styles if not already present
    if (!document.querySelector('#notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = `
            .custom-notification {
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 15px 20px;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                z-index: 9999;
                animation: slideInRight 0.3s ease;
                max-width: 400px;
                font-family: inherit;
            }
            
            .notification-success {
                background: #28a745;
                color: white;
                border-left: 4px solid #1e7e34;
            }
            
            .notification-error {
                background: #dc3545;
                color: white;
                border-left: 4px solid #bd2130;
            }
            
            .notification-warning {
                background: #ffc107;
                color: #212529;
                border-left: 4px solid #d39e00;
            }
            
            .notification-info {
                background: #17a2b8;
                color: white;
                border-left: 4px solid #117a8b;
            }
            
            .notification-content {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            
            .notification-content i:first-child {
                font-size: 18px;
            }
            
            .notification-close {
                background: none;
                border: none;
                color: inherit;
                cursor: pointer;
                margin-left: auto;
                padding: 4px;
                border-radius: 4px;
                opacity: 0.8;
                transition: opacity 0.2s;
            }
            
            .notification-close:hover {
                opacity: 1;
            }
            
            @keyframes slideInRight {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
        `;
        document.head.appendChild(style);
    }
    
    document.body.appendChild(notification);
    
    // Auto-remove after duration
    setTimeout(() => {
        if (notification.parentElement) {
            notification.style.animation = 'slideOutRight 0.3s ease';
            notification.addEventListener('animationend', () => {
                if (notification.parentElement) {
                    notification.remove();
                }
            });
            
            // Add slideOut animation
            if (!document.querySelector('#notification-animations')) {
                const animationStyle = document.createElement('style');
                animationStyle.id = 'notification-animations';
                animationStyle.textContent = `
                    @keyframes slideOutRight {
                        from {
                            transform: translateX(0);
                            opacity: 1;
                        }
                        to {
                            transform: translateX(100%);
                            opacity: 0;
                        }
                    }
                `;
                document.head.appendChild(animationStyle);
            }
        }
    }, duration);
    
    return notification;
}

function getNotificationIcon(type) {
    const icons = {
        'success': 'fa-check-circle',
        'error': 'fa-exclamation-circle',
        'warning': 'fa-exclamation-triangle',
        'info': 'fa-info-circle'
    };
    return icons[type] || 'fa-info-circle';
}

// Debounce and Throttle
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

// Array Utilities
function chunkArray(array, size) {
    const chunks = [];
    for (let i = 0; i < array.length; i += size) {
        chunks.push(array.slice(i, i + size));
    }
    return chunks;
}

function shuffleArray(array) {
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
}

function uniqueArray(array) {
    return [...new Set(array)];
}

// String Utilities
function capitalizeFirst(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

function camelToKebab(str) {
    return str.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase();
}

function kebabToCamel(str) {
    return str.replace(/-([a-z])/g, (g) => g[1].toUpperCase());
}

// DOM Manipulation Utilities
function createElement(tag, attributes = {}, children = []) {
    const element = document.createElement(tag);
    
    // Set attributes
    Object.entries(attributes).forEach(([key, value]) => {
        if (key === 'className') {
            element.className = value;
        } else if (key === 'textContent') {
            element.textContent = value;
        } else if (key === 'innerHTML') {
            element.innerHTML = value;
        } else if (key.startsWith('on')) {
            element.addEventListener(key.substring(2).toLowerCase(), value);
        } else {
            element.setAttribute(key, value);
        }
    });
    
    // Append children
    if (Array.isArray(children)) {
        children.forEach(child => {
            if (child instanceof Node) {
                element.appendChild(child);
            } else if (typeof child === 'string') {
                element.appendChild(document.createTextNode(child));
            }
        });
    }
    
    return element;
}

function removeElement(element) {
    if (element && element.parentNode) {
        element.parentNode.removeChild(element);
    }
}

function toggleElement(element, show) {
    if (element) {
        element.style.display = show ? '' : 'none';
    }
}

// Event Utilities
function addEventDelegate(selector, event, handler) {
    document.addEventListener(event, function(e) {
        if (e.target.matches(selector) || e.target.closest(selector)) {
            handler(e);
        }
    });
}

function preventDefaultHandler(handler) {
    return function(e) {
        e.preventDefault();
        handler(e);
    };
}

// AJAX Utilities (for mock API calls)
async function mockApiCall(endpoint, data = null, method = 'GET', delay = 500) {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            // Simulate successful API call
            const response = {
                status: 'success',
                data: generateMockResponse(endpoint, data),
                timestamp: new Date().toISOString()
            };
            resolve(response);
        }, delay);
    });
}

function generateMockResponse(endpoint, data) {
    switch(endpoint) {
        case '/api/logs':
            return Array.from({ length: 50 }, (_, i) => generateRandomLog());
        case '/api/incidents':
            return Array.from({ length: 10 }, (_, i) => ({
                id: i + 1,
                title: `Incident ${i + 1}`,
                severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
                status: ['open', 'in_progress', 'resolved', 'closed'][Math.floor(Math.random() * 4)],
                createdAt: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString()
            }));
        case '/api/stats':
            return {
                totalLogs: Math.floor(Math.random() * 10000) + 5000,
                activeIncidents: Math.floor(Math.random() * 50) + 10,
                blockedAttacks: Math.floor(Math.random() * 1000) + 500,
                avgResponseTime: (Math.random() * 5 + 1).toFixed(1) + 'h'
            };
        default:
            return { message: 'Mock API response' };
    }
}

// Chart Utilities
function createChartConfig(type, data, options = {}) {
    const defaultOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'top',
                labels: {
                    font: {
                        size: 12
                    }
                }
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
    };
    
    return {
        type: type,
        data: data,
        options: { ...defaultOptions, ...options }
    };
}

// Security Scoring
function calculateThreatScore(severity, frequency, recency) {
    const severityScore = {
        'critical': 100,
        'high': 75,
        'medium': 50,
        'low': 25
    }[severity.toLowerCase()] || 10;
    
    return Math.min(100, Math.floor(severityScore * (1 + frequency * 0.1) * (1 + recency * 0.05)));
}

function getThreatLevel(score) {
    if (score >= 80) return { level: 'Critical', color: '#dc3545' };
    if (score >= 60) return { level: 'High', color: '#fd7e14' };
    if (score >= 40) return { level: 'Medium', color: '#ffc107' };
    if (score >= 20) return { level: 'Low', color: '#28a745' };
    return { level: 'Info', color: '#17a2b8' };
}

// Export all functions
window.utils = {
    // DOM Utilities
    $,
    $$,
    
    // Generation Functions
    generateIP,
    generateMAC,
    generateRandomLog,
    generateRandomLogDescription,
    generateRandomUserAgent,
    
    // Formatting Functions
    formatDate,
    formatTime,
    formatDateTime,
    timeAgo,
    formatNumber,
    formatBytes,
    
    // UI Functions
    getSeverityColor,
    getAttackTypeIcon,
    getCountryFlag,
    getRemediationSuggestions,
    
    // Validation Functions
    isValidIP,
    isValidEmail,
    isValidURL,
    
    // Storage Functions
    saveToLocalStorage,
    loadFromLocalStorage,
    clearLocalStorage,
    setCookie,
    getCookie,
    deleteCookie,
    
    // Notification Functions
    showNotification,
    getNotificationIcon,
    
    // Performance Functions
    debounce,
    throttle,
    
    // Array Functions
    chunkArray,
    shuffleArray,
    uniqueArray,
    
    // String Functions
    capitalizeFirst,
    camelToKebab,
    kebabToCamel,
    
    // DOM Functions
    createElement,
    removeElement,
    toggleElement,
    
    // Event Functions
    addEventDelegate,
    preventDefaultHandler,
    
    // API Functions
    mockApiCall,
    
    // Chart Functions
    createChartConfig,
    
    // Security Functions
    calculateThreatScore,
    getThreatLevel
};

// Initialize utilities when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Add theme detection
    const theme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', theme);
    
    // Initialize tooltips
    initializeTooltips();
    
    // Initialize copy functionality
    initializeCopyButtons();
});

// Initialize tooltips
function initializeTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');
    tooltips.forEach(element => {
        element.addEventListener('mouseenter', showTooltip);
        element.addEventListener('mouseleave', hideTooltip);
    });
}

function showTooltip(e) {
    const tooltipText = this.getAttribute('data-tooltip');
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    tooltip.textContent = tooltipText;
    
    document.body.appendChild(tooltip);
    
    const rect = this.getBoundingClientRect();
    tooltip.style.position = 'fixed';
    tooltip.style.top = (rect.top - tooltip.offsetHeight - 10) + 'px';
    tooltip.style.left = (rect.left + rect.width / 2 - tooltip.offsetWidth / 2) + 'px';
    tooltip.style.zIndex = '10000';
    
    this.tooltipElement = tooltip;
}

function hideTooltip() {
    if (this.tooltipElement) {
        this.tooltipElement.remove();
        this.tooltipElement = null;
    }
}

// Initialize copy buttons
function initializeCopyButtons() {
    document.addEventListener('click', function(e) {
        if (e.target.closest('[data-copy]')) {
            const button = e.target.closest('[data-copy]');
            const textToCopy = button.getAttribute('data-copy');
            
            navigator.clipboard.writeText(textToCopy).then(() => {
                showNotification('Copied to clipboard!', 'success', 2000);
            }).catch(err => {
                showNotification('Failed to copy', 'error', 2000);
            });
        }
    });
}

// Export for global use
window.generateIP = generateIP;
window.formatDate = formatDate;
window.formatTime = formatTime;
window.formatDateTime = formatDateTime;
window.timeAgo = timeAgo;
window.getSeverityColor = getSeverityColor;
window.getAttackTypeIcon = getAttackTypeIcon;
window.showNotification = showNotification;
window.getRemediationSuggestions = getRemediationSuggestions;