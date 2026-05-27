// Utility functions

// Generate random IP address
exports.generateIP = () => {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
};

// Generate random MAC address
exports.generateMAC = () => {
  const hexDigits = "0123456789ABCDEF";
  let mac = "";
  for (let i = 0; i < 6; i++) {
    mac += hexDigits.charAt(Math.floor(Math.random() * 16));
    mac += hexDigits.charAt(Math.floor(Math.random() * 16));
    if (i < 5) mac += ":";
  }
  return mac;
};

// Format date
exports.formatDate = (dateString) => {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
};

// Format time
exports.formatTime = (dateString) => {
  const date = new Date(dateString);
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
};

// Time ago
exports.timeAgo = (dateString) => {
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
};

// Format bytes
exports.formatBytes = (bytes, decimals = 2) => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

// Get severity color
exports.getSeverityColor = (severity) => {
  const colors = {
    'critical': '#dc3545',
    'high': '#fd7e14',
    'medium': '#ffc107',
    'low': '#28a745',
    'info': '#17a2b8'
  };
  return colors[severity.toLowerCase()] || '#6c757d';
};

// Get attack type icon
exports.getAttackTypeIcon = (attackType) => {
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
};

// Get country flag (emoji)
exports.getCountryFlag = (countryCode) => {
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
};

// Validate IP address
exports.isValidIP = (ip) => {
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipRegex.test(ip);
};

// Validate email
exports.isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Generate secure random string
exports.generateSecureId = (length = 16) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  
  if (typeof window !== 'undefined' && window.crypto) {
    const values = new Uint32Array(length);
    window.crypto.getRandomValues(values);
    for (let i = 0; i < length; i++) {
      result += chars[values[i] % chars.length];
    }
  } else {
    // Fallback for Node.js or browsers without crypto support
    for (let i = 0; i < length; i++) {
      result += chars[Math.floor(Math.random() * chars.length)];
    }
  }
  
  return result;
};

// Debounce function
exports.debounce = (func, wait) => {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
};

// Throttle function
exports.throttle = (func, limit) => {
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
};