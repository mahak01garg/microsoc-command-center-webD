(function () {
    const { useEffect, useState } = React;
    const { createRoot } = ReactDOM;

    const routes = {
        login: 'login',
        register: 'register',
        'forgot-password': 'forgot-password',
        dashboard: 'dashboard',
        incidents: 'incidents',
        logs: 'logs',
        alerts: 'alerts',
        analytics: 'analytics',
        'audit-logs': 'audit-logs',
        'user-management': 'user-management',
        settings: 'settings'
    };

    const protectedRoutes = new Set(['dashboard', 'incidents', 'logs', 'alerts', 'analytics', 'audit-logs', 'user-management', 'settings']);
    const loadedExternalScripts = new Set();
    const pages = window.MICROSOC_PAGES || {};
    const LOCAL_API_BASE_URL = 'http://localhost:5001/api';
    const HOSTED_API_BASE_URL = 'https://microsoc-backend.onrender.com/api';
    const NOTIFICATION_BATCH_WINDOW_MS = 5000;
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
    const notificationBatch = {
        alerts: [],
        incidents: [],
        timer: null
    };
    let realtimeSocket = null;
    let realtimeReconnectTimer = null;
    let realtimeReconnectAttempt = 0;
    let realtimeRoot = null;
    let realtimeReconnectEnabled = true;
    let sidebarRepairTimer = null;
    const sidebarObservers = new WeakMap();
    let pageIntegrityObserver = null;

    const isLocalFrontend = ['localhost', '127.0.0.1'].includes(window.location.hostname);
    if (isLocalFrontend) {
        window.MICROSOC_API_BASE_URL = LOCAL_API_BASE_URL;
        localStorage.setItem('microsocUseLocalApi', 'true');
        localStorage.setItem('microsocApiBaseUrl', LOCAL_API_BASE_URL);
    } else {
        window.MICROSOC_API_BASE_URL = localStorage.getItem('microsocApiBaseUrl')
            || (localStorage.getItem('microsocUseLocalApi') === 'true' ? LOCAL_API_BASE_URL : HOSTED_API_BASE_URL);
    }

    function getRouteFromHash() {
        const route = window.location.hash.replace(/^#\/?/, '').split('?')[0];
        return routes[route] ? route : 'login';
    }

    function navigateTo(route) {
        const normalized = String(route || 'login').replace(/\.html$/, '');
        window.location.hash = `#/${routes[normalized] ? normalized : 'login'}`;
    }

    window.navigateTo = navigateTo;

    function updateThemeIcon(theme) {
        const themeIcon = document.querySelector('#theme-icon, .theme-toggle i, [onclick*="toggleTheme"] i');
        if (themeIcon) {
            themeIcon.className = theme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
        }
    }

    function toggleTheme() {
        const currentTheme = localStorage.getItem('theme') === 'light' ? 'light' : 'dark';
        const nextTheme = currentTheme === 'light' ? 'dark' : 'light';
        const themeStyle = document.getElementById('theme-style');

        if (themeStyle) {
            themeStyle.setAttribute('href', `css/${nextTheme}-theme.css?v=20260623t`);
        }

        document.body.dataset.theme = nextTheme;
        document.documentElement.dataset.theme = nextTheme;
        localStorage.setItem('theme', nextTheme);
        updateThemeIcon(nextTheme);
        window.dispatchEvent(new CustomEvent('microsoc:theme-changed', {
            detail: { theme: nextTheme }
        }));
        return nextTheme;
    }

    window.toggleTheme = toggleTheme;

    function patchLegacyNavigation(code) {
        return code
            .replace(/https:\/\/microsoc-backend\.onrender\.com\/api/g, window.MICROSOC_API_BASE_URL)
            .replace(/,\s*startLogStream\(\)\s*(?=\])/g, '')
            .replace(
                /localStorage\.setItem\('user',\s*JSON\.stringify\(user\)\);/g,
                "localStorage.setItem('user', JSON.stringify(user)); localStorage.setItem('token', localStorage.getItem('token') || 'demo-token');"
            )
            .replace(/localStorage\.removeItem\('user'\);/g, "localStorage.removeItem('user'); localStorage.removeItem('token');")
            .replace(/window\.location\.href\s*=\s*['"]login\.html['"]/g, "window.navigateTo('login')")
            .replace(/window\.location\.href\s*=\s*['"]register\.html['"]/g, "window.navigateTo('register')")
            .replace(/window\.location\.href\s*=\s*['"]forgot-password\.html['"]/g, "window.navigateTo('forgot-password')")
            .replace(/window\.location\.href\s*=\s*['"]dashboard\.html['"]/g, "window.navigateTo('dashboard')")
            .replace(/window\.location\.href\s*=\s*['"]incidents\.html['"]/g, "window.navigateTo('incidents')")
            .replace(/window\.location\.href\s*=\s*['"]logs\.html['"]/g, "window.navigateTo('logs')")
            .replace(/window\.location\.href\s*=\s*['"]alerts\.html['"]/g, "window.navigateTo('alerts')")
            .replace(/window\.location\.href\s*=\s*['"]analytics\.html['"]/g, "window.navigateTo('analytics')")
            .replace(/window\.location\.href\s*=\s*['"]settings\.html['"]/g, "window.navigateTo('settings')");
    }

    function exposePageFunctions(code) {
        const names = new Set();
        const functionPattern = /(?:^|\n)\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g;
        let match;

        while ((match = functionPattern.exec(code)) !== null) {
            names.add(match[1]);
        }

        if (!names.size) return code;

        const exposeCode = Array.from(names)
            .map((name) => `try { if (typeof ${name} === 'function') window.${name} = ${name}; } catch (error) {}`)
            .join('\n');

        return `${code}\n\n${exposeCode}`;
    }

    function rewriteLinks(container) {
        container.querySelectorAll('a[href="#"][onclick]').forEach((link) => {
            link.setAttribute('href', 'javascript:void(0)');
        });

        container.querySelectorAll('a[href$=".html"]').forEach((link) => {
            const route = link.getAttribute('href').replace(/\.html$/, '');
            if (routes[route]) {
                link.setAttribute('href', `#/${route}`);
            }
        });
    }

    function ensureActionHandlers(container) {
        container.querySelectorAll('[onclick], [onchange]').forEach((element) => {
            const handler = element.getAttribute('onclick') || element.getAttribute('onchange') || '';
            const match = handler.match(/^\s*([A-Za-z_$][\w$]*)\s*\(/);
            if (!match || typeof window[match[1]] === 'function') return;

            const missingName = match[1];
            window[missingName] = function () {
                const message = `Action "${missingName}" is not connected yet.`;
                if (typeof window.showNotification === 'function') {
                    window.showNotification(message, 'warning');
                } else {
                    alert(message);
                }
            };
        });
    }

    function escapeToastHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function installStackedNotificationSystem() {
        if (!document.querySelector('#microsoc-stacked-toast-styles')) {
            const style = document.createElement('style');
            style.id = 'microsoc-stacked-toast-styles';
            style.textContent = `
                .toast-stack {
                    position: fixed;
                    top: 18px;
                    right: 18px;
                    z-index: 2147483000;
                    display: flex;
                    flex-direction: column;
                    gap: 10px;
                    width: min(420px, calc(100vw - 24px));
                    pointer-events: none;
                }

                .toast-stack .custom-notification {
                    position: relative;
                    top: auto;
                    right: auto;
                    width: 100%;
                    pointer-events: auto;
                    color: var(--toast-text, #f8fafc);
                    background: var(--toast-bg, rgba(15, 23, 42, 0.96));
                    border: 1px solid var(--toast-border, rgba(148, 163, 184, 0.22));
                    box-shadow: var(--toast-shadow, 0 18px 40px rgba(2, 6, 23, 0.28));
                }

                .toast-stack .custom-notification .toast-copy strong {
                    color: var(--toast-title, currentColor);
                }

                .toast-stack .custom-notification .toast-copy span,
                .toast-stack .custom-notification .toast-copy small {
                    color: var(--toast-copy, currentColor);
                }

                .toast-stack .custom-notification .toast-close {
                    color: var(--toast-close, currentColor);
                }

                .toast-stack .custom-notification.notification-log {
                    --toast-bg: linear-gradient(135deg, rgba(8, 47, 73, 0.98), rgba(14, 116, 144, 0.95));
                    --toast-border: rgba(34, 211, 238, 0.5);
                    --toast-icon-bg: rgba(34, 211, 238, 0.18);
                    --toast-icon-color: #67e8f9;
                    border-left: 5px solid #22d3ee;
                }

                .toast-stack .custom-notification.notification-log .toast-icon {
                    background: var(--toast-icon-bg);
                    color: var(--toast-icon-color);
                }

                .toast-stack .custom-notification.notification-alert {
                    --toast-bg: linear-gradient(135deg, rgba(69, 26, 3, 0.98), rgba(154, 52, 18, 0.95));
                    --toast-border: rgba(251, 146, 60, 0.55);
                    --toast-icon-bg: rgba(251, 146, 60, 0.2);
                    --toast-icon-color: #fed7aa;
                    border-left: 5px solid #fb923c;
                }

                .toast-stack .custom-notification.notification-alert .toast-icon {
                    background: var(--toast-icon-bg);
                    color: var(--toast-icon-color);
                }

                .toast-stack .custom-notification.notification-incident {
                    --toast-bg: linear-gradient(135deg, rgba(20, 83, 45, 0.98), rgba(15, 118, 110, 0.95));
                    --toast-border: rgba(45, 212, 191, 0.55);
                    --toast-icon-bg: rgba(45, 212, 191, 0.2);
                    --toast-icon-color: #99f6e4;
                    border-left: 5px solid #2dd4bf;
                }

                .toast-stack .custom-notification.notification-incident .toast-icon {
                    background: var(--toast-icon-bg);
                    color: var(--toast-icon-color);
                }

                body[data-theme="light"] .toast-stack .custom-notification,
                html[data-theme="light"] .toast-stack .custom-notification {
                    --toast-text: #0f172a;
                    --toast-title: #0f172a;
                    --toast-copy: #334155;
                    --toast-close: #475569;
                    --toast-shadow: 0 18px 38px rgba(15, 23, 42, 0.14);
                }

                body[data-theme="light"] .toast-stack .custom-notification.notification-log,
                html[data-theme="light"] .toast-stack .custom-notification.notification-log {
                    --toast-bg: linear-gradient(135deg, #ecfeff, #ffffff);
                    --toast-border: rgba(8, 145, 178, 0.28);
                    --toast-icon-bg: rgba(8, 145, 178, 0.12);
                    --toast-icon-color: #0e7490;
                    border-left-color: #0891b2;
                }

                body[data-theme="light"] .toast-stack .custom-notification.notification-alert,
                html[data-theme="light"] .toast-stack .custom-notification.notification-alert {
                    --toast-bg: linear-gradient(135deg, #fff7ed, #ffffff);
                    --toast-border: rgba(234, 88, 12, 0.28);
                    --toast-icon-bg: rgba(234, 88, 12, 0.12);
                    --toast-icon-color: #c2410c;
                    border-left-color: #ea580c;
                }

                body[data-theme="light"] .toast-stack .custom-notification.notification-incident,
                html[data-theme="light"] .toast-stack .custom-notification.notification-incident {
                    --toast-bg: linear-gradient(135deg, #ecfdf5, #ffffff);
                    --toast-border: rgba(13, 148, 136, 0.28);
                    --toast-icon-bg: rgba(13, 148, 136, 0.12);
                    --toast-icon-color: #0f766e;
                    border-left-color: #0d9488;
                }
            `;
            document.head.appendChild(style);
        }

        window.showNotification = function (message, type = 'info', options = {}) {
            let stack = document.getElementById('toast-stack');
            if (!stack) {
                stack = document.createElement('div');
                stack.id = 'toast-stack';
                stack.className = 'toast-stack';
                document.body.appendChild(stack);
            }

            const notification = document.createElement('div');
            const kind = String(options.kind || '').toLowerCase();
            const kindClass = ['log', 'alert', 'incident'].includes(kind) ? ` notification-${kind}` : '';
            notification.className = `custom-notification notification-${type}${kindClass}`;
            const icons = {
                success: 'fa-check-circle',
                error: 'fa-shield-virus',
                warning: 'fa-exclamation-triangle',
                info: 'fa-info-circle'
            };
            const icon = icons[type] || icons.info;
            const title = options.title || (type === 'error' ? 'Security Alert' : 'MicroSOC');
            const meta = options.meta ? `<small>${escapeToastHtml(options.meta)}</small>` : '';

            notification.innerHTML = `
                <div class="toast-icon"><i class="fas ${icon}"></i></div>
                <div class="toast-copy">
                    <strong>${escapeToastHtml(title)}</strong>
                    <span>${escapeToastHtml(message)}</span>
                    ${meta}
                </div>
                <button class="toast-close" onclick="this.closest('.custom-notification').remove()" aria-label="Close notification">&times;</button>
            `;

            stack.appendChild(notification);
            window.setTimeout(() => {
                if (notification.parentElement) {
                    notification.classList.add('leaving');
                    notification.remove();
                }
            }, Number(options.duration) || 8000);
        };
    }

    function enhanceSecurityUi(route) {
        const mainContent = document.querySelector('.main-content');
        installStackedNotificationSystem();
        installNotificationDropdown();
        closeRealtimeFeed();
        if (!mainContent) {
            document.querySelector('.ai-assistant')?.remove();
            return;
        }

        syncRouteChrome(route, mainContent);
        if (route !== 'audit-logs') {
            installRouteTabs(mainContent, route);
        }
        installSidebarCollapseToggle();
        ensureAlertsSidebarLink(route);
        reorderSidebarNavigation();
        renderSidebarNavigation(document.getElementById('legacy-page') || document);
        scheduleSidebarRepair(document.getElementById('legacy-page') || document);
        installAIAssistant(route);
        syncUserManagementPanel(route);
        ensureDefenseBanner(mainContent, route);
        if (route === 'audit-logs') return;
        if (document.querySelector('.threat-ribbon')) return;

        const ribbon = document.createElement('div');
        ribbon.className = 'threat-ribbon';
        ribbon.innerHTML = `
            <span><i class="fas fa-shield-virus"></i> Threat Level: Elevated</span>
            <span><i class="fas fa-satellite-dish"></i> Sensors: Online</span>
            <span><i class="fas fa-fingerprint"></i> Identity Guard: Active</span>
            <span><i class="fas fa-bolt"></i> ${route.toUpperCase()} Console</span>
        `;
        mainContent.insertBefore(ribbon, mainContent.firstChild);

        document.querySelectorAll('.card').forEach((card, index) => {
            if (card.dataset.secured) return;
            card.dataset.secured = 'true';
            const tag = document.createElement('span');
            tag.className = 'security-card-tag';
            tag.textContent = `SEC-${String(index + 1).padStart(2, '0')}`;
            card.appendChild(tag);
        });
    }

    function syncRouteChrome(route, mainContent) {
        const routeChrome = {
            dashboard: {
                icon: 'fa-tachometer-alt',
                title: 'Dashboard Overview',
                subtitle: 'Real-time security monitoring of the Morphin Grid'
            },
            logs: {
                icon: 'fa-stream',
                title: 'Security Logs',
                subtitle: 'Real-time monitoring and analysis of security events'
            },
            alerts: {
                icon: 'fa-bell',
                title: 'Threat Detection & Alerts',
                subtitle: 'Persistent alert queue, lifecycle actions, and evidence-backed detections.'
            },
            incidents: {
                icon: 'fa-exclamation-triangle',
                title: 'Incident Management',
                subtitle: 'Monitor and manage security incidents'
            },
            analytics: {
                icon: 'fa-chart-line',
                title: 'Security Analytics',
                subtitle: 'Advanced threat intelligence and pattern analysis'
            },
            settings: {
                icon: 'fa-cogs',
                title: 'Settings',
                subtitle: 'Threat thresholds, alert rules, and system configs'
            },
            'user-management': {
                icon: 'fa-users-cog',
                title: 'User Management',
                subtitle: 'View every user in MicroSOC and control access instantly.'
            },
            'audit-logs': {
                icon: 'fa-clipboard-list',
                title: 'Audit Logs',
                subtitle: 'Review admin actions, system events, and security changes.'
            }
        };

        const chrome = routeChrome[route];
        const header = mainContent.querySelector(':scope > .main-header');
        if (header && chrome) {
            const title = header.querySelector('.header-left h1');
            const subtitle = header.querySelector('.header-left .subtitle');
            if (title) title.innerHTML = `<i class="fas ${chrome.icon}"></i> ${chrome.title}`;
            if (subtitle) subtitle.textContent = chrome.subtitle;
        }

        if (route === 'alerts') {
            mainContent.querySelector('#incidents-table')?.closest('.content-grid')?.remove();
            mainContent.querySelector('#new-incident-modal')?.remove();
            mainContent.querySelector('.main-header .filter-controls')?.remove();
            mainContent.querySelector('.main-header button[onclick*="openNewIncidentModal"]')?.remove();
        }
    }

    function installSidebarCollapseToggle() {
        const sidebar = document.getElementById('sidebar') || document.querySelector('.sidebar');
        const mainContent = document.querySelector('.main-content');
        const header = sidebar?.querySelector('.sidebar-header');
        if (!sidebar || !mainContent || !header) return;

        document.body.classList.toggle('sidebar-collapsed', localStorage.getItem('microsocSidebarCollapsed') === 'true');

        let button = header.querySelector('[data-sidebar-collapse]');
        if (!button) {
            button = document.createElement('button');
            button.type = 'button';
            button.className = 'sidebar-collapse-toggle';
            button.dataset.sidebarCollapse = 'true';
            button.setAttribute('aria-label', 'Toggle sidebar');
            header.appendChild(button);
        }

        const renderButton = () => {
            const collapsed = document.body.classList.contains('sidebar-collapsed');
            button.setAttribute('aria-expanded', String(!collapsed));
            button.innerHTML = `<i class="fas ${collapsed ? 'fa-angles-right' : 'fa-angles-left'}"></i>`;
        };

        if (!button.dataset.bound) {
            button.dataset.bound = 'true';
            button.addEventListener('click', () => {
                const collapsed = document.body.classList.toggle('sidebar-collapsed');
                localStorage.setItem('microsocSidebarCollapsed', String(collapsed));
                renderButton();
            });
        }

        renderButton();
    }

    function installRouteTabs(mainContent) {
        mainContent?.querySelectorAll('.soc-route-tabs').forEach(tabs => tabs.remove());
        document.querySelectorAll('.soc-route-tabs').forEach(tabs => tabs.remove());
    }

    function ensureAlertsSidebarLink(route) {
        const sidebarNav = document.querySelector('.sidebar-nav ul');
        if (!sidebarNav || sidebarNav.querySelector('[data-sidebar-route="alerts"]')) return;

        const item = document.createElement('li');
        item.dataset.sidebarRoute = 'alerts';
        if (route === 'alerts') item.classList.add('active');
        item.innerHTML = `
            <a href="#/alerts">
                <i class="fas fa-bell"></i>
                <span>Alerts</span>
            </a>
        `;

        const analyticsItem = sidebarNav.querySelector('a[href="analytics.html"]')?.closest('li');
        if (analyticsItem) {
            sidebarNav.insertBefore(item, analyticsItem);
        } else {
            sidebarNav.appendChild(item);
        }
    }

    function flushNotificationBatch() {
        const alerts = notificationBatch.alerts.splice(0);
        const incidents = notificationBatch.incidents.splice(0);

        if (alerts.length && typeof window.showNotification === 'function') {
            alerts.forEach((item, index) => {
                const severity = String(item.severity).toLowerCase();
                const type = severity === 'critical' ? 'error' : severity === 'high' ? 'warning' : 'info';
                const message = item.message || item.description || item.title || 'Security alert detected';
                window.setTimeout(() => {
                    window.showNotification(message, type, {
                        title: item.title || 'Threat Alert',
                        meta: [item.attackType, item.sourceIP, item.targetSystem].filter(Boolean).join(' | ')
                    });
                }, index * 120);
            });
        }

        if (incidents.length && typeof window.showNotification === 'function') {
            incidents.forEach((item, index) => {
                const severity = String(item.severity).toLowerCase();
                const type = severity === 'critical' ? 'error' : severity === 'high' ? 'warning' : 'info';
                const message = item.title || 'Incident created';
                window.setTimeout(() => {
                    window.showNotification(message, type, {
                        title: 'Incident Created',
                        meta: [item.status, item.severity, item.sourceIP].filter(Boolean).join(' | ')
                    });
                }, index * 120);
            });
        }

        notificationBatch.timer = null;
    }

    function queueNotificationBatch(kind, payload) {
        notificationBatch[kind].push(payload);
        clearTimeout(notificationBatch.timer);
        notificationBatch.timer = setTimeout(flushNotificationBatch, NOTIFICATION_BATCH_WINDOW_MS);
    }

    function severityToNotificationType(severity) {
        const value = String(severity || '').toLowerCase();
        if (value === 'critical') return 'error';
        if (value === 'high' || value === 'medium') return 'warning';
        return 'info';
    }

    function notifySecurityLog(log = {}) {
        if (typeof window.showNotification !== 'function') return;
        const severity = String(log.severity || 'info').toUpperCase();
        const message = `${severity} ${log.attackType || 'Security log'} from ${log.sourceIP || 'unknown source'}`;
        window.showNotification(message, severityToNotificationType(log.severity), {
            title: 'Security Log',
            kind: 'log',
            meta: [log.targetSystem, log.protocol, log.port ? `Port ${log.port}` : '', log.country].filter(Boolean).join(' | ')
        });
    }

    function notifyAlert(alert = {}) {
        if (typeof window.showNotification !== 'function') return;
        window.showNotification(
            alert.message || alert.description || alert.title || 'Security alert detected',
            severityToNotificationType(alert.severity),
            {
                title: alert.title || 'Threat Alert',
                kind: 'alert',
                meta: [alert.attackType, alert.sourceIP, alert.targetSystem].filter(Boolean).join(' | ')
            }
        );
    }

    function notifyIncident(incident = {}, eventType = 'incident:new') {
        if (typeof window.showNotification !== 'function') return;
        window.showNotification(
            incident.title || 'Incident created',
            severityToNotificationType(incident.severity),
            {
                title: eventType === 'incident:updated' ? 'Incident Updated' : 'Incident Created',
                kind: 'incident',
                meta: [incident.status, incident.severity, incident.sourceIP].filter(Boolean).join(' | ')
            }
        );
    }

    function getRealtimeFeedUrl() {
        try {
            const apiUrl = new URL(window.MICROSOC_API_BASE_URL);
            const wsProtocol = apiUrl.protocol === 'https:' ? 'wss:' : 'ws:';
            return `${wsProtocol}//${apiUrl.host}/ws/threat-feed`;
        } catch (error) {
            console.warn('Realtime feed URL could not be built:', error);
            return null;
        }
    }

    function getRealtimeRoot() {
        return realtimeRoot || document.getElementById('legacy-page') || document;
    }

    function closeRealtimeFeed() {
        realtimeReconnectEnabled = false;
        clearTimeout(realtimeReconnectTimer);
        realtimeReconnectTimer = null;
        realtimeReconnectAttempt = 0;

        if (realtimeSocket) {
            try {
                realtimeSocket.close();
            } catch (error) {
                // Ignore socket shutdown errors during route changes or logout.
            }
        }

        realtimeSocket = null;
    }

    function scheduleRealtimeReconnect() {
        if (realtimeReconnectTimer) return;

        const delay = Math.min(15000, 1000 * Math.max(1, realtimeReconnectAttempt + 1));
        realtimeReconnectAttempt += 1;
        realtimeReconnectTimer = setTimeout(() => {
            realtimeReconnectTimer = null;
            connectRealtimeFeed();
        }, delay);
    }

    function handleRealtimePayload(payload) {
        const root = getRealtimeRoot();

        if (payload?.type === 'alert:new' && payload.alert) {
            notifyAlert(payload.alert);
            refreshLiveCounts(root);
            return;
        }

        if ((payload?.type === 'incident:new' || payload?.type === 'incident:updated') && payload.incident) {
            notifyIncident(payload.incident, payload.type);
            refreshLiveCounts(root);
            return;
        }

        if (payload?.type === 'new-log' && payload.log) {
            notifySecurityLog(payload.log);
            refreshLiveCounts(root);
            return;
        }

        if (payload?.type === 'stats:updated') {
            refreshLiveCounts(root);
        }
    }

    function connectRealtimeFeed(root = document.getElementById('legacy-page') || document) {
        realtimeRoot = root || document;
        realtimeReconnectEnabled = true;

        if (realtimeSocket && (realtimeSocket.readyState === WebSocket.OPEN || realtimeSocket.readyState === WebSocket.CONNECTING)) {
            return;
        }

        const wsUrl = getRealtimeFeedUrl();
        if (!wsUrl) return;

        try {
            realtimeSocket = new WebSocket(wsUrl);
        } catch (error) {
            console.warn('Realtime feed connection failed to start:', error);
            scheduleRealtimeReconnect();
            return;
        }

        realtimeSocket.addEventListener('open', () => {
            realtimeReconnectAttempt = 0;
            clearTimeout(realtimeReconnectTimer);
            realtimeReconnectTimer = null;
            refreshLiveCounts(getRealtimeRoot());
        });

        realtimeSocket.addEventListener('message', (event) => {
            try {
                const payload = JSON.parse(event.data);
                handleRealtimePayload(payload);
            } catch (error) {
                console.warn('Realtime feed message parse failed:', error);
            }
        });

        realtimeSocket.addEventListener('close', () => {
            realtimeSocket = null;
            if (realtimeReconnectEnabled) {
                scheduleRealtimeReconnect();
            }
        });

        realtimeSocket.addEventListener('error', () => {
            // The close handler manages reconnect timing.
        });
    }

    function reorderSidebarNavigation() {
        const sidebarNav = document.querySelector('.sidebar-nav ul');
        if (!sidebarNav) return;

        const role = getCurrentUserRole();
        const desiredOrder = role === 'admin'
            ? ['dashboard', 'logs', 'alerts', 'incidents', 'analytics', 'audit-logs', 'user-management', 'settings']
            : ['dashboard', 'logs', 'alerts', 'incidents', 'analytics'];
        const items = Array.from(sidebarNav.querySelectorAll('li'));
        const mapped = new Map();

        items.forEach((item) => {
            const href = item.querySelector('a')?.getAttribute('href') || '';
            const key = href.includes('dashboard')
                ? 'dashboard'
                : href.includes('logs')
                    ? 'logs'
                    : href.includes('alerts')
                        ? 'alerts'
                        : href.includes('incidents')
                            ? 'incidents'
                            : href.includes('analytics')
                                ? 'analytics'
                                : href.includes('audit-logs')
                                    ? 'audit-logs'
                                : href.includes('user-management')
                                    ? 'user-management'
                                : href.includes('theme') || href === '#'
                                    ? 'theme'
                                    : href.includes('logout')
                                        ? 'logout'
                                        : null;
            if (key) mapped.set(key, item);
        });

        const themeItem = items.find((item) => item.querySelector('a[onclick*="toggleTheme"]'));
        const logoutItem = items.find((item) => item.querySelector('a[onclick*="logout"]'));
        const nextItems = desiredOrder.map((key) => mapped.get(key)).filter(Boolean);

        sidebarNav.innerHTML = '';
        nextItems.forEach((item) => sidebarNav.appendChild(item));
        if (themeItem) sidebarNav.appendChild(themeItem);
        if (logoutItem) sidebarNav.appendChild(logoutItem);
    }

    function installAIAssistant(route) {
        if (!protectedRoutes.has(route) || document.querySelector('.ai-assistant')) return;

        const assistant = document.createElement('section');
        assistant.className = 'ai-assistant collapsed';
        assistant.innerHTML = `
            <button type="button" class="ai-assistant-toggle" aria-label="Open AI SOC Assistant">
                <i class="fas fa-robot"></i>
            </button>
            <div class="ai-assistant-panel">
                <div class="ai-assistant-header">
                    <div>
                        <strong>AI SOC Assistant</strong>
                        <span>Ask for triage, reports, or next actions</span>
                    </div>
                    <button type="button" class="ai-assistant-close" aria-label="Close AI SOC Assistant">&times;</button>
                </div>
                <div class="ai-assistant-messages" id="ai-assistant-messages">
                    <div class="ai-message assistant">Ready. Ask me what to prioritize, summarize, or investigate.</div>
                </div>
                <form class="ai-assistant-form">
                    <input type="text" name="message" autocomplete="off" placeholder="Ask MicroSOC AI..." />
                    <button type="submit" aria-label="Send"><i class="fas fa-paper-plane"></i></button>
                </form>
            </div>
        `;

        document.body.appendChild(assistant);

        const toggle = assistant.querySelector('.ai-assistant-toggle');
        const close = assistant.querySelector('.ai-assistant-close');
        const form = assistant.querySelector('.ai-assistant-form');
        const input = assistant.querySelector('input[name="message"]');
        const messages = assistant.querySelector('.ai-assistant-messages');

        toggle.addEventListener('click', () => {
            assistant.classList.remove('collapsed');
            input.focus();
        });

        close.addEventListener('click', () => assistant.classList.add('collapsed'));

        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            const message = input.value.trim();
            if (!message) return;

            appendAIMessage(messages, message, 'user');
            input.value = '';
            const thinking = appendAIMessage(messages, 'Thinking...', 'assistant');

            try {
                const response = await fetch(`${window.MICROSOC_API_BASE_URL}/ai/chat`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
                    },
                    body: JSON.stringify({
                        message,
                        context: {
                            route,
                            user: JSON.parse(localStorage.getItem('user') || 'null'),
                            currentTime: new Date().toISOString()
                        }
                    })
                });
                const payload = await parseAssistantResponse(response);
                if (!response.ok || !payload.success) {
                    throw new Error(payload.detail || payload.message || 'Assistant failed');
                }

                const data = payload.data || {};
                const answer = data.answer || data.summary || JSON.stringify(data);
                const nextActions = Array.isArray(data.nextActions) && data.nextActions.length
                    ? `\n\nNext: ${data.nextActions.join(' | ')}`
                    : '';
                thinking.textContent = `${answer}${nextActions}`;
            } catch (error) {
                console.error('AI assistant failed:', error);
                const errorText = String(error.message || '').toLowerCase();
                thinking.textContent = errorText.includes('provider rejected')
                    ? 'AI provider rejected the request. Please check backend AI key/model configuration, then try again.'
                    : (error.message || 'MicroSOC AI could not respond right now.');
            }
        });
    }

    async function parseAssistantResponse(response) {
        const contentType = response.headers.get('content-type') || '';
        const bodyText = await response.text();
        if (!contentType.includes('application/json') || /^\s*</.test(bodyText)) {
            return {
                success: false,
                message: response.status === 401
                    ? 'Your login session expired. Please login again.'
                    : 'Assistant backend returned a non-JSON response.'
            };
        }
        try {
            return JSON.parse(bodyText);
        } catch (error) {
            return { success: false, message: 'Assistant backend returned invalid JSON.' };
        }
    }

    function appendAIMessage(container, text, role) {
        const message = document.createElement('div');
        message.className = `ai-message ${role}`;
        message.textContent = text;
        container.appendChild(message);
        container.scrollTop = container.scrollHeight;
        return message;
    }

    function sanitizeAuthPage(route, root) {
        if (!['login', 'register'].includes(route) || !root) return;

        const authShell = root.querySelector('.login-container');
        if (authShell) {
            authShell.dataset.authScreen = route;
        }

        root.querySelectorAll('.demo-credentials').forEach((block) => block.remove());

        if (route === 'login') {
            const emailInput = root.querySelector('#email');
            const passwordInput = root.querySelector('#password');
            if (emailInput) {
                emailInput.value = '';
                emailInput.setAttribute('autocomplete', 'username');
                emailInput.placeholder = 'admin@company.com';
            }
            if (passwordInput) {
                passwordInput.value = '';
                passwordInput.setAttribute('autocomplete', 'current-password');
                passwordInput.placeholder = 'Enter secure passphrase';
            }
        }

        if (route === 'register') {
            const roleSelect = root.querySelector('#role');
            if (roleSelect) {
                roleSelect.innerHTML = '<option value="analyst">Security Analyst</option>';
                roleSelect.value = 'analyst';
            }
        }
    }

    function syncCurrentUserUi(root) {
        if (!root) return;

        let user = null;
        try {
            user = JSON.parse(localStorage.getItem('user') || 'null');
        } catch (error) {
            user = null;
        }

        if (!user) return;

        const role = user.role || 'analyst';
        const displayRole = role.charAt(0).toUpperCase() + role.slice(1);

        root.querySelectorAll('#user-name, .user-name').forEach((element) => {
            element.textContent = user.name || 'User';
        });

        root.querySelectorAll('#user-role, .user-role').forEach((element) => {
            element.textContent = element.id === 'user-role' ? displayRole : displayRole;
        });

        root.querySelectorAll('#user-email, .user-email').forEach((element) => {
            element.textContent = user.email || '';
        });

        const profileName = root.querySelector('#profile-name');
        const profileRole = root.querySelector('#profile-role');
        const profileEmail = root.querySelector('#profile-email');

        if (profileName) profileName.textContent = user.name || 'User';
        if (profileRole) profileRole.textContent = `Role: ${displayRole}`;
        if (profileEmail) profileEmail.textContent = `Email: ${user.email || 'Not available'}`;
        renderSidebarNavigation(root);
        scheduleSidebarRepair(root);
    }

    function getCurrentUserRole() {
        return String(currentUser().role || 'analyst').trim().toLowerCase();
    }

    function showFeatureUnavailable(featureName) {
        const message = `${featureName} is coming soon.`;
        if (typeof window.showNotification === 'function') {
            window.showNotification(message, 'warning');
        } else {
            window.alert(message);
        }
    }

    function buildProtectedShell(title, activeRoute) {
        const active = (routeKey) => routeKey === activeRoute ? 'active' : '';
        const role = getCurrentUserRole();
        const items = ROLE_NAVIGATION[role] || ROLE_NAVIGATION.analyst;
        const navItems = items.map((item) => {
            const badge = item.badge
                ? `<span class="badge ${item.badge.className}" id="${item.badge.id}">0</span>`
                : '';
            const adminFeatureAttr = item.key === 'audit-logs' || item.key === 'user-management' || item.key === 'settings'
                ? ` data-admin-feature="${item.key}"`
                : '';
            return `<li class="${active(item.key)}"><a href="${item.href}"${adminFeatureAttr}><i class="fas ${item.icon}"></i><span>${item.label}</span>${badge}</a></li>`;
        }).join('');
        return {
            title,
            bodyClass: '',
            body: `
                <div class="sidebar" id="sidebar">
                    <div class="sidebar-header">
                        <div class="logo">
                            <i class="fas fa-shield-alt"></i>
                            <h2>MicroSOC</h2>
                        </div>
                        <button class="sidebar-toggle" onclick="toggleSidebar()">
                            <i class="fas fa-bars"></i>
                        </button>
                    </div>
                    <div class="user-info">
                        <div class="avatar">
                            <i class="fas fa-user-secret"></i>
                        </div>
                        <div class="user-details">
                            <h3 id="user-name">Loading...</h3>
                            <p id="user-role">Loading...</p>
                            <p id="user-email" style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">Loading...</p>
                        </div>
                    </div>
                    <nav class="sidebar-nav">
                        <ul>
                            ${navItems}
                            <li><a href="javascript:void(0)" onclick="toggleTheme(); return false;"><i class="fas fa-moon" id="theme-icon"></i><span>Theme</span></a></li>
                            <li><a href="#" onclick="logout()"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a></li>
                        </ul>
                    </nav>
                </div>
                <div class="main-content" id="main-content">
                    <header class="main-header">
                        <div class="header-left">
                            <h1><i class="fas fa-clipboard-list"></i> Audit Logs</h1>
                            <p class="subtitle">User actions and system accountability</p>
                        </div>
                    </header>
                </div>
            `
        };
    }

    function ensureDefenseBanner(mainContent, route) {
        if (!mainContent) return;

        const panel = document.getElementById('user-management-panel');
        const host = panel || mainContent;
        let banner = host.querySelector('.defense-banner') || mainContent.querySelector('.defense-banner');

        if (!banner) {
            banner = document.createElement('div');
            banner.className = 'defense-banner';
            banner.setAttribute('aria-hidden', 'true');
            banner.textContent = 'LIVE DEFENSE GRID  //  INTRUSION MONITORING ACTIVE  //  ZERO TRUST WATCH';
        }

        const anchor = panel
            ? host.querySelector('.feature-panel-header')
            : host.querySelector('.main-header');

        if (anchor) {
            anchor.insertAdjacentElement('afterend', banner);
        } else {
            host.insertBefore(banner, host.firstChild);
        }
    }

    function syncUserManagementPanel(route) {
        const panel = document.getElementById('user-management-panel');
        if (route === 'user-management') {
            if (!panel) {
                openUserManagementModal().catch((error) => {
                    console.error('Failed to open User Management panel:', error);
                });
            }
            return;
        }

        if (panel) {
            closeUserManagementModal();
        } else {
            restoreMainContentView();
        }
    }

    function setExclusiveMainContentView(panel) {
        const mainContent = document.querySelector('.main-content');
        if (!mainContent) return;
        document.body.classList.add('user-management-open');

        Array.from(mainContent.children).forEach((child) => {
            if (child === panel) return;
            if (!child.dataset.userManagementHidden) {
                child.dataset.userManagementHidden = 'true';
                child.hidden = true;
            }
        });
    }

    function restoreMainContentView() {
        const mainContent = document.querySelector('.main-content');
        if (!mainContent) return;
        document.body.classList.remove('user-management-open');

        Array.from(mainContent.children).forEach((child) => {
            if (child.dataset.userManagementHidden !== 'true') return;
            child.hidden = false;
            delete child.dataset.userManagementHidden;
        });
    }

    function ensureUserManagementModal() {
        let panel = document.getElementById('user-management-panel');
        if (panel) return panel;

        const host = findContentHost(document.querySelector('.legacy-page-root') || document);
        if (!host) return null;
        const role = currentUser().role || 'analyst';

        panel = document.createElement('section');
        panel.id = 'user-management-panel';
        panel.className = 'feature-panel feature-user-management';
        panel.innerHTML = `
            <div class="threat-ribbon">
                <span><i class="fas fa-shield-virus"></i> Threat Level: Elevated</span>
                <span><i class="fas fa-satellite-dish"></i> Sensors: Online</span>
                <span><i class="fas fa-fingerprint"></i> Identity Guard: Active</span>
                <span><i class="fas fa-bolt"></i> USER MANAGEMENT Console</span>
            </div>
            <div class="role-dashboard-strip ${role}">
                <div>
                    <strong>${role === 'admin' ? 'Admin Command View' : 'Analyst Triage View'}</strong>
                    <span>${role === 'admin' ? 'User approvals, access control, and policy management are enabled.' : 'Focused view for user visibility and limited access operations.'}</span>
                </div>
                <div class="role-actions">
                    <span><i class="fas fa-user-shield"></i> ${role.toUpperCase()}</span>
                    <span><i class="fas fa-users-cog"></i> User Controls</span>
                    ${role === 'admin' ? '<span><i class="fas fa-lock-open"></i> Admin controls enabled</span>' : '<span><i class="fas fa-lock"></i> Admin controls hidden</span>'}
                </div>
            </div>
            <div class="feature-panel-header">
                <div>
                    <h2 style="font-size:26px;font-weight:900;line-height:1.1;"><i class="fas fa-users-cog"></i> User Management</h2>
                    <p>View every user in MicroSOC and control access instantly.</p>
                </div>
                <div class="user-management-actions">
                    <button type="button" class="btn btn-outline" id="user-management-refresh">
                        <i class="fas fa-sync"></i> Refresh
                    </button>
                </div>
            </div>
            <div class="user-management-toolbar">
                <div class="user-management-searchbox">
                    <i class="fas fa-search"></i>
                    <input type="text" id="user-management-search" placeholder="Search name, email, role...">
                </div>
            </div>
            <div id="user-management-sections" class="user-management-sections">
                <div class="table-responsive">
                    <table class="data-table user-management-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Status</th>
                                <th>Last Login</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="user-management-body">
                            <tr><td colspan="6">Loading users...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        `;
        host.insertAdjacentElement('afterbegin', panel);
        setExclusiveMainContentView(panel);
        panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        return panel;
    }

    function closeUserManagementModal() {
        document.getElementById('user-management-panel')?.remove();
        restoreMainContentView();
    }

    function renderUserManagementUserRow(user) {
        const normalizedRole = String(user.role || 'analyst').trim().toLowerCase();
        const approvalStatus = String(user.approvalStatus || 'pending').trim().toLowerCase();
        const isAdmin = normalizedRole === 'admin';
        const isApproved = approvalStatus === 'approved';
        const isRejected = approvalStatus === 'rejected';
        const isActive = Boolean(user.isActive);
        const statusLabel = isAdmin
            ? 'Admin'
            : isApproved
                ? (isActive ? 'Approved' : 'Disabled')
                : isRejected
                    ? 'Rejected'
                    : 'Pending';
        const statusClass = isAdmin
            ? 'badge-info'
            : isApproved
                ? (isActive ? 'badge-success' : 'badge-warning')
                : isRejected
                    ? 'badge-danger'
                    : 'badge-warning';

        let actionsHtml = '<span class="badge badge-info">Protected Admin</span>';
        if (!isAdmin) {
            if (!isApproved && !isRejected) {
                actionsHtml = `
                    <button type="button" class="btn btn-sm btn-outline" data-user-action="approve" data-user-id="${user.id}">Approve</button>
                    <button type="button" class="btn btn-sm btn-outline" data-user-action="reject" data-user-id="${user.id}">Reject</button>
                `;
            } else if (isApproved && isActive) {
                actionsHtml = `
                    <button type="button" class="btn btn-sm btn-outline" data-user-action="disable" data-user-id="${user.id}">Disable</button>
                `;
            } else if (isApproved && !isActive) {
                actionsHtml = `
                    <button type="button" class="btn btn-sm btn-outline" data-user-action="enable" data-user-id="${user.id}">Enable</button>
                `;
            } else if (isRejected) {
                actionsHtml = `
                    <button type="button" class="btn btn-sm btn-outline" data-user-action="approve" data-user-id="${user.id}">Approve</button>
                `;
            }
        }

        return `
            <tr>
                <td>${user.name || 'Unknown'}</td>
                <td>${user.email || 'Unknown'}</td>
                <td><span class="badge badge-info">${String(user.role || 'analyst').toUpperCase()}</span></td>
                <td><span class="badge ${statusClass}">${statusLabel}</span></td>
                <td>${user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'Never'}</td>
                <td>
                    <div class="user-management-actions">
                        ${actionsHtml}
                    </div>
                </td>
            </tr>
        `;
    }

    function renderUserManagementRows(users = [], search = '') {
        const sections = document.getElementById('user-management-sections');
        if (!sections) return;

        const term = search.trim().toLowerCase();
        const filtered = term
            ? users.filter(user => [user.name, user.email, user.role, user.approvalStatus].join(' ').toLowerCase().includes(term))
            : users;

        if (!filtered.length) {
            sections.innerHTML = '<div class="user-management-empty">No users found.</div>';
            return;
        }

        const buckets = {
            admin: filtered.filter((user) => String(user.role || '').trim().toLowerCase() === 'admin'),
            analyst: filtered.filter((user) => String(user.role || '').trim().toLowerCase() === 'analyst'),
            other: filtered.filter((user) => {
                const role = String(user.role || '').trim().toLowerCase();
                return role && role !== 'admin' && role !== 'analyst';
            })
        };

        const renderSection = (title, count, usersInSection, emptyLabel) => `
            <section class="user-management-group">
                <div class="user-management-group-header">
                    <div>
                        <h3>${title}</h3>
                        <p>${count} user${count === 1 ? '' : 's'} in this section.</p>
                    </div>
                    <span class="user-management-group-count">${count}</span>
                </div>
                <div class="table-responsive">
                    <table class="data-table user-management-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Status</th>
                                <th>Last Login</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${count
                                ? usersInSection.map(renderUserManagementUserRow).join('')
                                : `<tr><td colspan="6">${emptyLabel}</td></tr>`}
                        </tbody>
                    </table>
                </div>
            </section>
        `;

        sections.innerHTML = `
            ${renderSection('Admins', buckets.admin.length, buckets.admin, 'No admins found.')}
            ${renderSection('Analysts', buckets.analyst.length, buckets.analyst, 'No analysts found.')}
            ${buckets.other.length ? renderSection('Other Roles', buckets.other.length, buckets.other, 'No users found.') : ''}
        `;
    }

    async function openUserManagementModal() {
        const modal = ensureUserManagementModal();
        if (!modal) {
            window.alert('Unable to open User Management right now.');
            return;
        }
        const tbody = modal.querySelector('#user-management-body');
        const sections = modal.querySelector('#user-management-sections');
        const refreshButton = modal.querySelector('#user-management-refresh');
        const searchInput = modal.querySelector('#user-management-search');

        if (sections) {
            sections.innerHTML = '<div class="user-management-empty">Loading users...</div>';
        } else if (tbody) {
            tbody.innerHTML = '<tr><td colspan="6">Loading users...</td></tr>';
        }

        let users = [];

        async function loadUsers() {
            const payload = await apiRequest('/users');
            users = payload.users || [];
            renderUserManagementRows(users, searchInput.value);
        }

        if (!modal.dataset.bound) {
            modal.dataset.bound = 'true';
            refreshButton.addEventListener('click', () => {
                loadUsers().catch(error => {
                    tbody.innerHTML = `<tr><td colspan="6">${error.message}</td></tr>`;
                });
            });

            searchInput.addEventListener('input', () => renderUserManagementRows(users, searchInput.value));

            modal.addEventListener('click', async (event) => {
                const actionButton = event.target.closest('[data-user-action]');
                if (!actionButton) return;

                const userId = actionButton.dataset.userId;
                const action = actionButton.dataset.userAction;

                try {
                    await apiRequest(`/users/${userId}/access`, {
                        method: 'PATCH',
                        body: JSON.stringify({ action })
                    });
                    await loadUsers();
                    refreshLiveCounts(document.getElementById('legacy-page') || document);
                } catch (error) {
                    window.alert(error.message || 'Could not update user');
                }
            });
        }

        try {
            await loadUsers();
        } catch (error) {
            tbody.innerHTML = `<tr><td colspan="6">${error.message}</td></tr>`;
        }
    }

    function renderSidebarNavigation(root) {
        const sidebarNav = root?.querySelector('.sidebar-nav ul');
        if (!sidebarNav) return;

        const role = getCurrentUserRole();
        const items = ROLE_NAVIGATION[role] || ROLE_NAVIGATION.analyst;
        const route = (document.body.dataset.reactRoute || window.location.hash.replace(/^#\/?/, '') || 'login').split('?')[0];

        sidebarNav.innerHTML = items.map(item => {
            const itemRoute = item.href.startsWith('#/')
                ? item.href.replace(/^#\//, '').split('?')[0]
                : item.key === 'user-management'
                    ? 'user-management'
                    : item.href.split('#')[0].replace('.html', '');
            const isActive = itemRoute === route;
            const badge = item.badge
                ? `<span class="badge ${item.badge.className}" id="${item.badge.id}">0</span>`
                : '';
            const adminFeatureAttr = item.key === 'user-management' ? ' data-admin-feature="user-management"' : '';

            return `
                <li class="${isActive ? 'active' : ''}" data-sidebar-key="${item.key}">
                    <a href="${item.href}"${adminFeatureAttr} ${item.title ? `title="${item.title}"` : ''}>
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

        sidebarNav.querySelectorAll('[data-admin-feature]').forEach((element) => {
            element.addEventListener('click', (event) => {
                event.preventDefault();
                const feature = element.dataset.adminFeature || '';
                if (feature === 'user-management') {
                    navigateTo('user-management');
                    return;
                }
                showFeatureUnavailable(element.querySelector('span')?.textContent || 'This feature');
            });
        });

        observeSidebarNavigation(root);
    }

    function scheduleSidebarRepair(root) {
        if (sidebarRepairTimer) return;
        sidebarRepairTimer = setTimeout(() => {
            sidebarRepairTimer = null;
            enforceSidebarNavigationIntegrity(root);
        }, 0);
    }

    function observeSidebarNavigation(root) {
        const sidebarNav = root?.querySelector('.sidebar-nav ul');
        if (!sidebarNav || sidebarObservers.has(sidebarNav)) return;

        const observer = new MutationObserver(() => {
            enforceSidebarNavigationIntegrity(root);
        });
        observer.observe(sidebarNav, { childList: true, subtree: true });
        sidebarObservers.set(sidebarNav, observer);

        observePageIntegrity(root);
    }

    function enforceSidebarNavigationIntegrity(root) {
        const sidebarNav = root?.querySelector('.sidebar-nav ul');
        if (!sidebarNav) return;

        const role = getCurrentUserRole();
        const expectedKeys = (ROLE_NAVIGATION[role] || ROLE_NAVIGATION.analyst).map((item) => item.key);
        const currentKeys = Array.from(sidebarNav.querySelectorAll('li[data-sidebar-key]')).map((item) => item.dataset.sidebarKey);
        const hasSecurityLogs = Boolean(sidebarNav.querySelector('a[href*="logs.html"]'));

        if (!hasSecurityLogs || expectedKeys.join('|') !== currentKeys.join('|')) {
            renderSidebarNavigation(root);
        }
    }

    function observePageIntegrity(root) {
        if (pageIntegrityObserver) return;

        const observeTarget = root || document.body;
        if (!observeTarget) return;

        pageIntegrityObserver = new MutationObserver(() => {
            const latestRoot = document.getElementById('legacy-page') || document;
            enforceSidebarNavigationIntegrity(latestRoot);
        });
        pageIntegrityObserver.observe(observeTarget, { childList: true, subtree: true });
    }

    async function getNotificationItems() {
        try {
            const payload = await apiRequest('/alerts/recent?limit=10');
            const formatNotificationTime = (value) => {
                const date = new Date(value);
                if (Number.isNaN(date.getTime())) return 'Time unavailable';
                return date.toLocaleString([], {
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                });
            };
            return (payload.alerts || []).map((alert) => ({
                type: alert.severity === 'critical' ? 'critical' : alert.severity === 'high' ? 'warning' : 'info',
                icon: alert.severity === 'critical' ? 'fa-exclamation-circle' : alert.severity === 'high' ? 'fa-exclamation-triangle' : 'fa-info-circle',
                title: alert.title,
                message: alert.description || alert.source || 'Security alert',
                time: formatNotificationTime(alert.createdAt || alert.firstSeen || alert.lastSeen || alert.log?.timestamp || alert.updatedAt)
            }));
        } catch (error) {
            console.error('Notifications failed:', error);
            return [];
        }
    }

    function installNotificationDropdown() {
        const bell = document.querySelector('.notification');
        if (!bell) return;

        bell.setAttribute('onclick', 'window.showNotifications(event)');
        bell.setAttribute('role', 'button');
        bell.setAttribute('aria-label', 'Notifications');

        window.showNotifications = async function (event) {
            if (event) event.stopPropagation();

            let dropdown = document.querySelector('.notification-dropdown');
            if (!dropdown) {
                dropdown = document.createElement('div');
                dropdown.className = 'notification-dropdown hidden';
                document.body.appendChild(dropdown);
            }

            dropdown.innerHTML = `
                <div class="notification-dropdown-header">
                    <strong>Notifications</strong>
                    <button type="button" onclick="window.markAllAsRead(event)">Mark all read</button>
                </div>
                <div class="notification-dropdown-list">
                    <div class="notification-dropdown-item info"><i class="fas fa-spinner fa-spin"></i><div>Loading live alerts...</div></div>
                </div>
            `;

            const rect = bell.getBoundingClientRect();
            const width = 340;
            const left = Math.max(12, Math.min(rect.right - width, window.innerWidth - width - 12));
            dropdown.style.top = `${rect.bottom + window.scrollY + 12}px`;
            dropdown.style.left = `${left + window.scrollX}px`;
            dropdown.classList.toggle('hidden');

            const items = await getNotificationItems();
            dropdown.querySelector('.notification-dropdown-list').innerHTML = items.length
                ? items.map((item) => `
                        <div class="notification-dropdown-item ${item.type}">
                            <i class="fas ${item.icon}"></i>
                            <div>
                                <div class="notification-dropdown-title">${item.title}</div>
                                <div class="notification-dropdown-message">${item.message}</div>
                                <div class="notification-dropdown-time">${item.time}</div>
                            </div>
                        </div>
                    `).join('')
                : '<div class="notification-dropdown-item info"><i class="fas fa-check-circle"></i><div>No live alerts right now.</div></div>';
        };

        window.closeNotifications = function () {
            document.querySelector('.notification-dropdown')?.classList.add('hidden');
        };

        window.markAllAsRead = function (event) {
            if (event) event.stopPropagation();
            const count = document.getElementById('notification-count');
            if (count) {
                count.textContent = '0';
                count.style.display = 'none';
            }
            window.closeNotifications();
            if (typeof window.showNotification === 'function') {
                window.showNotification('All notifications marked as read', 'success');
            }
        };

        if (!window.__notificationDropdownEventsInstalled) {
            window.__notificationDropdownEventsInstalled = true;
            document.addEventListener('click', (event) => {
                if (
                    event.target.closest('.notification') ||
                    event.target.closest('.notification-dropdown')
                ) {
                    return;
                }
                window.closeNotifications?.();
            });
            document.addEventListener('keydown', (event) => {
                if (event.key === 'Escape') window.closeNotifications?.();
            });
        }
    }

    function setDocumentChrome(page, route) {
        document.title = page.title || 'MicroSOC Command Center';
        document.body.className = page.bodyClass || '';
        document.body.dataset.theme = localStorage.getItem('theme') || 'dark';
        document.documentElement.dataset.theme = document.body.dataset.theme;
        document.body.dataset.reactRoute = route;
    }

    function loadScript(src) {
        return new Promise((resolve, reject) => {
            if (loadedExternalScripts.has(src) || document.querySelector(`script[src="${src}"]`)) {
                loadedExternalScripts.add(src);
                resolve();
                return;
            }

            const script = document.createElement('script');
            script.src = src;
            script.onload = () => {
                loadedExternalScripts.add(src);
                resolve();
            };
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }

    function installOptionalLibraryFallback(src) {
        if (src.includes('chart.js') && !window.Chart) {
            window.Chart = function Chart() {
                return {
                    update() {},
                    destroy() {},
                    config: { type: 'line' }
                };
            };
        }

        if (src.includes('apexcharts') && !window.ApexCharts) {
            window.ApexCharts = function ApexCharts() {
                return {
                    render() {},
                    updateOptions() {},
                    destroy() {}
                };
            };
        }
    }

    async function runLegacyScript(script) {
        const src = script.src;

        if (src && /^https?:\/\//.test(src)) {
            try {
                await loadScript(src);
            } catch (error) {
                installOptionalLibraryFallback(src);
                console.warn(`Optional script failed to load: ${src}`, error);
            }
            return;
        }

        const code = src
            ? await fetch(src).then((response) => response.text())
            : script.code;

        const originalAddEventListener = document.addEventListener.bind(document);
        document.addEventListener = function (type, callback, options) {
            if (type === 'DOMContentLoaded') {
                window.setTimeout(callback, 0);
                return;
            }
            return originalAddEventListener(type, callback, options);
        };

        try {
            Function(exposePageFunctions(patchLegacyNavigation(code)))();
        } finally {
            document.addEventListener = originalAddEventListener;
        }
    }

    function guardRoute(route) {
        const token = localStorage.getItem('token');
        const user = localStorage.getItem('user');
        if (protectedRoutes.has(route) && !token && !user) {
            closeRealtimeFeed();
            navigateTo('login');
            return false;
        }
        if (!protectedRoutes.has(route)) {
            closeRealtimeFeed();
        }
        return true;
    }

    function HtmlPage({ route }) {
        const [readyPage, setReadyPage] = useState({ body: '', scripts: [], error: '' });

        useEffect(() => {
            if (!guardRoute(route)) return;

            const page = pages[route] || (route === 'user-management'
                ? { ...(pages.analytics || {}), title: 'User Management - MicroSOC Command Center' }
                : route === 'settings'
                    ? { ...(pages['settings'] || {}), title: 'Settings - MicroSOC Command Center' }
                : null);
            if (!page) {
                setReadyPage({ body: '', scripts: [], error: `Route "${route}" was not found.` });
                return;
            }

            setDocumentChrome(page, route);
            setReadyPage({ body: page.body, scripts: page.scripts || [], error: '' });
        }, [route]);

        useEffect(() => {
            if (!readyPage.body || readyPage.error) return;

            let cancelled = false;

            async function hydrateLegacyPage() {
                const root = document.getElementById('legacy-page');
                if (!root) return;

                root.dataset.activeRoute = route;
                delete root.dataset.featureSuiteInstalled;
                delete root.dataset.alertsConsoleInstalled;
                delete root.dataset.auditLogsConsoleInstalled;
                delete root.dataset.userManagementHidden;
                delete root.dataset.settingsConsoleInstalled;

                rewriteLinks(root);
                for (const script of readyPage.scripts) {
                    if (cancelled) return;
                    try {
                        await runLegacyScript(script);
                    } catch (error) {
                        console.error('Page script failed to run:', error);
                    }
                }
                ensureActionHandlers(root);
                enhanceSecurityUi(route);
                sanitizeAuthPage(route, root);
                syncCurrentUserUi(root);
                installFeatureSuite(route, root);
                if (route !== 'user-management') {
                    document.body.classList.remove('user-management-open');
                    restoreMainContentView();
                }
                const routeMainContent = root.querySelector('.main-content');
                syncRouteChrome(route, routeMainContent);
                window.setTimeout(() => syncRouteChrome(route, routeMainContent), 100);
                window.setTimeout(() => syncRouteChrome(route, routeMainContent), 500);
            }

            hydrateLegacyPage();
            return () => {
                cancelled = true;
            };
        }, [readyPage]);

        if (readyPage.error) {
            return React.createElement(
                'main',
                { className: 'login-page' },
                React.createElement(
                    'div',
                    { className: 'login-container' },
                    React.createElement(
                        'div',
                        { className: 'login-card' },
                        React.createElement('h1', null, 'MicroSOC Command Center'),
                        React.createElement('p', null, readyPage.error),
                        React.createElement(
                            'button',
                            { className: 'btn btn-primary', onClick: () => navigateTo('login') },
                            'Back to Login'
                        )
                    )
                )
            );
        }

        return React.createElement('div', {
            id: 'legacy-page',
            dangerouslySetInnerHTML: { __html: readyPage.body }
        });
    }

    function getAuthHeaders() {
        return {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
        };
    }

    async function apiRequest(path, options = {}) {
        const response = await fetch(`${window.MICROSOC_API_BASE_URL}${path}`, {
            ...options,
            headers: { ...getAuthHeaders(), ...(options.headers || {}) }
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || payload.success === false) {
            throw new Error(payload.message || payload.error || 'Request failed');
        }
        return payload;
    }

    function normalizeAttackMapCountry(value) {
        const raw = String(value || '').trim();
        const aliases = {
            'united states': 'US',
            'united states of america': 'US',
            usa: 'US',
            'u.s.a.': 'US',
            america: 'US',
            germany: 'DE',
            india: 'IN',
            china: 'CN',
            russia: 'RU',
            'russian federation': 'RU',
            brazil: 'BR',
            japan: 'JP',
            korea: 'KR',
            'south korea': 'KR',
            'united kingdom': 'UK',
            uk: 'UK',
            france: 'FR'
        };
        if (!raw) return 'Unknown';
        return aliases[raw.toLowerCase()] || raw.toUpperCase();
    }

    function getAttackMapCountryName(value) {
        const code = normalizeAttackMapCountry(value);
        return {
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
        }[code] || value || code;
    }

    function getAttackMapCountryPosition(value, index = 0) {
        const code = normalizeAttackMapCountry(value);
        return {
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
        }[code] || [18 + ((index * 13) % 64), 24 + ((index * 19) % 46)];
    }

    function renderDashboardAttackMapSurface(container, countries, totalLogs) {
        const rows = (Array.isArray(countries) ? countries : [])
            .filter(item => item && item.country)
            .map(item => ({
                country: getAttackMapCountryName(item.country),
                code: normalizeAttackMapCountry(item.country),
                count: Number(item.count || 0),
                severityRank: Number(item.severityRank || 1)
            }))
            .filter(item => item.count > 0)
            .sort((a, b) => b.count - a.count);

        const total = Number(totalLogs || rows.reduce((sum, item) => sum + item.count, 0));
        const severityClass = rank => rank >= 4 ? 'critical' : rank === 3 ? 'high' : rank === 2 ? 'medium' : 'low';
        const severityColor = rank => rank >= 4 ? '#ef4444' : rank === 3 ? '#f97316' : rank === 2 ? '#facc15' : '#22c55e';

        container.dataset.attackMapSource = 'server';
        container.innerHTML = `
            <div class="map-surface map-surface--aggregate">
                <div class="map-grid"></div>
                <div class="attack-map-total-badge" style="position:absolute;right:12px;top:12px;z-index:4;padding:7px 10px;border-radius:999px;background:rgba(2,6,23,0.78);border:1px solid rgba(103,232,249,0.28);color:#a5f3fc;font-weight:800;font-size:12px;">All-time logs ${total.toLocaleString()}</div>
                ${rows.length ? '' : '<div class="map-empty-state">No country activity yet.</div>'}
                ${rows.map((item, index) => {
                    const [top, left] = getAttackMapCountryPosition(item.code, index);
                    return `
                        <button class="map-point map-point-${severityClass(item.severityRank)} map-point-${item.code}" style="top:${top}%;left:${left}%;width:44px;height:44px;border:0;background:${severityColor(item.severityRank)};" title="${item.country} · ${item.count} attacks">
                            <span class="map-point-count">${item.count}</span>
                            <span class="map-tooltip">${item.country} • ${item.count} attacks</span>
                        </button>
                    `;
                }).join('')}
            </div>
            <div class="attack-country-summary">
                <div class="attack-country-summary-title">All-time active logs · ${total.toLocaleString()} attacks</div>
                <div class="attack-country-summary-list">
                    ${rows.map(item => `
                        <div class="attack-country-summary-item">
                            <span>${item.country}</span>
                            <strong>${item.count}</strong>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    async function forceDashboardAttackMapAggregate(root = document) {
        const container = root.querySelector?.('#attack-map-container') || document.getElementById('attack-map-container');
        if (!container) return;

        container.innerHTML = '<div class="map-empty-state">Loading all-time attack map...</div>';
        try {
            const payload = await apiRequest(`/dashboard/attack-map?_=${Date.now()}`);
            renderDashboardAttackMapSurface(container, payload.countryAttackMap || [], payload.totalLogs);
            console.info('MicroSOC aggregate attack map rendered', {
                totalLogs: payload.totalLogs,
                countries: (payload.countryAttackMap || []).length
            });
        } catch (error) {
            console.error('Force aggregate attack map failed:', error);
            container.innerHTML = '<div class="map-empty-state">Attack map unavailable. Please check backend connection.</div>';
        }
    }

    function installFeatureSuite(route, root) {
        if (!protectedRoutes.has(route) || !root || root.dataset.featureSuiteInstalled) return;
        root.dataset.featureSuiteInstalled = 'true';
        if (route !== 'audit-logs') {
            renderRoleDashboard(root);
        }
        refreshLiveCounts(root);
        if (route === 'dashboard') {
            if (typeof window.initDashboard === 'function') {
                window.initDashboard();
            } else {
                refreshLegacyDashboardData(root);
            }
            root.querySelector('.feature-attack-viz')?.remove();
            window.refreshAttackMap = () => forceDashboardAttackMapAggregate(root);
            forceDashboardAttackMapAggregate(root);
            window.setTimeout(() => forceDashboardAttackMapAggregate(root), 750);
            window.setTimeout(() => forceDashboardAttackMapAggregate(root), 2500);
        }
        if (route === 'alerts') renderAlertsConsole(root);
        if (route === 'audit-logs') renderAuditLogsConsole(root);
        if (route === 'settings') renderSettingsConsole(root);
        if (route === 'incidents') {
            refreshLegacyIncidentStats(root);
            renderIncidentConsole(root);
        }
        if (route === 'analytics') {
            relocateAnalyticsInsights(root);
            renderThreatIntel(root);
        }
        applyRoleRestrictions(root);
    }

    function findContentHost(root) {
        return root.querySelector('.main-content') || root;
    }

    function currentUser() {
        try {
            return JSON.parse(localStorage.getItem('user') || '{}');
        } catch (error) {
            return {};
        }
    }

    function isAdminUser() {
        return String(currentUser().role || 'analyst').trim().toLowerCase() === 'admin';
    }

    function escapeInline(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function getThreatContextForAttack(attackType) {
        const key = String(attackType || '').toLowerCase();
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

    function getRelatedCves(item = {}) {
        const existing = item.relatedCves || item.cves || item.evidence?.relatedCves || item.metadata?.relatedCves;
        if (Array.isArray(existing) && existing.length) return existing;
        return getThreatContextForAttack(item.attackType || item.title || item.description).cves;
    }

    function renderCveBadges(item = {}) {
        return getRelatedCves(item).map(cve => `<span class="badge badge-info">${escapeInline(cve)}</span>`).join('');
    }

    function getMitreForItem(item = {}) {
        const candidates = [
            item.mitreTechnique,
            item.threatIntel?.mitreTechnique,
            item.evidence?.mitreTechnique,
            item.metadata?.mitreTechnique
        ];
        const stored = candidates.find(value => {
            const text = String(value || '').trim();
            return text && !/^unknown$/i.test(text) && !/^mitre unknown$/i.test(text);
        });
        return stored || getThreatContextForAttack(item.attackType || item.title || item.description).mitre;
    }

    function applyRoleRestrictions(root) {
        const role = String(currentUser().role || 'analyst').trim().toLowerCase();
        root.dataset.userRole = role;

        if (role === 'admin') return;

        const adminOnlyMatchers = [
            /user management/i,
            /assign roles?/i,
            /system settings/i,
            /threat feed configuration/i,
            /audit logs?/i,
            /settings/i,
            /create incident/i,
            /archive/i,
            /delete/i,
            /export/i,
            /generate/i
        ];

        root.querySelectorAll('[onclick], button, a, select, input').forEach((element) => {
            const action = element.getAttribute('onclick') || '';
            const label = element.textContent || element.getAttribute('title') || element.getAttribute('aria-label') || '';
            const adminOnlyAction = /delete|clearLogs|deleteSelectedLogs|assignRole|userManagement|systemSettings|threatFeedConfig|audit|generateMock|createIncidentFromLog|createAlertFromLog|export/i.test(action);
            const adminOnlyLabel = adminOnlyMatchers.some((matcher) => matcher.test(label));

            if (adminOnlyAction || adminOnlyLabel) {
                const container = element.closest('li, .card, .form-group, .log-controls, .ticket-actions') || element;
                container.classList.add('admin-only-hidden');
                container.setAttribute('hidden', '');
            }
        });
    }

    async function refreshLiveCounts(root) {
        try {
            const [incidentPayload, logPayload, alertPayload] = await Promise.all([
                apiRequest('/incidents/stats'),
                apiRequest('/logs/stats?timeRange=all'),
                apiRequest('/alerts/stats?timeRange=all')
            ]);
            const statusCounts = Object.fromEntries((incidentPayload.stats?.statusCounts || []).map(item => [item._id, item.count]));
            const activeIncidents = (statusCounts.open || 0) + (statusCounts.in_progress || 0);
            root.querySelectorAll('#incident-count, .sidebar-nav .badge-danger').forEach(item => {
                item.textContent = activeIncidents;
            });
            root.querySelectorAll('#log-count, .sidebar-nav .badge-warning').forEach(item => {
                item.textContent = logPayload.stats?.totalLogs?.[0]?.count || 0;
            });
            const notificationCount = root.querySelector('#notification-count');
            if (notificationCount) {
                const requiringAction = alertPayload.stats?.requiringAction?.[0]?.count || alertPayload.summary?.requiringAction || 0;
                notificationCount.textContent = requiringAction;
                notificationCount.style.display = requiringAction > 0 ? 'inline-flex' : 'none';
            }
        } catch (error) {
            console.error('Live count refresh failed:', error);
        }
    }

    async function refreshLegacyDashboardData(root) {
        const statsContainer = root.querySelector('#stats-container');
        if (!statsContainer) return;
        try {
            const payload = await apiRequest('/dashboard/stats');
            statsContainer.innerHTML = (payload.stats || []).map(stat => `
                <div class="stat-card">
                    <div class="stat-icon" style="background: ${stat.color}20; color: ${stat.color}">
                        <i class="fas ${stat.icon}"></i>
                    </div>
                    <div class="stat-info">
                        <h3>${stat.title}</h3>
                        <div class="stat-value">${stat.value}</div>
                        <div class="stat-change ${stat.changeType}">
                            <i class="fas fa-database"></i> Live
                        </div>
                    </div>
                </div>
            `).join('');
        } catch (error) {
            statsContainer.innerHTML = '<div class="empty-state">No live dashboard stats available.</div>';
        }
    }

    async function refreshLegacyIncidentStats(root) {
        const grid = root.querySelector('.main-content .stats-grid');
        if (!grid) return;
        try {
            const payload = await apiRequest('/incidents/stats');
            const statusCounts = Object.fromEntries((payload.stats?.statusCounts || []).map(item => [item._id, item.count]));
            const severityCounts = Object.fromEntries((payload.stats?.severityCounts || []).map(item => [item._id, item.count]));
            const cards = [
                ['fa-exclamation-circle', 'Open Incidents', statusCounts.open || 0, '#dc3545'],
                ['fa-skull-crossbones', 'Critical', severityCounts.critical || 0, '#fd7e14'],
                ['fa-user-clock', 'In Progress', statusCounts.in_progress || 0, '#007bff'],
                ['fa-check-circle', 'Resolved', statusCounts.resolved || 0, '#28a745']
            ];
            grid.innerHTML = cards.map(([icon, title, value, color]) => `
                <div class="stat-card">
                    <div class="stat-icon" style="background: ${color}20; color: ${color}">
                        <i class="fas ${icon}"></i>
                    </div>
                    <div class="stat-info">
                        <h3>${title}</h3>
                        <div class="stat-value">${value}</div>
                        <div class="stat-change positive"><i class="fas fa-database"></i> Live</div>
                    </div>
                </div>
            `).join('');
        } catch (error) {
            grid.innerHTML = '<div class="empty-state">No live incident stats available.</div>';
        }
    }

    function renderRoleDashboard(root) {
        const host = root.querySelector('.threat-ribbon') || findContentHost(root);
        if (!host || root.querySelector('.role-dashboard-strip')) return;
        const user = currentUser();
        const role = user.role || 'analyst';
        const strip = document.createElement('div');
        strip.className = `role-dashboard-strip ${role}`;
        strip.innerHTML = `
            <div>
                <strong>${role === 'admin' ? 'Admin Command View' : 'Analyst Triage View'}</strong>
                <span>${role === 'admin' ? 'User approvals, system-wide incidents, and policy controls enabled.' : 'Focused queue for alerts, investigations, and remediation tracking.'}</span>
            </div>
            <div class="role-actions">
                <span><i class="fas fa-user-shield"></i> ${role.toUpperCase()}</span>
                <span><i class="fas fa-bell"></i> Auto-refresh on</span>
                ${role === 'admin' ? '<span><i class="fas fa-lock-open"></i> Admin controls enabled</span>' : '<span><i class="fas fa-lock"></i> Admin controls hidden</span>'}
            </div>
        `;
        host.insertAdjacentElement(host.classList.contains('threat-ribbon') ? 'afterend' : 'afterbegin', strip);
    }

    function renderAlertsConsole(root) {
        const host = findContentHost(root);
        if (!host || root.dataset.alertsConsoleInstalled) return;
        root.dataset.alertsConsoleInstalled = 'true';
        const role = currentUser().role || 'analyst';

        const existingSummary = root.querySelector('#alerts-summary');
        const existingWorkbench = root.querySelector('#alerts-workbench');
        const panel = existingSummary && existingWorkbench ? null : document.createElement('section');

        let summary;
        let workbench;
        let refreshButton;
        let activeInvestigationAlert = null;
        let currentAlerts = [];
        let currentAlertsPage = 1;
        let currentAlertsTotal = 0;
        let currentAlertsTotalPages = 1;
        const alertsPageSize = 50;

        if (panel) {
            panel.className = 'feature-panel feature-alerts-console';
            panel.innerHTML = `
                <div class="feature-panel-header">
                    <div>
                        <h2 style="color:#0f172a !important;-webkit-text-fill-color:#0f172a !important;opacity:1 !important;text-shadow:none !important;font-weight:900 !important;">Threat Detection & Alerts</h2>
                        <p style="color:#164e63 !important;-webkit-text-fill-color:#164e63 !important;opacity:1 !important;">Persistent alert queue, lifecycle actions, and evidence-backed detections.</p>
                    </div>
                    <div class="alerts-actions">
                        <button type="button" class="btn btn-outline" data-refresh-alerts><i class="fas fa-sync"></i> Refresh</button>
                    </div>
                </div>
                <div class="alerts-summary-grid" data-alerts-summary></div>
                <div class="alerts-workbench" data-alerts-workbench></div>
            `;
            host.prepend(panel);
            summary = panel.querySelector('[data-alerts-summary]');
            workbench = panel.querySelector('[data-alerts-workbench]');
            refreshButton = panel.querySelector('[data-refresh-alerts]');
        } else {
            summary = existingSummary;
            workbench = existingWorkbench;
            refreshButton = root.querySelector('[data-refresh-alerts]');
        }

        const escapeHtml = (value) => String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');

        const alertId = (alert) => alert?._id || alert?.id || '';

        function formatDateTime(value) {
            if (!value) return 'Unknown';
            const date = new Date(value);
            if (Number.isNaN(date.getTime())) return 'Unknown';
            return date.toLocaleString();
        }

        function formatStatus(value) {
            return String(value || 'new').replace(/_/g, ' ');
        }

        function getAlertDrawer() {
            let drawer = root.querySelector('[data-alert-investigation-drawer]');
            if (drawer) return drawer;

            drawer = document.createElement('aside');
            drawer.className = 'alert-investigation-drawer';
            drawer.hidden = true;
            drawer.setAttribute('data-alert-investigation-drawer', '');
            drawer.innerHTML = `
                <div class="alert-investigation-backdrop" data-close-investigation></div>
                <section class="alert-investigation-panel" role="dialog" aria-modal="true" aria-label="Alert investigation">
                    <div data-alert-investigation-content></div>
                </section>
            `;
            (panel || host).appendChild(drawer);
            return drawer;
        }

        function closeInvestigationDrawer() {
            const drawer = getAlertDrawer();
            drawer.hidden = true;
            document.body.classList.remove('alert-investigation-open');
        }

        function renderInvestigationLoading(message = 'Loading investigation...') {
            const drawer = getAlertDrawer();
            drawer.hidden = false;
            document.body.classList.add('alert-investigation-open');
            drawer.querySelector('[data-alert-investigation-content]').innerHTML = `
                <div class="investigation-loading">
                    <i class="fas fa-spinner fa-spin"></i>
                    <span>${escapeHtml(message)}</span>
                </div>
            `;
        }

        function summarizeEvidence(evidence) {
            if (!evidence || typeof evidence !== 'object') return [];
            return Object.entries(evidence)
                .filter(([, value]) => value !== undefined && value !== null && value !== '')
                .slice(0, 8)
                .map(([key, value]) => [key, typeof value === 'object' ? JSON.stringify(value) : String(value)]);
        }

        function buildInvestigationSummary(alert, relatedLogs = []) {
            const severity = String(alert.severity || 'medium').toLowerCase();
            const hits = Number(alert.occurrenceCount || relatedLogs.length || 1);
            const blockedCount = relatedLogs.filter(log => log.isBlocked).length;
            const recommendations = [
                `Correlate ${escapeHtml(alert.sourceIP || 'the source')} against recent Security Logs and attacker history.`,
                severity === 'critical' || severity === 'high'
                    ? 'Prioritize containment: block source, verify target health, and open an incident if not already linked.'
                    : 'Monitor for recurrence and keep evidence attached before resolving.',
                blockedCount
                    ? `${blockedCount} related log${blockedCount === 1 ? '' : 's'} already show blocked activity.`
                    : 'No blocked related log found in the current sample; verify firewall/WAF response.'
            ];

            return {
                confidence: hits > 3 ? 'High' : hits > 1 ? 'Medium' : 'Low',
                impact: severity === 'critical' ? 'Potential service or data impact' : severity === 'high' ? 'Likely active threat path' : 'Needs validation',
                recommendations
            };
        }

        async function loadRelatedLogsForAlert(alert) {
            if (!alert?.sourceIP) return [];
            try {
                const params = new URLSearchParams({
                    limit: '8',
                    timeRange: 'all',
                    sourceIP: alert.sourceIP
                });
                const payload = await apiRequest(`/logs?${params.toString()}`);
                return Array.isArray(payload.logs) ? payload.logs : [];
            } catch (error) {
                console.warn('Related alert logs failed:', error);
                return [];
            }
        }

        function renderInvestigationDrawer(alert, relatedLogs = []) {
            activeInvestigationAlert = alert;
            const drawer = getAlertDrawer();
            const content = drawer.querySelector('[data-alert-investigation-content]');
            const summaryData = buildInvestigationSummary(alert, relatedLogs);
            const evidenceItems = summarizeEvidence(alert.evidence);
            const notes = Array.isArray(alert.notes) ? alert.notes : [];
            const linkedLog = alert.log && typeof alert.log === 'object' ? alert.log : null;
            const linkedIncident = alert.incident && typeof alert.incident === 'object' ? alert.incident : null;
            const canAdminAct = role === 'admin';

            content.innerHTML = `
                <header class="investigation-header">
                    <div>
                        <p class="investigation-kicker">Alert Investigation</p>
                        <h3>${escapeHtml(alert.title || 'Security Alert')}</h3>
                        <div class="investigation-badges">
	                            <span class="investigation-severity ${escapeHtml(alert.severity || 'medium')}">${escapeHtml(String(alert.severity || 'medium').toUpperCase())}</span>
	                            <span>${escapeHtml(formatStatus(alert.status))}</span>
	                            <span>${escapeHtml(getMitreForItem(alert))}</span>
	                        </div>
                    </div>
                    <button type="button" class="investigation-close" data-close-investigation aria-label="Close investigation">&times;</button>
                </header>

                <div class="investigation-body">
                    <section class="investigation-card investigation-card-wide">
                        <h4><i class="fas fa-bullseye"></i> What Happened</h4>
                        <p>${escapeHtml(alert.description || 'No description available.')}</p>
                        <div class="investigation-facts">
                            <span><strong>Source</strong>${escapeHtml(alert.sourceIP || 'Unknown')}</span>
                            <span><strong>Target</strong>${escapeHtml(alert.targetSystem || 'Unknown')}</span>
	                            <span><strong>Attack</strong>${escapeHtml(alert.attackType || 'Threat')}</span>
	                            <span><strong>Hits</strong>${escapeHtml(alert.occurrenceCount || 1)}</span>
	                        </div>
                    </section>

                    <section class="investigation-card">
                        <h4><i class="fas fa-clock"></i> Timeline</h4>
                        <div class="investigation-timeline">
                            <span><strong>First seen</strong>${escapeHtml(formatDateTime(alert.firstSeen || alert.createdAt))}</span>
                            <span><strong>Last seen</strong>${escapeHtml(formatDateTime(alert.lastSeen || alert.updatedAt))}</span>
                            <span><strong>Reviewed</strong>${escapeHtml(formatDateTime(alert.reviewedAt))}</span>
                        </div>
                    </section>

                    <section class="investigation-card">
                        <h4><i class="fas fa-brain"></i> AI Triage</h4>
                        <div class="investigation-ai">
                            <span><strong>Confidence</strong>${escapeHtml(summaryData.confidence)}</span>
                            <span><strong>Impact</strong>${escapeHtml(summaryData.impact)}</span>
                        </div>
                        <ul>
                            ${summaryData.recommendations.map(item => `<li>${item}</li>`).join('')}
                        </ul>
                    </section>

                    <section class="investigation-card investigation-card-wide">
                        <h4><i class="fas fa-stream"></i> Related Logs</h4>
                        ${relatedLogs.length ? `
                            <div class="investigation-log-list">
                                ${relatedLogs.map(log => `
                                    <div class="investigation-log-row">
                                        <span>${escapeHtml(formatDateTime(log.timestamp || log.createdAt))}</span>
                                        <strong>${escapeHtml(log.attackType || 'Threat')}</strong>
                                        <span>${escapeHtml(log.targetSystem || 'Unknown target')}</span>
                                        <span class="investigation-severity ${escapeHtml(log.severity || 'medium')}">${escapeHtml(String(log.severity || 'medium').toUpperCase())}</span>
                                    </div>
                                `).join('')}
                            </div>
                        ` : '<p class="investigation-muted">No related logs found for this source IP yet.</p>'}
                    </section>

                    <section class="investigation-card">
                        <h4><i class="fas fa-paperclip"></i> Evidence</h4>
                        ${evidenceItems.length ? `
                            <div class="investigation-evidence">
                                ${evidenceItems.map(([key, value]) => `
                                    <span><strong>${escapeHtml(key)}</strong>${escapeHtml(value)}</span>
                                `).join('')}
                            </div>
                        ` : '<p class="investigation-muted">No structured evidence attached.</p>'}
                    </section>

                    <section class="investigation-card">
                        <h4><i class="fas fa-link"></i> Links & Notes</h4>
                        <div class="investigation-links">
                            <span><strong>Linked Log</strong>${linkedLog ? escapeHtml(linkedLog._id || linkedLog.id || 'Available') : 'Not linked'}</span>
                            <span><strong>Incident</strong>${linkedIncident ? escapeHtml(linkedIncident.title || linkedIncident._id) : 'Not created'}</span>
                        </div>
                        ${notes.length ? `
                            <div class="investigation-notes">
                                ${notes.slice(-3).map(note => `
                                    <p>${escapeHtml(note.text || note)}<small>${escapeHtml(formatDateTime(note.createdAt))}</small></p>
                                `).join('')}
                            </div>
                        ` : '<p class="investigation-muted">No analyst notes yet.</p>'}
                    </section>
                </div>

                <footer class="investigation-footer">
                    <button type="button" data-close-investigation>Close</button>
                    <button type="button" data-investigation-view-logs>View Related Logs</button>
                    ${canAdminAct ? `
                        <button type="button" data-investigation-status="in_progress">Mark In Progress</button>
                        <button type="button" data-investigation-create-incident>Create Incident</button>
                        <button type="button" data-investigation-status="resolved">Resolve</button>
                    ` : '<button type="button" data-investigation-escalate>Escalate</button>'}
                </footer>
            `;
        }

        async function openInvestigation(alertIdValue, options = {}) {
            renderInvestigationLoading(options.markInProgress ? 'Opening investigation...' : 'Loading alert evidence...');
            try {
                let payload = await apiRequest(`/alerts/${alertIdValue}`);
                let selected = payload.alert;

                if (
                    options.markInProgress &&
                    role === 'admin' &&
                    selected?.status !== 'in_progress' &&
                    !['resolved', 'closed'].includes(selected?.status)
                ) {
                    payload = await apiRequest(`/alerts/${alertIdValue}`, {
                        method: 'PATCH',
                        body: JSON.stringify({
                            status: 'in_progress',
                            notes: [{ text: 'Investigation started from Alerts console.' }]
                        })
                    });
                    selected = payload.alert || selected;
                    await loadAlerts({ page: 1 });
                }

                const relatedLogs = await loadRelatedLogsForAlert(selected);
                renderInvestigationDrawer(selected, relatedLogs);
            } catch (error) {
                getAlertDrawer().querySelector('[data-alert-investigation-content]').innerHTML = `
                    <div class="investigation-error">
                        <button type="button" class="investigation-close" data-close-investigation aria-label="Close investigation">&times;</button>
                        <i class="fas fa-triangle-exclamation"></i>
                        <h3>Investigation failed</h3>
                        <p>${escapeHtml(error.message || 'Could not load alert investigation.')}</p>
                    </div>
                `;
            }
        }

        function applyAlertsTheme() {
            const themeHref = document.getElementById('theme-style')?.getAttribute('href') || '';
            const isLight = themeHref.includes('light-theme') || document.body.dataset.theme === 'light' || localStorage.getItem('theme') === 'light';
            const titleColor = isLight ? '#0f172a' : '#dbeafe';
            const subtitleColor = isLight ? '#164e63' : '#94a3b8';
            const iconColor = isLight ? '#0e7490' : '#22c1dc';
            const sectionTitleColor = isLight ? '#0f172a' : '#e5eefb';
            const titleTargets = root.querySelectorAll('.feature-alerts-console .feature-panel-header > div > h2, .feature-alerts-console .feature-panel-header > div > p, .feature-alerts-console .feature-panel-header > div > h2 i, .feature-alerts-console .card-header h3, .feature-alerts-console .card-header h3 i, .feature-alerts-console > .feature-panel-header > div > h2, .feature-alerts-console > .feature-panel-header > div > p, .feature-alerts-console > .card > .card-header > h3, .feature-alerts-console > .card > .card-header > h3 i');
            const textTargets = root.querySelectorAll('h1, h2, h3, p');

            titleTargets.forEach((node) => {
                if (!node) return;
                const isIcon = node.tagName === 'I';
                const isSubtitle = node.tagName === 'P';
                const color = isIcon ? iconColor : (isSubtitle ? subtitleColor : titleColor);
                node.style.setProperty('color', color, 'important');
                node.style.setProperty('-webkit-text-fill-color', color, 'important');
                node.style.setProperty('opacity', '1', 'important');
                node.style.setProperty('text-shadow', 'none', 'important');
            });

            root.querySelectorAll('.feature-alerts-console .card-header h3, .feature-alerts-console .feature-panel-header h2').forEach((node) => {
                node.style.setProperty('color', sectionTitleColor, 'important');
                node.style.setProperty('-webkit-text-fill-color', sectionTitleColor, 'important');
                node.style.setProperty('opacity', '1', 'important');
                node.style.setProperty('text-shadow', 'none', 'important');
                node.style.setProperty('font-weight', '900', 'important');
            });

            root.querySelectorAll('.feature-alerts-console .card-header h3 i, .feature-alerts-console .feature-panel-header h2 i').forEach((icon) => {
                icon.style.setProperty('color', iconColor, 'important');
            });

            textTargets.forEach((node) => {
                const text = (node.textContent || '').replace(/\s+/g, ' ').trim();
                if (text === 'Threat Detection & Alerts' || text === 'Active Alerts') {
                    const isSection = text === 'Active Alerts';
                    const color = isSection ? sectionTitleColor : titleColor;
                    node.style.setProperty('color', color, 'important');
                    node.style.setProperty('-webkit-text-fill-color', color, 'important');
                    node.style.setProperty('opacity', '1', 'important');
                    node.style.setProperty('text-shadow', 'none', 'important');
                    node.style.setProperty('font-weight', '900', 'important');
                    const icon = node.querySelector('i');
                    if (icon) {
                        icon.style.setProperty('color', iconColor, 'important');
                    }
                }
            });
        }

        applyAlertsTheme();
        window.addEventListener('microsoc:theme-changed', applyAlertsTheme);

        function renderSummary(stats = {}) {
            const statusCounts = Object.fromEntries((stats.statusCounts || []).map(item => [item._id, item.count]));
            const severityCounts = Object.fromEntries((stats.severityCounts || []).map(item => [item._id, item.count]));
            const requiringAction = stats.requiringAction?.[0]?.count || 0;
            const total = stats.totalAlerts?.[0]?.count || 0;
            summary.innerHTML = [
                ['Total Alerts', total, 'fa-bell'],
                ['Needs Action', requiringAction, 'fa-exclamation-triangle'],
                ['Critical', severityCounts.critical || 0, 'fa-skull-crossbones'],
                ['Resolved', statusCounts.resolved || 0, 'fa-check-circle']
            ].map(([title, value, icon]) => `
                <div class="stat-card">
                    <div class="stat-icon" style="background: #0dcaf020; color: #0dcaf0">
                        <i class="fas ${icon}"></i>
                    </div>
                    <div class="stat-info">
                        <h3>${title}</h3>
                        <div class="stat-value">${value}</div>
                        <div class="stat-change positive">Live</div>
                    </div>
                </div>
            `).join('');
        }

        function renderAlerts(alerts = [], pagination = {}) {
            if (!alerts.length) {
                workbench.innerHTML = '<p class="empty-state">No alerts found for the selected window.</p>';
                return;
            }

            const total = Number(pagination.total ?? currentAlertsTotal ?? alerts.length);
            const page = Number(pagination.page ?? currentAlertsPage ?? 1);
            const totalPages = Number(pagination.totalPages ?? currentAlertsTotalPages ?? 1);
            const canLoadMore = page < totalPages && alerts.length < total;

            workbench.innerHTML = `
                <div class="alerts-list-status">
                    <span>Showing <strong>${escapeHtml(alerts.length)}</strong> of <strong>${escapeHtml(total)}</strong> active alerts</span>
                    <span>Page ${escapeHtml(page)} / ${escapeHtml(totalPages)}</span>
                </div>
                ${alerts.map(alert => `
                <article class="alert-ticket ${escapeHtml(alert.severity || 'medium')}">
                    <div class="alert-ticket-main">
                        <div class="alert-ticket-header">
                            <strong>${escapeHtml(alert.title || 'Security Alert')}</strong>
                            <span>${escapeHtml(formatStatus(alert.status))}</span>
                        </div>
                        <p>${escapeHtml(alert.description || 'No description available.')}</p>
	                        <div class="alert-meta">
	                            <span><i class="fas fa-shield-virus"></i> ${escapeHtml(alert.attackType || 'Threat')}</span>
	                            <span><i class="fas fa-network-wired"></i> ${escapeHtml(alert.sourceIP || 'Unknown')}</span>
	                            <span><i class="fas fa-fingerprint"></i> ${escapeHtml(getMitreForItem(alert))}</span>
	                            <span><i class="fas fa-copy"></i> ${escapeHtml(alert.occurrenceCount || 1)} hits</span>
	                        </div>
                    </div>
                    <div class="ticket-actions">
                        <button type="button" data-alert-view="${escapeHtml(alertId(alert))}">View</button>
                        <button type="button" data-alert-investigate="${escapeHtml(alertId(alert))}">Investigate</button>
                        ${role === 'admin'
                            ? `<button type="button" data-alert-status="${escapeHtml(alertId(alert))}:resolved">Resolve</button><button type="button" data-alert-delete="${escapeHtml(alertId(alert))}">Archive</button>`
                            : '<button type="button" data-alert-escalate>Escalate</button>'}
                    </div>
                </article>
                `).join('')}
                ${canLoadMore ? `
                    <div class="alerts-load-more-row">
                        <button type="button" class="btn btn-outline" data-alert-load-more>
                            <i class="fas fa-chevron-down"></i> Load More Alerts
                        </button>
                    </div>
                ` : ''}
            `;
        }

        async function loadAlerts(options = {}) {
            const page = Math.max(1, Number(options.page || 1));
            const append = Boolean(options.append);
            const [alertsResult, statsResult] = await Promise.allSettled([
                apiRequest(`/alerts/recent?limit=${alertsPageSize}&page=${page}&timeRange=all`),
                apiRequest('/alerts/stats?timeRange=all')
            ]);
            if (alertsResult.status === 'rejected') throw alertsResult.reason;
            const alertsPayload = alertsResult.value;
            const statsPayload = statsResult.status === 'fulfilled' ? statsResult.value : {};
            currentAlerts = append
                ? [...currentAlerts, ...(alertsPayload.alerts || [])]
                : (alertsPayload.alerts || []);
            currentAlertsPage = Number(alertsPayload.page || page);
            currentAlertsTotal = Number(alertsPayload.total || currentAlerts.length);
            currentAlertsTotalPages = Number(alertsPayload.totalPages || 1);
            renderSummary(statsPayload.stats || alertsPayload.stats || {});
            renderAlerts(currentAlerts, {
                total: currentAlertsTotal,
                page: currentAlertsPage,
                totalPages: currentAlertsTotalPages
            });
        }

        refreshButton?.addEventListener('click', () => {
            loadAlerts({ page: 1 }).catch(error => {
                workbench.innerHTML = `<p class="empty-state">${error.message}</p>`;
            });
        });

        workbench.addEventListener('click', async (event) => {
            const statusButton = event.target.closest('[data-alert-status]');
            const deleteButton = event.target.closest('[data-alert-delete]');
            const viewButton = event.target.closest('[data-alert-view]');
            const investigateButton = event.target.closest('[data-alert-investigate]');
            const escalateButton = event.target.closest('[data-alert-escalate]');
            const loadMoreButton = event.target.closest('[data-alert-load-more]');

            if (loadMoreButton) {
                loadMoreButton.disabled = true;
                loadMoreButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
                await loadAlerts({ page: currentAlertsPage + 1, append: true });
                return;
            }

            if (investigateButton) {
                await openInvestigation(investigateButton.dataset.alertInvestigate, { markInProgress: true });
                return;
            }

            if (statusButton) {
                const [id, status] = statusButton.dataset.alertStatus.split(':');
                await apiRequest(`/alerts/${id}`, {
                    method: 'PATCH',
                    body: JSON.stringify({ status, note: `Status updated to ${status}` })
                });
                await loadAlerts({ page: 1 });
            }

            if (deleteButton) {
                const reason = prompt('Archive reason:', 'No longer relevant') || 'No longer relevant';
                await apiRequest(`/alerts/${deleteButton.dataset.alertDelete}`, {
                    method: 'DELETE',
                    body: JSON.stringify({ reason })
                });
                    await loadAlerts({ page: 1 });
                }

            if (escalateButton) {
                window.alert('Escalation noted. Use the incident workflow to create a follow-up case.');
            }

            if (viewButton) {
                await openInvestigation(viewButton.dataset.alertView);
            }
        });

        root.addEventListener('click', async (event) => {
            if (event.target.closest('[data-close-investigation]')) {
                closeInvestigationDrawer();
                return;
            }

            const statusButton = event.target.closest('[data-investigation-status]');
            if (statusButton && activeInvestigationAlert) {
                const status = statusButton.dataset.investigationStatus;
                await apiRequest(`/alerts/${alertId(activeInvestigationAlert)}`, {
                    method: 'PATCH',
                    body: JSON.stringify({
                        status,
                        notes: [{ text: `Investigation drawer updated status to ${status}.` }]
                    })
                });
                await loadAlerts({ page: 1 });
                await openInvestigation(alertId(activeInvestigationAlert));
                if (typeof window.showNotification === 'function') {
                    window.showNotification(`Alert marked ${formatStatus(status)}`, 'success');
                }
                return;
            }

            if (event.target.closest('[data-investigation-view-logs]') && activeInvestigationAlert) {
                window.navigateTo ? window.navigateTo('logs') : (window.location.href = 'logs.html');
                return;
            }

            if (event.target.closest('[data-investigation-escalate]')) {
                window.alert('Escalation noted. Ask an admin to create or assign an incident from this investigation.');
                return;
            }

            if (event.target.closest('[data-investigation-create-incident]') && activeInvestigationAlert) {
                const selected = activeInvestigationAlert;
                const linkedLogId = selected.log && typeof selected.log === 'object'
                    ? (selected.log._id || selected.log.id)
                    : selected.log;
                const isValidSourceIP = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(String(selected.sourceIP || ''));
                const relatedCves = getRelatedCves(selected);
                const mitreTechnique = getMitreForItem(selected);
                const cveText = relatedCves.length ? `\nRelated CVEs: ${relatedCves.join(', ')}` : '';
	                const incidentPayload = {
	                    title: `Alert: ${selected.title || selected.attackType || 'Security investigation'}`,
	                    description: `${selected.description || 'Created from alert investigation.'}\n\nSource: ${selected.sourceIP || 'Unknown'}\nMITRE: ${mitreTechnique}${cveText}\nHits: ${selected.occurrenceCount || 1}`,
	                    severity: ['critical', 'high', 'medium', 'low'].includes(selected.severity) ? selected.severity : 'medium',
	                    status: 'open',
	                    category: 'other',
	                    affectedSystems: [selected.targetSystem].filter(Boolean),
	                    relatedCves,
                        threatIntel: {
                            mitreTechnique
                        },
	                    relatedLogs: linkedLogId ? [linkedLogId] : [],
                    impact: ['critical', 'high'].includes(selected.severity) ? 'high' : 'medium',
                    priority: ['critical', 'high'].includes(selected.severity) ? selected.severity : 'medium'
                };
                if (isValidSourceIP) {
                    incidentPayload.sourceIP = selected.sourceIP;
                }

                const payload = await apiRequest('/incidents', {
                    method: 'POST',
                    body: JSON.stringify(incidentPayload)
                });
                await apiRequest(`/alerts/${alertId(selected)}`, {
                    method: 'PATCH',
                    body: JSON.stringify({
                        incident: payload.incident?._id || payload.incident?.id,
                        notes: [{ text: `Incident created from investigation: ${payload.incident?.title || 'Incident'}` }]
                    })
                }).catch(() => null);
                await loadAlerts({ page: 1 });
                await openInvestigation(alertId(selected));
                if (typeof window.showNotification === 'function') {
                    window.showNotification('Incident created from alert investigation', 'success');
                }
            }
        });

        loadAlerts({ page: 1 }).catch(error => {
            workbench.innerHTML = `<p class="empty-state">${error.message}</p>`;
        });
    }

    function renderAuditLogsConsole(root) {
        const host = findContentHost(root);
        if (!host || root.dataset.auditLogsConsoleInstalled) return;
        root.dataset.auditLogsConsoleInstalled = 'true';

        const panel = root.querySelector('.feature-audit-logs-console');
        if (!panel) return;

        root.querySelector('.main-header .header-right [data-audit-refresh]')?.remove();
        const role = currentUser().role || 'analyst';
        const existingChrome = root.querySelector('.audit-logs-chrome');

        const escapeHtml = (value) => String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');

        if (!existingChrome) {
            const chrome = document.createElement('div');
            chrome.className = 'audit-logs-chrome';
            chrome.innerHTML = `
                <div class="threat-ribbon">
                    <span><i class="fas fa-shield-virus"></i> Threat Level: Elevated</span>
                    <span><i class="fas fa-satellite-dish"></i> Sensors: Online</span>
                    <span><i class="fas fa-fingerprint"></i> Identity Guard: Active</span>
                    <span><i class="fas fa-bolt"></i> AUDIT LOGS Console</span>
                </div>
                <div class="role-dashboard-strip ${role}">
                    <div>
                        <strong>${role === 'admin' ? 'Admin Command View' : 'Analyst Triage View'}</strong>
                        <span>${role === 'admin' ? 'User approvals, system-wide audit visibility, and policy controls enabled.' : 'Focused view for audit visibility and review-only operations.'}</span>
                    </div>
                    <div class="role-actions">
                        <span><i class="fas fa-user-shield"></i> ${role.toUpperCase()}</span>
                        <span><i class="fas fa-clipboard-list"></i> Audit Controls</span>
                        ${role === 'admin' ? '<span><i class="fas fa-lock-open"></i> Admin controls enabled</span>' : '<span><i class="fas fa-lock"></i> Admin controls hidden</span>'}
                    </div>
                </div>
            `;
            host.insertBefore(chrome, host.firstChild);
        }

        panel.innerHTML = `
            <div class="feature-panel-header">
                <div>
                    <h2 style="font-size:26px;font-weight:900;line-height:1.1;"><i class="fas fa-history"></i> Audit Activity</h2>
                    <p>Real activity only. Grouped by actor type and date with full event context.</p>
                </div>
                <div class="audit-logs-actions">
                    <button type="button" class="btn btn-outline" data-audit-refresh>
                        <i class="fas fa-sync"></i> Refresh
                    </button>
                </div>
            </div>
            <div class="audit-logs-toolbar">
                <input type="text" data-audit-search placeholder="Search user, action, module, target...">
                <select data-audit-time>
                    <option value="24h">Last 24 Hours</option>
                    <option value="7d" selected>Last 7 Days</option>
                    <option value="30d">Last 30 Days</option>
                    <option value="all">All Time</option>
                </select>
                <select data-audit-module>
                    <option value="all" selected>All Modules</option>
                    <option value="auth">Auth</option>
                    <option value="users">Users</option>
                    <option value="incidents">Incidents</option>
                    <option value="logs">Logs</option>
                    <option value="reports">Reports</option>
                    <option value="settings">Settings</option>
                </select>
                <select data-audit-result>
                    <option value="all" selected>All Results</option>
                    <option value="success">Success</option>
                    <option value="warning">Warning</option>
                    <option value="failure">Failure</option>
                </select>
            </div>
            <div class="audit-summary-grid" data-audit-summary></div>
            <div class="audit-role-groups" data-audit-groups></div>
            <div class="audit-drawer-backdrop" data-audit-backdrop hidden></div>
            <aside class="audit-details-drawer" data-audit-drawer hidden>
                <div class="audit-drawer-header">
                    <div>
                        <p class="audit-drawer-kicker">Audit Entry</p>
                        <h3 data-audit-drawer-title>Details</h3>
                    </div>
                    <button type="button" class="audit-drawer-close" data-audit-drawer-close aria-label="Close details">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="audit-drawer-body" data-audit-drawer-body></div>
            </aside>
        `;

        const summary = panel.querySelector('[data-audit-summary]');
        const groups = panel.querySelector('[data-audit-groups]');
        const refreshButton = panel.querySelector('[data-audit-refresh]');
        const searchInput = panel.querySelector('[data-audit-search]');
        const timeSelect = panel.querySelector('[data-audit-time]');
        const moduleSelect = panel.querySelector('[data-audit-module]');
        const resultSelect = panel.querySelector('[data-audit-result]');
        const drawer = panel.querySelector('[data-audit-drawer]');
        const drawerBackdrop = panel.querySelector('[data-audit-backdrop]');
        const drawerClose = panel.querySelector('[data-audit-drawer-close]');
        const drawerTitle = panel.querySelector('[data-audit-drawer-title]');
        const drawerBody = panel.querySelector('[data-audit-drawer-body]');

        if (!summary || !groups || !searchInput || !timeSelect || !moduleSelect || !resultSelect || !drawer || !drawerBody) return;

        timeSelect.value = 'all';

        const roleMeta = {
            admin: {
                label: 'Admin Actions',
                icon: 'fa-user-shield',
                description: 'Actions performed by administrators.'
            },
            analyst: {
                label: 'Analyst Actions',
                icon: 'fa-user-astronaut',
                description: 'Actions performed by analysts.'
            },
            system: {
                label: 'System Actions',
                icon: 'fa-gear',
                description: 'Automated system events and backend activity.'
            },
            other: {
                label: 'Other Actions',
                icon: 'fa-circle-question',
                description: 'Entries that do not match a known actor role.'
            }
        };

        let currentLogs = [];

        function normalizeRole(role) {
            const value = String(role || 'system').trim().toLowerCase();
            if (value === 'admin' || value === 'analyst' || value === 'system') return value;
            return 'other';
        }

        function isSystemAuditEvent(log = {}) {
            const action = String(log.action || '').toLowerCase();
            const module = String(log.module || '').toLowerCase();
            const details = String(log.details || '').toLowerCase();
            const metadata = log.metadata || {};
            const source = String(metadata.source || '').toLowerCase();
            const systemActions = [
                'settings updated',
                'policy/config changes',
                'policy config changes',
                'auto incident created',
                'auto incident updated',
                'security log generated',
                'bulk logs created',
                'mock logs generated',
                'alert auto generated',
                'status/health event',
                'status health event'
            ];
            const systemSources = ['bulk-live-stream', 'mock-generator', 'live-stream-auto-threshold', 'system-auto-threshold'];

            return systemActions.some(item => action.includes(item))
                || systemSources.some(item => source.includes(item))
                || Boolean(metadata.systemGenerated)
                || (module === 'settings' && action.includes('updated'))
                || (module === 'logs' && (action.includes('generated') || action.includes('bulk logs created') || details.includes('system ingested')))
                || (module === 'alerts' && action.includes('auto'))
                || (module === 'incidents' && action.includes('auto'));
        }

        function getAuditGroupRole(log = {}) {
            return isSystemAuditEvent(log) ? 'system' : normalizeRole(log.actorRole);
        }

        function formatDateLabel(value) {
            return new Date(value || Date.now()).toLocaleDateString('en-GB', {
                day: '2-digit',
                month: 'short',
                year: 'numeric'
            });
        }

        function formatDateTime(value) {
            return new Date(value || Date.now()).toLocaleString('en-GB', {
                day: '2-digit',
                month: 'short',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        }

        function formatJson(value) {
            try {
                return JSON.stringify(value || {}, null, 2);
            } catch (error) {
                return '{}';
            }
        }

        function auditDisplayValue(value) {
            if (value === null || value === undefined || value === '' || String(value).toLowerCase() === 'unknown') return 'Not Captured';
            return String(value);
        }

        function auditHash(value = '') {
            return Array.from(String(value || 'audit')).reduce((hash, char) => {
                return ((hash << 5) - hash + char.charCodeAt(0)) >>> 0;
            }, 2166136261);
        }

        function auditSeed(log = {}) {
            return [
                log.id,
                log._id,
                log.timestamp,
                log.actorEmail,
                log.action,
                log.targetLabel,
                log.targetId
            ].filter(Boolean).join('|') || 'microsoc-audit';
        }

        function mockSessionId(log = {}) {
            const hash = auditHash(auditSeed(log)).toString(16).padStart(8, '0');
            const tail = auditHash(`${auditSeed(log)}:session`).toString(36).slice(0, 6).toUpperCase();
            return `SES-${hash.slice(0, 8)}-${tail}`;
        }

        function auditLabel(value = '') {
            return String(value)
                .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
                .replace(/[_-]+/g, ' ')
                .replace(/\b\w/g, letter => letter.toUpperCase());
        }

        function renderAuditFields(fields = []) {
            const visibleFields = fields.filter(field => field && field.label && auditDisplayValue(field.value) !== 'Not Captured');
            if (!visibleFields.length) {
                return '';
            }
            return `
                <div class="audit-kv-list">
                    ${visibleFields.map(field => `
                        <div class="audit-kv-row">
                            <span>${escapeHtml(field.label)}</span>
                            <strong>${escapeHtml(auditDisplayValue(field.value))}</strong>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        function renderAuditMetadata(metadata = {}) {
            const entries = Object.entries(metadata || {})
                .filter(([key, value]) => value !== undefined && value !== null && value !== '' && typeof value !== 'object')
                .map(([key, value]) => ({ label: auditLabel(key), value }));
            return renderAuditFields(entries);
        }

        function getAuditSessionId(log = {}) {
            const targetType = String(log.targetType || '').toLowerCase();
            if (log.metadata?.sessionId) return log.metadata.sessionId;
            if (targetType.includes('session')) return log.targetId;
            return log.metadata?.session || mockSessionId(log);
        }

        function getAuditRecordId(log = {}) {
            return log.id || log._id || `AUD-${auditHash(`${auditSeed(log)}:record`).toString(16).toUpperCase()}`;
        }

        function getAuditIp(log = {}) {
            return auditDisplayValue(log.ipAddress);
        }

        function formatAuditUserAgent(userAgent) {
            const value = auditDisplayValue(userAgent);
            if (value === 'Not Captured') return value;
            const browserMatch = value.match(/(Edg|Chrome|Firefox|Version)\/([\d.]+)/i);
            const browserName = browserMatch?.[1] === 'Edg'
                ? 'Edge'
                : browserMatch?.[1] === 'Version'
                    ? 'Safari'
                    : browserMatch?.[1] || 'Browser';
            const browserVersion = browserMatch?.[2]?.split('.')[0] || '';
            const os = value.includes('Mac OS X')
                ? `macOS ${value.match(/Mac OS X ([\d_]+)/)?.[1]?.replace(/_/g, '.') || ''}`.trim()
                : value.includes('Windows NT 10')
                    ? 'Windows 10/11'
                    : value.includes('Windows')
                        ? 'Windows'
                        : value.includes('Linux')
                            ? 'Linux'
                            : value.includes('Android')
                                ? 'Android'
                                : value.includes('iPhone') || value.includes('iPad')
                                    ? 'iOS'
                                    : '';
            return [browserName + (browserVersion ? ` ${browserVersion}` : ''), os].filter(Boolean).join(' · ') || value;
        }

        function isAutomatedAuditActorEvent(log = {}) {
            const action = String(log.action || '').toLowerCase();
            const source = String(log.metadata?.source || '').toLowerCase();
            return action.includes('auto incident')
                || action.includes('alert auto generated')
                || action.includes('bulk logs created')
                || action.includes('mock logs generated')
                || action.includes('security log generated')
                || action.includes('status/health')
                || source.includes('live-stream')
                || source.includes('mock-generator')
                || source.includes('system-auto');
        }

        function getAuditDrawerActor(log = {}) {
            if (isAutomatedAuditActorEvent(log)) {
                return {
                    name: 'System',
                    email: 'system@microsoc.local',
                    role: 'system'
                };
            }

            return {
                name: log.actorName || 'System',
                email: auditDisplayValue(log.actorEmail),
                role: log.actorRole || log.metadata?.role || 'system'
            };
        }

        function renderAuditDetails(log = {}, drawerActor = getAuditDrawerActor(log)) {
            const action = String(log.action || '').toLowerCase();
            if (action.includes('logged in')) {
                return [
                    'Authentication successful.',
                    `Role: ${auditDisplayValue(drawerActor.role)}`,
                    'Access granted.'
                ].join('\n');
            }
            return log.details || 'No details captured.';
        }

        const renderSummary = (stats = {}, logs = currentLogs, pagination = {}) => {
            const visibleLogs = Array.isArray(logs) ? logs : [];
            const totalEvents = Number(pagination.total ?? stats.totalEvents?.[0]?.count ?? visibleLogs.length) || 0;
            const roleStats = Object.fromEntries((stats.byRole || []).map((item) => [normalizeRole(item._id), item.count]));
            const byRole = Object.keys(roleStats).length
                ? roleStats
                : visibleLogs.reduce((acc, log) => {
                    const role = getAuditGroupRole(log);
                    acc[role] = (acc[role] || 0) + 1;
                    return acc;
                }, {});
            const byResult = Object.fromEntries((stats.byResult || []).map((item) => [item._id, item.count]));
            const byModule = Object.fromEntries((stats.byModule || []).map((item) => [item._id, item.count]));

            summary.innerHTML = [
                ['Total Events', totalEvents, 'fa-stream'],
                ['Admin Actions', byRole.admin || 0, 'fa-user-shield'],
                ['Analyst Actions', byRole.analyst || 0, 'fa-user-astronaut'],
                ['System Actions', byRole.system || 0, 'fa-gear'],
                ['Failures', byResult.failure || 0, 'fa-triangle-exclamation']
            ].map(([title, value, icon]) => `
                <div class="stat-card">
                    <div class="stat-icon" style="background: rgba(6, 182, 212, 0.12); color: var(--soc-cyan)">
                        <i class="fas ${icon}"></i>
                    </div>
                    <div class="stat-info">
                        <h3>${escapeHtml(title)}</h3>
                        <div class="stat-value">${escapeHtml(value)}</div>
                        <div class="stat-change positive">Live</div>
                    </div>
                </div>
            `).join('');
        };

        function renderDrawer(log) {
            if (!log) return;
            drawerTitle.textContent = log.action || 'Audit Entry';
            const sessionId = getAuditSessionId(log);
            const drawerActor = getAuditDrawerActor(log);
            drawerBody.innerHTML = `
                <div class="audit-drawer-section">
                    <span class="audit-drawer-label">Timestamp</span>
                    <strong>${escapeHtml(formatDateTime(log.timestamp))}</strong>
                </div>
                <div class="audit-drawer-section">
                    <span class="audit-drawer-label">Actor</span>
                    <strong>${escapeHtml(drawerActor.name)}</strong>
                    <div class="audit-subtext">${escapeHtml(drawerActor.email)}</div>
                </div>
                <div class="audit-drawer-grid">
                    <div class="audit-drawer-section">
                        <span class="audit-drawer-label">Role</span>
                        <strong>${escapeHtml(String(drawerActor.role || 'system').toUpperCase())}</strong>
                    </div>
                    <div class="audit-drawer-section">
                        <span class="audit-drawer-label">Result</span>
                        <strong>${escapeHtml(String(log.result || 'success').toUpperCase())}</strong>
                    </div>
                    <div class="audit-drawer-section">
                        <span class="audit-drawer-label">Module</span>
                        <strong>${escapeHtml(log.module || 'general')}</strong>
                    </div>
                    <div class="audit-drawer-section">
                        <span class="audit-drawer-label">Target</span>
                        <strong>${escapeHtml(log.targetLabel || log.targetType || 'N/A')}</strong>
                    </div>
                </div>
                <div class="audit-drawer-section">
                    <span class="audit-drawer-label">Details</span>
                    <p>${escapeHtml(renderAuditDetails(log, drawerActor))}</p>
                </div>
                <div class="audit-drawer-section">
                    <span class="audit-drawer-label">Technical</span>
                    ${renderAuditFields([
                        { label: 'Session ID', value: sessionId },
                        { label: 'Record ID', value: getAuditRecordId(log) },
                        { label: 'IP', value: getAuditIp(log) },
                        { label: 'User Agent', value: formatAuditUserAgent(log.userAgent) }
                    ])}
                </div>
            `;
            drawer.hidden = false;
            drawerBackdrop.hidden = false;
            document.body.classList.add('audit-drawer-open');
        }

        function closeDrawer() {
            drawer.hidden = true;
            drawerBackdrop.hidden = true;
            document.body.classList.remove('audit-drawer-open');
        }

        function groupLogs(logs = []) {
            const roleGroups = {
                admin: [],
                analyst: [],
                system: [],
                other: []
            };

            logs.forEach((log, index) => {
                const key = getAuditGroupRole(log);
                roleGroups[key].push({ ...log, __index: index });
            });

            return roleGroups;
        }

        function renderGroups(logs = []) {
            closeDrawer();
            if (!logs.length) {
                groups.innerHTML = `
                    <div class="user-management-empty audit-empty-state">
                        No real audit activity yet for the selected filters.
                    </div>
                `;
                return;
            }

            const roleGroups = groupLogs(logs);

            groups.innerHTML = Object.entries(roleMeta)
                .map(([role, meta]) => {
                    const items = roleGroups[role] || [];
                    if (!items.length) return '';

                    const dateBuckets = items.reduce((acc, log) => {
                        const dateKey = formatDateLabel(log.timestamp);
                        if (!acc[dateKey]) acc[dateKey] = [];
                        acc[dateKey].push(log);
                        return acc;
                    }, {});

                    const dateSections = Object.entries(dateBuckets)
                        .map(([dateLabel, dateLogs]) => `
                            <article class="audit-date-group">
                                <div class="audit-date-header">
                                    <div>
                                        <h4>${escapeHtml(dateLabel)}</h4>
                                        <p>${escapeHtml(`${dateLogs.length} event${dateLogs.length === 1 ? '' : 's'}`)}</p>
                                    </div>
                                </div>
                                <div class="table-responsive">
                                    <table class="data-table audit-logs-table">
                                        <thead>
                                            <tr>
                                                <th>Time</th>
                                                <th>Actor</th>
                                                <th>Action</th>
                                                <th>Module</th>
                                                <th>Target</th>
                                                <th>Result</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${dateLogs.map((log) => `
                                                <tr class="audit-log-row" data-audit-index="${log.__index}">
                                                    <td>${escapeHtml(new Date(log.timestamp || Date.now()).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }))}</td>
                                                    <td>
                                                        <strong>${escapeHtml(log.actorName || 'System')}</strong>
                                                        <div class="audit-subtext">${escapeHtml(log.actorEmail || 'Unknown')}</div>
                                                    </td>
                                                    <td><strong>${escapeHtml(log.action || 'Action')}</strong></td>
                                                    <td><span class="audit-module">${escapeHtml(log.module || 'general')}</span></td>
                                                    <td>
                                                        <div>${escapeHtml(log.targetLabel || log.targetType || 'N/A')}</div>
                                                    </td>
                                                    <td><span class="badge badge-${log.result === 'failure' ? 'danger' : log.result === 'warning' ? 'warning' : 'success'}">${escapeHtml(String(log.result || 'success').toUpperCase())}</span></td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            </article>
                        `)
                        .join('');

                    return `
                        <section class="audit-role-group">
                            <div class="audit-role-group-header">
                                <div>
                                    <h3><i class="fas ${meta.icon}"></i> ${escapeHtml(meta.label)}</h3>
                                    <p>${escapeHtml(meta.description)}</p>
                                </div>
                                <span class="audit-role-count">${escapeHtml(items.length)}</span>
                            </div>
                            <div class="audit-date-groups">${dateSections}</div>
                        </section>
                    `;
                })
                .join('') || '<div class="user-management-empty audit-empty-state">No audit logs found for the selected filters.</div>';
        }

        async function loadAuditLogs() {
            const params = new URLSearchParams();
            params.set('timeRange', timeSelect.value);
            params.set('module', moduleSelect.value);
            params.set('result', resultSelect.value);
            params.set('search', searchInput.value.trim());
            params.set('limit', '200');

            const payload = await apiRequest(`/audit-logs?${params.toString()}`);
            currentLogs = payload.logs || [];
            renderSummary(payload.stats || {}, currentLogs, {
                total: payload.total,
                page: payload.page,
                totalPages: payload.totalPages
            });
            renderGroups(currentLogs);
        }

        groups.addEventListener('click', (event) => {
            const row = event.target.closest('[data-audit-index]');
            if (!row) return;
            const log = currentLogs[Number(row.dataset.auditIndex)];
            if (!log) return;
            renderDrawer(log);
        });

        drawerBackdrop.addEventListener('click', closeDrawer);
        drawerClose.addEventListener('click', closeDrawer);

        closeDrawer();

        refreshButton?.addEventListener('click', () => {
            loadAuditLogs().catch((error) => {
                groups.innerHTML = `<div class="user-management-empty audit-empty-state">${escapeHtml(error.message)}</div>`;
            });
        });

        [searchInput, timeSelect, moduleSelect, resultSelect].forEach((element) => {
            element.addEventListener('input', () => {
                loadAuditLogs().catch((error) => {
                    groups.innerHTML = `<div class="user-management-empty audit-empty-state">${escapeHtml(error.message)}</div>`;
                });
            });
            element.addEventListener('change', () => {
                loadAuditLogs().catch((error) => {
                    groups.innerHTML = `<div class="user-management-empty audit-empty-state">${escapeHtml(error.message)}</div>`;
                });
            });
        });

        if (!isAdminUser()) {
            summary.innerHTML = '';
            groups.innerHTML = '<div class="user-management-empty audit-empty-state">You do not have permission to view audit logs.</div>';
            return;
        }

        loadAuditLogs().catch((error) => {
            groups.innerHTML = `<div class="user-management-empty audit-empty-state">${escapeHtml(error.message)}</div>`;
        });
    }

    function renderSettingsConsole(root) {
        const panel = root.querySelector('.feature-settings-console');
        if (!panel || root.dataset.settingsConsoleInstalled) return;
        root.dataset.settingsConsoleInstalled = 'true';

        function applySettingsTheme() {
            const themeHref = document.getElementById('theme-style')?.getAttribute('href') || '';
            const isLight = themeHref.includes('light-theme') || document.body.dataset.theme === 'light' || localStorage.getItem('theme') === 'light';
            const titleColor = isLight ? '#0f172a' : '#dbeafe';
            const subtitleColor = isLight ? '#164e63' : '#94a3b8';
            const iconColor = isLight ? '#0e7490' : '#22c1dc';

            root.querySelectorAll('.main-header .header-left h1, .feature-settings-console .feature-panel-header h2').forEach((node) => {
                node.style.setProperty('color', titleColor, 'important');
                node.style.setProperty('-webkit-text-fill-color', titleColor, 'important');
                node.style.setProperty('opacity', '1', 'important');
                node.style.setProperty('text-shadow', 'none', 'important');
                node.style.setProperty('font-weight', '900', 'important');
            });

            root.querySelectorAll('.main-header .header-left h1 i, .feature-settings-console .feature-panel-header h2 i').forEach((icon) => {
                icon.style.setProperty('color', iconColor, 'important');
            });

            root.querySelectorAll('.main-header .subtitle, .feature-settings-console .feature-panel-header p').forEach((node) => {
                node.style.setProperty('color', subtitleColor, 'important');
                node.style.setProperty('-webkit-text-fill-color', subtitleColor, 'important');
                node.style.setProperty('opacity', '1', 'important');
            });
        }

        function scheduleSettingsThemeApply() {
            applySettingsTheme();
            requestAnimationFrame(applySettingsTheme);
            setTimeout(applySettingsTheme, 80);
        }

        const escapeHtml = (value) => String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');

        if (!isAdminUser()) {
            panel.innerHTML = `
                <div class="feature-panel-header">
                    <div>
                        <h2><i class="fas fa-cogs"></i> Settings</h2>
                        <p>Admin-only access. Ask an administrator to update SOC controls.</p>
                    </div>
                </div>
                <div class="user-management-empty audit-empty-state">You do not have permission to view settings.</div>
            `;
            return;
        }

        const defaults = {
            generalSettings: {
                theme: 'dark',
                autoRefreshEnabled: true,
                refreshIntervalSeconds: 30
            },
            alertConfig: {
                failedLoginThreshold: 5,
                otherAlertsThreshold: 1
            },
            incidentConfig: {
                createIncidentAfter: 3,
                severityEscalationEnabled: true
            },
            aiSettings: {
                analysisEnabled: true,
                autoGenerateRecommendations: true
            },
            notificationSettings: {
                emailNotifications: true,
                criticalAlertNotifications: true,
                incidentAssignmentNotifications: true
            }
        };

        let originalSettings = null;
        const SETTINGS_CACHE_KEY = 'microsocSystemSettingsCache';
        let statusState = {
            backend: 'loading',
            database: 'loading',
            websocket: 'loading',
            ai: 'loading'
        };
        let draftSettings = JSON.parse(JSON.stringify(defaults));

        function getCachedSettings() {
            try {
                const cached = JSON.parse(localStorage.getItem(SETTINGS_CACHE_KEY) || 'null');
                return cached && typeof cached === 'object' ? cached : null;
            } catch (error) {
                return null;
            }
        }

        function cacheSettings(settings) {
            if (!settings) return;
            localStorage.setItem(SETTINGS_CACHE_KEY, JSON.stringify({
                ...settings,
                _cachedAt: new Date().toISOString()
            }));
        }

        function pickNewestSettings(serverSettings, cachedSettings) {
            if (!serverSettings) return cachedSettings || defaults;
            if (!cachedSettings) return serverSettings;

            const serverTime = new Date(serverSettings.updatedAt || serverSettings._cachedAt || 0).getTime();
            const cachedTime = new Date(cachedSettings._cachedAt || cachedSettings.updatedAt || 0).getTime();
            return cachedTime > serverTime ? cachedSettings : serverSettings;
        }

        panel.innerHTML = `
            <div class="settings-inline-intro">
                <p>General settings, alert configuration, incident automation, AI, notifications, and live system status.</p>
            </div>

            <div class="settings-summary-grid" data-settings-summary></div>

            <div class="settings-grid">
                <section class="settings-card settings-card-wide">
                    <div class="settings-card-header">
                        <h3><i class="fas fa-sliders-h"></i> 1. General Settings</h3>
                        <p>Theme and dashboard refresh behavior.</p>
                    </div>
                    <div class="settings-fields" data-settings-general></div>
                </section>

                <section class="settings-card settings-card-wide">
                    <div class="settings-card-header">
                        <h3><i class="fas fa-bell"></i> 2. Alert Configuration</h3>
                        <p>Thresholds that map directly to your detection architecture.</p>
                    </div>
                    <div class="settings-fields" data-settings-alerts></div>
                </section>

                <section class="settings-card settings-card-wide">
                    <div class="settings-card-header">
                        <h3><i class="fas fa-sitemap"></i> 3. Incident Configuration</h3>
                        <p>Rules for auto-creating and escalating incidents.</p>
                    </div>
                    <div class="settings-fields" data-settings-incidents></div>
                </section>

                <section class="settings-card settings-card-wide">
                    <div class="settings-card-header">
                        <h3><i class="fas fa-robot"></i> 4. AI Settings</h3>
                        <p>Control how much AI assists the SOC workflow.</p>
                    </div>
                    <div class="settings-fields" data-settings-ai></div>
                </section>

                <section class="settings-card settings-card-wide">
                    <div class="settings-card-header">
                        <h3><i class="fas fa-envelope"></i> 5. Notification Settings</h3>
                        <p>Keep the right people informed at the right time.</p>
                    </div>
                    <div class="settings-fields" data-settings-notifications></div>
                </section>

                <section class="settings-card settings-card-status">
                    <div class="settings-card-header">
                        <h3><i class="fas fa-circle-nodes"></i> 6. System Status</h3>
                        <p>Read-only endpoint checks from the live app.</p>
                    </div>
                    <div class="settings-status-grid" data-settings-status>
                        <div class="settings-status-item"><strong>Backend API</strong><span>Checking...</span></div>
                        <div class="settings-status-item"><strong>Database</strong><span>Checking...</span></div>
                        <div class="settings-status-item"><strong>WebSocket</strong><span>Checking...</span></div>
                        <div class="settings-status-item"><strong>AI Service</strong><span>Checking...</span></div>
                    </div>
                </section>
            </div>
        `;
        applySettingsTheme();

        const summary = panel.querySelector('[data-settings-summary]');
        const generalFields = panel.querySelector('[data-settings-general]');
        const alertFields = panel.querySelector('[data-settings-alerts]');
        const incidentFields = panel.querySelector('[data-settings-incidents]');
        const aiFields = panel.querySelector('[data-settings-ai]');
        const notificationFields = panel.querySelector('[data-settings-notifications]');
        const statusGrid = panel.querySelector('[data-settings-status]');
        const saveButton = root.querySelector('[data-settings-save]');

        if (!summary || !generalFields || !alertFields || !incidentFields || !aiFields || !notificationFields || !statusGrid || !saveButton) {
            return;
        }

        function setThemePreview(theme) {
            const normalized = String(theme || 'dark').toLowerCase() === 'light' ? 'light' : 'dark';
            document.body.dataset.theme = normalized;
            document.documentElement.dataset.theme = normalized;
            localStorage.setItem('theme', normalized);
            updateThemeIcon(normalized);
            const themeStyle = document.getElementById('theme-style');
            if (themeStyle) {
                themeStyle.setAttribute('href', `css/${normalized}-theme.css?v=20260623t`);
            }
            scheduleSettingsThemeApply();
            window.dispatchEvent(new CustomEvent('microsoc:theme-changed', {
                detail: { theme: normalized }
            }));
        }

        function renderSummaryView() {
            summary.innerHTML = [
                ['Theme', draftSettings.generalSettings.theme === 'light' ? 'Light' : 'Dark', 'fa-palette'],
                ['Auto Refresh', draftSettings.generalSettings.autoRefreshEnabled ? 'Enabled' : 'Disabled', 'fa-arrows-rotate'],
                ['Alert Rules', `Login ${draftSettings.alertConfig.failedLoginThreshold} / Other ${draftSettings.alertConfig.otherAlertsThreshold}`, 'fa-bell'],
                ['AI', draftSettings.aiSettings.analysisEnabled ? 'On' : 'Off', 'fa-robot']
            ].map(([title, value, icon]) => `
                <div class="stat-card">
                    <div class="stat-icon" style="background: rgba(6, 182, 212, 0.12); color: var(--soc-cyan)">
                        <i class="fas ${icon}"></i>
                    </div>
                    <div class="stat-info">
                        <h3>${escapeHtml(title)}</h3>
                        <div class="stat-value">${escapeHtml(value)}</div>
                        <div class="stat-change positive">Live</div>
                    </div>
                </div>
            `).join('');
        }

        function radioGroup(path, label, options, help) {
            const [section, key] = path.split('.');
            const current = String(draftSettings[section]?.[key] || options[0].value);
            return `
                <label class="settings-control">
                    <div class="settings-control-head">
                        <span>${escapeHtml(label)}</span>
                    </div>
                    <div class="settings-radio-group">
                        ${options.map((option) => `
                            <label class="settings-radio ${current === option.value ? 'active' : ''}">
                                <input type="radio" name="${path}" value="${escapeHtml(option.value)}" ${current === option.value ? 'checked' : ''} data-setting-radio="${path}">
                                <span>${escapeHtml(option.label)}</span>
                            </label>
                        `).join('')}
                    </div>
                    <small>${escapeHtml(help)}</small>
                </label>
            `;
        }

        function toggleControl(path, label, help) {
            const [section, key] = path.split('.');
            const checked = Boolean(draftSettings[section]?.[key]);
            return `
                <label class="settings-toggle">
                    <div>
                        <span>${escapeHtml(label)}</span>
                        <small>${escapeHtml(help)}</small>
                    </div>
                    <input type="checkbox" ${checked ? 'checked' : ''} data-setting-toggle="${path}">
                </label>
            `;
        }

        function numberControl(path, label, help, min, max, step = 1) {
            const [section, key] = path.split('.');
            const value = Number(draftSettings[section]?.[key] ?? defaults[section]?.[key] ?? min);
            const unit = path === 'generalSettings.refreshIntervalSeconds' ? ' sec' : '';
            return `
                <label class="settings-control">
                    <div class="settings-control-head">
                        <span>${escapeHtml(label)}</span>
                        <strong data-setting-value="${escapeHtml(path)}">${escapeHtml(`${value}${unit}`)}</strong>
                    </div>
                    <input type="number" min="${min}" max="${max}" step="${step}" value="${escapeHtml(value)}" data-setting-number="${path}">
                    <small>${escapeHtml(help)}${unit ? ' Unit: seconds.' : ''}</small>
                </label>
            `;
        }

        function renderForms() {
            generalFields.innerHTML = `
                ${radioGroup('generalSettings.theme', 'Theme', [
                    { value: 'dark', label: 'Dark' },
                    { value: 'light', label: 'Light' }
                ], 'Theme changes the command center look instantly.')}
                ${toggleControl('generalSettings.autoRefreshEnabled', 'Auto Refresh', 'Keep live dashboards updating automatically.')}
                ${numberControl('generalSettings.refreshIntervalSeconds', 'Refresh Interval', 'How often the page refreshes live data.', 5, 300, 5)}
            `;

            alertFields.innerHTML = `
                ${numberControl('alertConfig.failedLoginThreshold', 'Failed Login Threshold', 'How many failed logins trigger alerting.', 1, 100, 1)}
                ${numberControl('alertConfig.otherAlertsThreshold', 'Other Alerts Threshold', 'How many non-login attack logs trigger alerting. Set 1 for instant alerts.', 1, 1000, 1)}
                <div class="settings-help-card">
                    <strong>Detection Rules</strong>
                    <p>Security logs are always stored. Failed logins use their own threshold; every other attack type uses Other Alerts Threshold.</p>
                </div>
            `;

            incidentFields.innerHTML = `
                ${numberControl('incidentConfig.createIncidentAfter', 'Create Incident After', 'How many similar alerts auto-create an incident.', 1, 20, 1)}
                ${toggleControl('incidentConfig.severityEscalationEnabled', 'Severity Escalation', 'Escalate repeated alerts into incidents automatically.')}
            `;

            aiFields.innerHTML = `
                ${toggleControl('aiSettings.analysisEnabled', 'AI Analysis', 'Enable AI-assisted summaries and triage.')}
                ${toggleControl('aiSettings.autoGenerateRecommendations', 'Auto Generate Recommendations', 'Let AI generate response suggestions automatically.')}
            `;

            notificationFields.innerHTML = `
                ${toggleControl('notificationSettings.emailNotifications', 'Email Notifications', 'Send security updates to email.')}
                ${toggleControl('notificationSettings.criticalAlertNotifications', 'Critical Alert Notifications', 'Notify on critical detections immediately.')}
                ${toggleControl('notificationSettings.incidentAssignmentNotifications', 'Incident Assignment Notifications', 'Notify analysts when an incident is assigned to them.')}
            `;
        }

        function syncDraftFromInputs() {
            panel.querySelectorAll('[data-setting-toggle]').forEach((input) => {
                const [section, key] = input.dataset.settingToggle.split('.');
                if (!draftSettings[section]) draftSettings[section] = {};
                draftSettings[section][key] = input.checked;
            });

            panel.querySelectorAll('[data-setting-number]').forEach((input) => {
                const [section, key] = input.dataset.settingNumber.split('.');
                if (!draftSettings[section]) draftSettings[section] = {};
                const fallback = originalSettings?.[section]?.[key] ?? defaults[section]?.[key] ?? 0;
                const parsed = Number(input.value);
                draftSettings[section][key] = Number.isFinite(parsed) && input.value !== '' ? parsed : fallback;
            });

            panel.querySelectorAll('[data-setting-radio]').forEach((input) => {
                const [section, key] = input.dataset.settingRadio.split('.');
                if (!draftSettings[section]) draftSettings[section] = {};
                if (input.checked) {
                    draftSettings[section][key] = input.value;
                }
            });
        }

        function setFormValues(settings) {
            const incomingAlertConfig = settings?.alertConfig || {};
            const themeHref = document.getElementById('theme-style')?.getAttribute('href') || '';
            const activeTheme = themeHref.includes('light-theme') || document.body.dataset.theme === 'light' || localStorage.getItem('theme') === 'light'
                ? 'light'
                : 'dark';
            draftSettings = {
                generalSettings: { ...defaults.generalSettings, ...(settings?.generalSettings || {}), theme: activeTheme },
                alertConfig: {
                    failedLoginThreshold: incomingAlertConfig.failedLoginThreshold ?? defaults.alertConfig.failedLoginThreshold,
                    otherAlertsThreshold: incomingAlertConfig.otherAlertsThreshold ?? defaults.alertConfig.otherAlertsThreshold
                },
                incidentConfig: { ...defaults.incidentConfig, ...(settings?.incidentConfig || {}) },
                aiSettings: { ...defaults.aiSettings, ...(settings?.aiSettings || {}) },
                notificationSettings: { ...defaults.notificationSettings, ...(settings?.notificationSettings || {}) }
            };
            renderForms();
            renderSummaryView();
        }

        function syncSettingsThemeFromEvent(event) {
            if (!document.body.contains(panel)) return;
            const normalized = String(event.detail?.theme || localStorage.getItem('theme') || 'dark').toLowerCase() === 'light' ? 'light' : 'dark';
            if (!draftSettings.generalSettings) draftSettings.generalSettings = {};
            const changed = draftSettings.generalSettings.theme !== normalized;
            draftSettings.generalSettings.theme = normalized;
            if (changed) {
                renderForms();
                renderSummaryView();
            }
            scheduleSettingsThemeApply();
        }

        function renderStatus(statusPayload = {}) {
            const statuses = [
                {
                    label: 'Backend API',
                    ok: statusPayload.backend !== 'down',
                    detail: statusPayload.backendDetail || 'Connected'
                },
                {
                    label: 'Database',
                    ok: statusPayload.database !== 'down',
                    detail: statusPayload.databaseDetail || 'Connected'
                },
                {
                    label: 'WebSocket',
                    ok: statusPayload.websocket !== 'down',
                    detail: statusPayload.websocketDetail || 'Connected'
                },
                {
                    label: 'AI Service',
                    ok: statusPayload.ai !== 'down',
                    detail: statusPayload.aiDetail || 'Connected'
                }
            ];

            statusGrid.innerHTML = statuses.map((item) => `
                <div class="settings-status-item ${item.ok ? 'online' : 'offline'}">
                    <strong>${escapeHtml(item.label)}</strong>
                    <span>${item.ok ? '🟢' : '🔴'} ${escapeHtml(item.detail)}</span>
                </div>
            `).join('');
        }

        async function loadSystemStatus() {
            const [health, realtime, ai] = await Promise.allSettled([
                apiRequest('/health'),
                apiRequest('/realtime/status'),
                apiRequest('/ai/status')
            ]);

            statusState = {
                backend: health.status === 'fulfilled' ? 'up' : 'down',
                database: health.status === 'fulfilled' && String(health.value.database || '').toLowerCase() === 'connected' ? 'up' : 'down',
                websocket: realtime.status === 'fulfilled' && realtime.value.success ? 'up' : 'down',
                ai: ai.status === 'fulfilled' && ai.value.success && ai.value.healthy !== false ? 'up' : 'down',
                backendDetail: health.status === 'fulfilled' ? 'Connected' : 'Unavailable',
                databaseDetail: health.status === 'fulfilled' ? String(health.value.database || 'unknown') : 'Unavailable',
                websocketDetail: realtime.status === 'fulfilled' && realtime.value.success ? 'Connected' : 'Unavailable',
                aiDetail: ai.status === 'fulfilled' && ai.value.success ? `${ai.value.provider || 'ai'} / ${ai.value.model || 'status'}` : 'Unavailable'
            };

            renderStatus(statusState);
        }

        async function loadSettings() {
            const cached = getCachedSettings();
            if (cached) {
                originalSettings = cached;
                setFormValues(cached);
            }

            const payload = await apiRequest('/settings');
            const loadedSettings = pickNewestSettings(payload.settings, cached);
            originalSettings = loadedSettings;
            cacheSettings(loadedSettings);
            setFormValues(loadedSettings);
            await loadSystemStatus();
        }

        async function saveSettings(options = {}) {
            syncDraftFromInputs();
            const pendingSettings = JSON.parse(JSON.stringify(draftSettings));
            const actionButton = options.button || null;
            const originalButtonHtml = actionButton?.innerHTML;

            if (actionButton) {
                actionButton.disabled = true;
                actionButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';
            }

            const payload = await apiRequest('/settings', {
                method: 'PATCH',
                body: JSON.stringify(pendingSettings)
            });
            const savedSettings = {
                ...(payload.settings || {}),
                ...pendingSettings
            };
            originalSettings = savedSettings;
            cacheSettings(savedSettings);
            window.dispatchEvent(new CustomEvent('microsoc:settings-updated', {
                detail: { settings: savedSettings }
            }));
            setFormValues(savedSettings);
            setThemePreview(savedSettings.generalSettings?.theme || pendingSettings.generalSettings?.theme);
            await loadSystemStatus();

            if (options.statusSelector) {
                const stateNode = panel.querySelector(options.statusSelector);
                if (stateNode) {
                    stateNode.textContent = options.statusText || 'Updated. New detection rules apply to new logs.';
                }
            }

            if (actionButton) {
                actionButton.disabled = false;
                actionButton.innerHTML = originalButtonHtml;
            }

            if (typeof window.showNotification === 'function') {
                window.showNotification(options.message || 'Settings saved successfully', 'success');
            }
        }

        panel.addEventListener('input', (event) => {
            if (event.target.matches('[data-setting-number]')) {
                const [section, key] = event.target.dataset.settingNumber.split('.');
                if (!draftSettings[section]) draftSettings[section] = {};
                const fallback = originalSettings?.[section]?.[key] ?? defaults[section]?.[key] ?? 0;
                const parsed = Number(event.target.value);
                draftSettings[section][key] = Number.isFinite(parsed) && event.target.value !== '' ? parsed : fallback;
                const valueNode = panel.querySelector(`[data-setting-value="${section}.${key}"]`);
                if (valueNode) {
                    const unit = `${section}.${key}` === 'generalSettings.refreshIntervalSeconds' ? ' sec' : '';
                    valueNode.textContent = `${event.target.value || fallback}${unit}`;
                }
                renderSummaryView();
            }
        });

        panel.addEventListener('change', (event) => {
            if (event.target.matches('[data-setting-toggle]')) {
                syncDraftFromInputs();
                renderSummaryView();
            }

            if (event.target.matches('[data-setting-radio]')) {
                syncDraftFromInputs();
                setThemePreview(event.target.value);
                renderSummaryView();
            }

            if (event.target.matches('[data-setting-number]')) {
                syncDraftFromInputs();
                renderSummaryView();
            }
        });

        if (window.__microsocSettingsThemeSync) {
            window.removeEventListener('microsoc:theme-changed', window.__microsocSettingsThemeSync);
        }
        window.__microsocSettingsThemeSync = syncSettingsThemeFromEvent;
        window.addEventListener('microsoc:theme-changed', syncSettingsThemeFromEvent);

        saveButton.addEventListener('click', () => {
            saveSettings({
                button: saveButton,
                message: 'Settings saved successfully'
            }).catch((error) => {
                saveButton.disabled = false;
                saveButton.innerHTML = '<i class="fas fa-save"></i> Save Changes';
                if (typeof window.showNotification === 'function') {
                    window.showNotification(error.message, 'error');
                } else {
                    window.alert(error.message);
                }
            });
        });

        loadSettings().catch((error) => {
            panel.innerHTML = `
                <div class="feature-panel-header">
                    <div>
                        <h2><i class="fas fa-cogs"></i> Settings</h2>
                        <p>Could not load settings.</p>
                    </div>
                </div>
                <div class="user-management-empty audit-empty-state">${escapeHtml(error.message)}</div>
            `;
        });
    }

    function renderIncidentConsole(root) {
        if (root.querySelector('#incidents-table')) {
            return;
        }
        const host = findContentHost(root);
        if (root.querySelector('.feature-incident-console')) return;
        const role = currentUser().role || 'analyst';
        let currentIncidents = [];
        const panel = document.createElement('section');
        panel.className = 'feature-panel feature-incident-console';
        panel.innerHTML = role === 'admin' ? `
            <div class="feature-panel-header">
                <div>
                    <h2>Incident Management</h2>
                    <p>Create, assign, resolve, and track timeline events across the SOC.</p>
                </div>
            </div>
            <form class="incident-quick-form">
                <input name="title" placeholder="Incident title" required>
                <select name="severity"><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
                <input name="sourceIP" placeholder="Source IP">
                <button type="submit" class="btn btn-primary"><i class="fas fa-plus"></i> Create</button>
            </form>
            <div class="incident-workbench" data-incident-workbench></div>
        ` : `
            <div class="feature-panel-header">
                <div>
                    <h2>My Incidents</h2>
                    <p>Only incidents assigned to you can be updated from this view.</p>
                </div>
            </div>
            <div class="incident-workbench" data-incident-workbench></div>
        `;
        host.prepend(panel);
        const workbench = panel.querySelector('[data-incident-workbench]');

        function loadLocalIncidents() {
            try {
                const incidents = JSON.parse(localStorage.getItem('microsocLocalIncidents') || '[]');
                return Array.isArray(incidents) ? incidents : [];
            } catch (error) {
                return [];
            }
        }

        function mergeIncidents(backendIncidents = []) {
            const enrichIncident = (incident) => {
                const assignedUser = incident.assignedTo && typeof incident.assignedTo === 'object' ? incident.assignedTo : null;
                return {
                    ...incident,
                    assignedToId: assignedUser ? (assignedUser.id || assignedUser._id || '') : (incident.assignedToId || ''),
                    assignedToLabel: assignedUser
                        ? `${assignedUser.name || ''}${assignedUser.name && assignedUser.email ? ' · ' : ''}${assignedUser.email || ''}`.trim() || assignedUser.name || assignedUser.email
                        : (incident.assignedToLabel || incident.assignedTo || '')
                };
            };
            const merged = backendIncidents.map(enrichIncident);
            const seen = new Set(backendIncidents.map((incident) => String(incident._id || incident.id)));
            loadLocalIncidents().map(enrichIncident).forEach((incident) => {
                const key = String(incident._id || incident.id);
                if (!seen.has(key)) {
                    seen.add(key);
                    merged.push(incident);
                }
            });
            return merged.sort((a, b) => new Date(b.createdAt || b.updatedAt || 0) - new Date(a.createdAt || a.updatedAt || 0));
        }

        let assignableUsersCache = [];

        async function loadAssignableUsers() {
            if (assignableUsersCache.length) {
                return assignableUsersCache;
            }

            const payload = await apiRequest('/users');
            assignableUsersCache = (payload.users || [])
                .filter(user => user && user.role !== 'viewer' && user.isActive !== false && user.approvalStatus === 'approved')
                .sort((a, b) => {
                    if (a.role !== b.role) return a.role === 'admin' ? -1 : 1;
                    return String(a.name || a.email || '').localeCompare(String(b.name || b.email || ''));
                });
            return assignableUsersCache;
        }

        function ensureAssignModal() {
            let modal = document.getElementById('incident-assign-modal');
            if (modal) return modal;

            modal = document.createElement('div');
            modal.id = 'incident-assign-modal';
            modal.className = 'modal hidden';
            modal.innerHTML = `
                <div class="modal-content modal-lg">
                    <div class="modal-header">
                        <h3><i class="fas fa-user-plus"></i> Assign Incident</h3>
                        <button class="close-modal" type="button" data-close-assign>&times;</button>
                    </div>
                    <div class="modal-body">
                        <div class="timeline-incident-summary" data-assign-summary style="margin-bottom:16px;"></div>
                        <div class="form-group">
                            <label for="incident-assign-user">Assign to</label>
                            <select id="incident-assign-user">
                                <option value="">Loading users...</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="incident-assign-note">Note</label>
                            <textarea id="incident-assign-note" rows="4" placeholder="Optional note for the timeline"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-outline" type="button" data-close-assign>Cancel</button>
                        <button class="btn btn-primary" type="button" data-submit-assign>
                            <i class="fas fa-user-check"></i> Save Assignment
                        </button>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
            modal.addEventListener('click', (event) => {
                if (event.target === modal || event.target.closest('[data-close-assign]')) {
                    closeAssignModal();
                    return;
                }
                if (event.target.closest('[data-submit-assign]')) {
                    submitAssignModal().catch((error) => {
                        console.error('Incident assignment failed:', error);
                        if (typeof window.showNotification === 'function') {
                            window.showNotification(error.message || 'Incident assignment failed', 'error');
                        } else {
                            window.alert(error.message || 'Incident assignment failed');
                        }
                    });
                }
            });
            return modal;
        }

        function renderAssignSummary(incident) {
            const summary = document.querySelector('[data-assign-summary]');
            if (!summary) return;
            summary.innerHTML = `
                <h4>${escapeHtml(incident.title || 'Incident')}</h4>
                <p>${escapeHtml(incident.description || 'No description')}</p>
                <div class="timeline-incident-meta">
                    <span class="badge badge-danger">${escapeHtml(String(incident.severity || 'medium').toUpperCase())}</span>
                    <span class="status-badge status-${escapeHtml(incident.status || 'open')}">${escapeHtml(String(incident.status || 'open').replace('_', ' ').toUpperCase())}</span>
                    <span>Current assignee: ${escapeHtml(incident.assignedToLabel || incident.assignedTo || 'Unassigned')}</span>
                </div>
            `;
        }

        async function openAssignModal(incidentId) {
            const incident = currentIncidents.find(item => String(item._id || item.id) === String(incidentId));
            if (!incident) return;

            const modal = ensureAssignModal();
            modal.dataset.incidentId = String(incidentId);
            renderAssignSummary(incident);

            const select = document.getElementById('incident-assign-user');
            const note = document.getElementById('incident-assign-note');
            if (select) {
                select.disabled = true;
                select.innerHTML = '<option value="">Loading users...</option>';
            }
            if (note) note.value = '';

            try {
                const users = await loadAssignableUsers();
                if (select) {
                    select.innerHTML = '<option value="">Unassigned</option>';
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
                        select.appendChild(option);
                    });
                    select.disabled = false;
                }
            } catch (error) {
                console.error('Failed to load users for assignment:', error);
                if (select) {
                    select.innerHTML = '<option value="">Unassigned</option><option value="" disabled>Unable to load users</option>';
                    select.disabled = false;
                }
            }

            modal.classList.remove('hidden');
            document.body.style.overflow = 'hidden';
        }

        function closeAssignModal() {
            const modal = document.getElementById('incident-assign-modal');
            if (modal) {
                delete modal.dataset.incidentId;
                modal.classList.add('hidden');
            }
            document.body.style.overflow = '';
        }

        async function submitAssignModal() {
            const modal = document.getElementById('incident-assign-modal');
            const incidentId = modal?.dataset?.incidentId;
            if (!incidentId) return;

            const userId = document.getElementById('incident-assign-user')?.value || '';
            const note = document.getElementById('incident-assign-note')?.value?.trim() || '';

            await apiRequest(`/incidents/${incidentId}/assign`, {
                method: 'PUT',
                body: JSON.stringify({
                    userId: userId || null,
                    note: note || undefined
                })
            });

            closeAssignModal();
            assignableUsersCache = [];
            loadIncidents();
        }

        async function loadIncidents() {
            const query = '/incidents?limit=8';
            const data = await apiRequest(query);
            const incidents = mergeIncidents(data.incidents || []);
            currentIncidents = incidents;
	            workbench.innerHTML = incidents.map(incident => {
                    const cveBadges = renderCveBadges(incident);
                    return `
	                <article class="incident-ticket ${incident.severity}">
	                    <div>
	                        <strong>${incident.title}</strong>
	                        <span>${incident.status.replace('_', ' ')} · ${incident.severity}</span>
                            <div class="alert-meta" style="margin-top:8px;">
                                <span><i class="fas fa-fingerprint"></i> ${escapeInline(getMitreForItem(incident))}</span>
                            </div>
	                        ${cveBadges ? `<div class="alert-meta" style="margin-top:8px;">
	                            <span><i class="fas fa-bug"></i> ${renderCveBadges(incident)}</span>
	                        </div>` : ''}
	                    </div>
                    <div class="ticket-actions">
                        <button type="button" data-status="${incident._id || incident.id}:in_progress">In Progress</button>
                        <button type="button" data-status="${incident._id || incident.id}:resolved">Resolve</button>
                        <button type="button" data-timeline="${incident._id || incident.id}">Timeline</button>
                        ${role === 'admin' ? '<button type="button" data-assign-incident>Assign</button>' : ''}
                        ${role === 'admin' ? '<button type="button" data-admin-incident="edit">Edit</button>' : '<button type="button" data-admin-incident="note">Add Note</button>'}
                    </div>
                </article>
            `;
                }).join('') || '<p class="empty-state">No incidents yet.</p>';
        }

        if (role === 'admin') {
            panel.querySelector('form').addEventListener('submit', async (event) => {
                event.preventDefault();
                const form = new FormData(event.currentTarget);
                const relatedCves = getThreatContextForAttack(form.get('title')).cves;
                const mitreTechnique = getThreatContextForAttack(form.get('title')).mitre;
                const cveText = relatedCves.length ? `\n\nRelated CVEs: ${relatedCves.join(', ')}` : '';
                await apiRequest('/incidents', {
                    method: 'POST',
	                    body: JSON.stringify({
	                        title: form.get('title'),
	                        description: `${form.get('severity')} incident created from analyst console\n\nMITRE: ${mitreTechnique}${cveText}`,
	                        severity: form.get('severity'),
	                        sourceIP: form.get('sourceIP') || undefined,
	                        relatedCves,
                            threatIntel: {
                                mitreTechnique
                            },
	                        category: 'other'
	                    })
                });
                event.currentTarget.reset();
                loadIncidents();
            });
        }

        workbench.addEventListener('click', async (event) => {
            const statusButton = event.target.closest('[data-status]');
            const timelineButton = event.target.closest('[data-timeline]');
            const assignButton = event.target.closest('[data-assign-incident]');
            const adminButton = event.target.closest('[data-admin-incident]');
            if (statusButton) {
                const [id, status] = statusButton.dataset.status.split(':');
                await apiRequest(`/incidents/${id}/status`, {
                    method: 'PUT',
                    body: JSON.stringify({ status, note: `Status changed to ${status}` })
                });
                loadIncidents();
            }
            if (assignButton && role === 'admin') {
                const ticket = event.target.closest('.incident-ticket');
                const statusValue = ticket?.querySelector('[data-status]')?.dataset.status || '';
                const incidentId = statusValue.split(':')[0];
                if (incidentId) {
                    openAssignModal(incidentId);
                }
            }
            if (timelineButton) {
                await apiRequest(`/incidents/${timelineButton.dataset.timeline}/timeline`, {
                    method: 'POST',
                    body: JSON.stringify({ action: 'Analyst review', note: 'Timeline checkpoint added from console' })
                });
                loadIncidents();
            }
            if (adminButton) {
                if (role === 'admin') {
                    window.alert('Edit incident in the incidents tab.');
                } else {
                    const note = window.prompt('Add a note for this incident:', 'Analyst note');
                    if (note) {
                        const activeTicket = event.target.closest('.incident-ticket');
                        const incidentId = activeTicket?.querySelector('[data-status]')?.dataset.status?.split(':')?.[0];
                        if (incidentId) {
                            await apiRequest(`/incidents/${incidentId}/timeline`, {
                                method: 'POST',
                                body: JSON.stringify({ action: 'Analyst note', note })
                            });
                            loadIncidents();
                        }
                    }
                }
            }
        });

        loadIncidents().catch(error => {
            workbench.innerHTML = `<p class="empty-state">${error.message}</p>`;
        });
    }

    async function renderAttackVisualization(root) {
        const host = findContentHost(root);
        root.querySelector('.feature-attack-viz')?.remove();
        const panel = document.createElement('section');
        panel.className = 'feature-panel feature-attack-viz';
        panel.innerHTML = `
            <div class="feature-panel-header">
                <div>
                    <h2>Attack Visualization</h2>
                    <p>Source IP hotspots, world map signals, and attack trend graph.</p>
                </div>
            </div>
            <div class="attack-viz-grid">
                <div class="attack-map" data-attack-map></div>
                <div class="trend-bars" data-trend-bars></div>
            </div>
        `;
        host.appendChild(panel);
        const map = panel.querySelector('[data-attack-map]');
        const bars = panel.querySelector('[data-trend-bars]');
        map.innerHTML = '<div class="empty-state">Loading live attack sources...</div>';
        bars.innerHTML = '<div class="empty-state">Loading live trends...</div>';

        function loadLocalSecurityLogs() {
            try {
                const logs = JSON.parse(localStorage.getItem('microsocSecurityLogs') || '[]');
                return Array.isArray(logs) ? logs : [];
            } catch (error) {
                return [];
            }
        }

        function buildHourlyTrendFromLogs(logs) {
            const now = Date.now();
            const oneDayAgo = now - (24 * 60 * 60 * 1000);
            const buckets = new Map();

            logs.forEach((log) => {
                const timestamp = new Date(log.timestamp || log.createdAt).getTime();
                if (!Number.isFinite(timestamp) || timestamp < oneDayAgo) return;

                const date = new Date(timestamp);
                const key = `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}-${date.getHours()}`;
                const current = buckets.get(key) || {
                    _id: { day: date.getDate(), hour: date.getHours() },
                    count: 0,
                    timestamp
                };
                current.count += 1;
                buckets.set(key, current);
            });

            return Array.from(buckets.values()).sort((a, b) => a.timestamp - b.timestamp);
        }

        function renderTrendBars(hourlyTrend) {
            const maxTrend = Math.max(...hourlyTrend.map(item => item.count || 1), 1);
            bars.innerHTML = hourlyTrend.length
                ? hourlyTrend.map((item) => {
                    const value = item.count || 0;
                    const label = item._id?.hour !== undefined ? `${String(item._id.hour).padStart(2, '0')}:00` : 'bucket';
                    const height = Math.max(12, (value / maxTrend) * 220);
                    return `
                        <div class="trend-bar-item" title="${label}: ${value} attacks">
                            <span style="height:${height}px"></span>
                            <strong>${value}</strong>
                            <small>${label}</small>
                        </div>
                    `;
                }).join('')
                : '<div class="empty-state">No trend data yet. Start live stream to generate local trend bars.</div>';
        }

        try {
            const [attackMap, stats] = await Promise.all([
                apiRequest('/dashboard/attack-map'),
                apiRequest('/logs/stats?timeRange=24h')
            ]);
            const coordinates = {
                US: [24, 38], USA: [24, 38], RU: [63, 28], Russia: [63, 28],
                CN: [76, 44], China: [76, 44], IN: [69, 55], India: [69, 55],
                BR: [36, 70], Brazil: [36, 70], DE: [52, 35], Germany: [52, 35],
                JP: [82, 46], Japan: [82, 46], KR: [79, 43], UK: [48, 33]
            };
            const countryDisplayNames = {
                US: 'United States',
                RU: 'Russia',
                CN: 'China',
                IN: 'India',
                BR: 'Brazil',
                DE: 'Germany',
                JP: 'Japan',
                KR: 'South Korea',
                UK: 'United Kingdom'
            };
            const countryAliases = {
                'united states': 'US',
                'united states of america': 'US',
                usa: 'US',
                'u.s.a.': 'US',
                america: 'US',
                germany: 'DE',
                india: 'IN',
                china: 'CN',
                russia: 'RU',
                'russian federation': 'RU',
                brazil: 'BR',
                japan: 'JP',
                korea: 'KR',
                'south korea': 'KR',
                'united kingdom': 'UK',
                uk: 'UK'
            };
            const countryAttacks = attackMap.countryAttackMap || [];
            const attackers = countryAttacks.length ? countryAttacks : [];
            const maxCount = Math.max(...attackers.map(item => item.count || item.attacks || 1), 1);
            const normalizeCountry = (value) => {
                const raw = String(value || '').trim();
                if (!raw) return 'Unknown';
                return countryAliases[raw.toLowerCase()] || raw.toUpperCase();
            };
            const getCountryDisplayName = (value) => {
                const code = normalizeCountry(value);
                if (code === 'Unknown') return 'Unknown';
                return countryDisplayNames[code] || value || code;
            };
            map.innerHTML = attackers.length
                ? attackers.map((attacker, index) => {
                    const countryCode = normalizeCountry(attacker.country || attacker._id || attacker.ip);
                    const countryName = getCountryDisplayName(attacker.country || attacker._id || attacker.ip);
                    const [x, y] = coordinates[countryCode] || coordinates[countryCode.toUpperCase()] || [20 + ((index * 17) % 60), 28 + ((index * 13) % 44)];
                    const count = attacker.count || attacker.attacks || 0;
                    const sev = count >= maxCount * 0.75 ? 'critical' : count >= maxCount * 0.5 ? 'high' : count >= maxCount * 0.25 ? 'medium' : 'low';
                    const label = countryCode === 'Unknown' ? 'UN' : countryCode.slice(0, 2).toUpperCase();
                    return `<button class="map-pip ${sev}" style="left:${x}%;top:${y}%;" title="${countryName} · ${count} attacks"><span>${label}</span><small>${count}</small></button>`;
                }).join('')
                : '<div class="empty-state">No country activity yet.</div>';

            const countrySummary = attackers.length
                ? `
                    <div class="attack-map-summary">
                        <div class="attack-map-summary-title">All-time active logs · ${Number(attackMap.totalLogs || 0).toLocaleString()} attacks</div>
                        <div class="attack-map-summary-list">
                            ${attackers.map((attacker) => {
                                const countryName = getCountryDisplayName(attacker.country || attacker._id || attacker.ip);
                                const count = attacker.count || attacker.attacks || 0;
                                return `<div class="attack-map-summary-item"><span>${countryName}</span><strong>${count}</strong></div>`;
                            }).join('')}
                        </div>
                    </div>
                `
                : '';
            map.insertAdjacentHTML('beforeend', countrySummary);

            const hourlyTrend = stats.stats?.hourlyTrend?.length
                ? stats.stats.hourlyTrend
                : buildHourlyTrendFromLogs(loadLocalSecurityLogs());
            renderTrendBars(hourlyTrend);
        } catch (error) {
            console.error('Attack visualization failed:', error);
            map.innerHTML = '<div class="empty-state">Live attack sources unavailable.</div>';
            renderTrendBars(buildHourlyTrendFromLogs(loadLocalSecurityLogs()));
        }
    }

    function relocateAnalyticsInsights(root) {
        const contentGrid = root.querySelector('.content-grid');
        const insightsContainer = root.querySelector('#insights-container');
        const insightsCard = insightsContainer?.closest('.card');

        if (!contentGrid || !insightsCard || insightsCard.parentElement === contentGrid) return;

        insightsCard.classList.remove('mt-20');
        insightsCard.classList.add('analytics-insights-card');
        contentGrid.appendChild(insightsCard);
    }

    function renderThreatIntel(root) {
        const host = findContentHost(root);
        if (root.querySelector('.feature-threat-intel')) return;
        const panel = document.createElement('section');
        panel.className = 'feature-panel feature-threat-intel';
        panel.innerHTML = `
            <div class="feature-panel-header">
                <div>
                    <h2>Threat Intelligence</h2>
                    <p>CVE lookup, MITRE ATT&CK mapping, and IOC analysis.</p>
                </div>
            </div>
            <div class="intel-tools">
                <form data-cve-form><input name="cve" placeholder="CVE-2021-44228"><button type="submit">Lookup CVE</button></form>
                <form data-ioc-form><input name="ioc" placeholder="185.220.101.10 or domain"><button type="submit">Analyze IOC</button></form>
                <form data-mitre-form><input name="attack" placeholder="SQL Injection"><button type="submit">Map MITRE</button></form>
            </div>
            <div class="intel-result" data-intel-result>
                <div class="intel-empty">
                    Search a CVE, IOC, or attack type to generate an analyst-ready intelligence card.
                </div>
            </div>
        `;
        host.appendChild(panel);
        const result = panel.querySelector('[data-intel-result]');
        const toList = (value, fallback = []) => {
            if (Array.isArray(value)) return value.filter(Boolean);
            if (typeof value === 'string' && value.trim()) return [value.trim()];
            return fallback;
        };
        const titleCase = (value = '') => String(value || 'unknown')
            .replace(/[-_]/g, ' ')
            .replace(/\b\w/g, letter => letter.toUpperCase());
        const statusClass = value => String(value || 'unknown').toLowerCase().replace(/[^a-z0-9]+/g, '-');
        const renderField = (label, value) => `
            <div class="intel-field">
                <span>${escapeInline(label)}</span>
                <strong>${escapeInline(value || 'N/A')}</strong>
            </div>
        `;
        const renderActions = items => `
            <ul class="intel-action-list">
                ${toList(items, ['Review related logs', 'Validate exposed assets', 'Monitor for repeat activity']).map(item => `
                    <li><i class="fas fa-check-circle"></i><span>${escapeInline(item)}</span></li>
                `).join('')}
            </ul>
        `;
        const renderReferences = (refs, cveId) => {
            const referenceItems = toList(refs);
            if (cveId) {
                referenceItems.push({ label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}` });
                referenceItems.push({ label: 'CVE Record', url: `https://www.cve.org/CVERecord?id=${encodeURIComponent(cveId)}` });
            }
            const uniqueRefs = referenceItems.reduce((items, ref) => {
                const label = typeof ref === 'string' ? ref : ref.label || ref.name || ref.url;
                const url = typeof ref === 'string' ? ref : ref.url || ref.href;
                const key = `${label}-${url || ''}`;
                if (!items.some(item => item.key === key)) items.push({ key, label, url });
                return items;
            }, []);
            if (!uniqueRefs.length) return '';
            return `
                <div class="intel-reference-row">
                    ${uniqueRefs.map(ref => ref.url && /^https?:\/\//i.test(ref.url)
                        ? `<a href="${escapeInline(ref.url)}" target="_blank" rel="noopener noreferrer">${escapeInline(ref.label || 'Reference')}</a>`
                        : `<span>${escapeInline(ref.label || 'Reference')}</span>`
                    ).join('')}
                </div>
            `;
        };
        const getLocalIocObservations = ioc => {
            const value = String(ioc || '').trim().toLowerCase();
            if (!value) return [];
            try {
                const logs = JSON.parse(localStorage.getItem('microsocSecurityLogs') || '[]');
                if (!Array.isArray(logs)) return [];
                return logs
                    .filter(log => {
                        const haystack = [
                            log.sourceIP,
                            log.description,
                            log.targetSystem,
                            log.country,
                            log.attackType
                        ].filter(Boolean).join(' ').toLowerCase();
                        return haystack.includes(value);
                    })
                    .slice(0, 50)
                    .map(log => ({
                        sourceIP: log.sourceIP,
                        country: log.country,
                        attackType: log.attackType,
                        severity: log.severity,
                        isBlocked: log.isBlocked,
                        timestamp: log.timestamp || log.createdAt,
                        description: log.description,
                        targetSystem: log.targetSystem
                    }));
            } catch (error) {
                return [];
            }
        };
        const inferAffectedProduct = cve => {
            const text = `${cve?.title || ''} ${cve?.summary || ''}`.toLowerCase();
            if (cve?.affectedProduct || cve?.product || cve?.vendor) return cve.affectedProduct || cve.product || cve.vendor;
            if (text.includes('outlook')) return 'Microsoft Outlook';
            if (text.includes('log4j')) return 'Apache Log4j';
            if (text.includes('moveit')) return 'MOVEit Transfer';
            if (text.includes('xz')) return 'XZ Utils';
            if (text.includes('spring')) return 'Spring Framework';
            if (text.includes('big-ip') || text.includes('f5')) return 'F5 BIG-IP';
            if (text.includes('http/2')) return 'HTTP/2 enabled web services';
            return 'Review asset inventory';
        };
        const tacticForTechnique = technique => {
            const id = String(technique || '').match(/T\d+(?:\.\d+)?/)?.[0] || '';
            const tactics = {
                T1190: 'Initial Access',
                T1059: 'Execution',
                T1189: 'Initial Access',
                T1110: 'Credential Access',
                T1078: 'Defense Evasion / Persistence',
                T1046: 'Discovery',
                T1595: 'Reconnaissance',
                T1498: 'Impact',
                T1566: 'Initial Access',
                T1204: 'Execution',
                T1486: 'Impact',
                T1082: 'Discovery',
                T1071: 'Command and Control'
            };
            return tactics[id] || 'Mapped ATT&CK tactic';
        };
        const renderCard = ({ kind, badge, title, subtitle, fields, description, actionsTitle, actions, references }) => `
            <article class="intel-result-card">
                <div class="intel-result-head">
                    <div>
                        <span class="intel-kicker">${escapeInline(kind)}</span>
                        <h3>${escapeInline(title)}</h3>
                        ${subtitle ? `<p>${escapeInline(subtitle)}</p>` : ''}
                    </div>
                    <span class="intel-status-badge ${statusClass(badge)}">${escapeInline(titleCase(badge))}</span>
                </div>
                <div class="intel-grid">
                    ${fields.map(field => renderField(field.label, field.value)).join('')}
                </div>
                ${description ? `<p class="intel-description">${escapeInline(description)}</p>` : ''}
                <div class="intel-actions">
                    <strong>${escapeInline(actionsTitle || 'Recommended Actions')}</strong>
                    ${renderActions(actions)}
                </div>
                ${references || ''}
            </article>
        `;
        const showLoading = label => {
            result.innerHTML = `<div class="intel-empty intel-loading">${escapeInline(label)}...</div>`;
        };
        const showError = error => {
            result.innerHTML = renderCard({
                kind: 'Lookup Error',
                badge: 'unknown',
                title: 'Intelligence lookup failed',
                subtitle: 'The request could not be completed.',
                fields: [
                    { label: 'Status', value: 'Unavailable' },
                    { label: 'Next Step', value: 'Check backend/API connection' }
                ],
                description: error?.message || 'Unable to fetch threat intelligence right now.',
                actionsTitle: 'Recovery',
                actions: ['Retry the lookup', 'Confirm the backend server is running', 'Check the browser console for request errors']
            });
        };
        const renderCve = (data, query) => {
            const cve = data?.cve || data?.data?.cve || data?.result || {};
            const cveId = cve.id || query || 'CVE lookup';
            const severity = cve.severity || cve.baseSeverity || cve.cvssSeverity || 'unknown';
            const cvss = cve.cvss ?? cve.cvssScore ?? cve.score ?? 'N/A';
            const title = cve.title || cve.name || `${cveId} vulnerability intelligence`;
            result.innerHTML = renderCard({
                kind: cveId,
                badge: severity,
                title,
                subtitle: 'CVE Intelligence',
                fields: [
                    { label: 'Severity', value: titleCase(severity) },
                    { label: 'CVSS Score', value: cvss === null ? 'Not available' : cvss },
                    { label: 'Affected Product', value: inferAffectedProduct(cve) },
                    { label: 'Source', value: data?.success ? 'Local threat catalog' : 'Threat enrichment' }
                ],
                description: cve.description || cve.summary || 'No description available for this CVE in the current catalog.',
                actionsTitle: 'Recommended Mitigation',
                actions: cve.mitigations || cve.mitigation || cve.recommendations,
                references: renderReferences(cve.references || cve.refs, cveId)
            });
        };
        const renderIoc = (data, query) => {
            const ioc = data?.results?.[0] || data?.ioc || data?.result || {};
            const reputation = ioc.reputation || ioc.verdict || ioc.classification || 'unknown';
            const confidence = ioc.confidence ?? ioc.threatScore ?? ioc.score ?? 'N/A';
            result.innerHTML = renderCard({
                kind: 'IOC Analysis',
                badge: reputation,
                title: ioc.value || query || 'Indicator',
                subtitle: 'Indicator reputation and response guidance',
                fields: [
                    { label: 'IOC Type', value: titleCase(ioc.type || 'unknown') },
                    { label: 'Reputation', value: titleCase(reputation) },
                    { label: 'Country', value: ioc.country || ioc.geo?.country || 'Unknown' },
                    { label: 'Threat Score', value: confidence === 'N/A' ? 'N/A' : `${confidence}/100` },
                    { label: 'Known Activity', value: ioc.knownActivity || ioc.activity || 'No matching log activity' },
                    { label: 'Observed Logs', value: ioc.observedCount ? `${ioc.observedCount} event${ioc.observedCount === 1 ? '' : 's'}` : 'No matches' }
                ],
                description: ioc.knownActivity || ioc.activity || ioc.description || 'Correlate this indicator with recent logs, affected assets, and network telemetry before taking broad blocking action.',
                actionsTitle: 'Recommendation',
                actions: ioc.recommendations || ioc.recommendation || ['Monitor related traffic', 'Block if business use is not required', 'Create a detection rule for repeated sightings']
            });
        };
        const renderMitre = (data, query) => {
            const mapping = data?.mapping || data?.mitre || data?.result || {};
            const techniques = toList(mapping.techniques || mapping.technique);
            const primaryTechnique = techniques[0] || 'T1082 System Information Discovery';
            const techniqueId = primaryTechnique.match(/T\d+(?:\.\d+)?/)?.[0] || primaryTechnique;
            const techniqueName = primaryTechnique.replace(/^T\d+(?:\.\d+)?\s*/, '') || 'Mapped technique';
            const tactic = mapping.tactic || mapping.tactics || tacticForTechnique(primaryTechnique);
            result.innerHTML = renderCard({
                kind: 'MITRE ATT&CK Mapping',
                badge: 'mapped',
                title: `${techniqueId} ${techniqueName}`.trim(),
                subtitle: query || mapping.input || 'Attack behavior mapping',
                fields: [
                    { label: 'Technique', value: techniqueId },
                    { label: 'Tactic', value: Array.isArray(tactic) ? tactic.join(', ') : tactic },
                    { label: 'Confidence', value: mapping.confidence ? `${mapping.confidence}%` : 'Estimated' },
                    { label: 'Related Techniques', value: techniques.slice(1).join(', ') || 'None' }
                ],
                description: mapping.description || 'This mapping helps connect the observed behavior to MITRE ATT&CK so the SOC can choose detections, mitigations, and containment steps faster.',
                actionsTitle: 'Mitigation',
                actions: mapping.mitigations || mapping.mitigation || ['Enforce MFA where credentials are involved', 'Apply rate limiting and alert thresholds', 'Review affected accounts and host telemetry']
            });
        };
        panel.querySelector('[data-cve-form]').addEventListener('submit', async (event) => {
            event.preventDefault();
            const cve = String(new FormData(event.currentTarget).get('cve') || 'CVE-2021-44228').trim().toUpperCase();
            showLoading(`Looking up ${cve}`);
            try {
                renderCve(await apiRequest(`/threat-intel/cve/${encodeURIComponent(cve)}`), cve);
            } catch (error) {
                showError(error);
            }
        });
        panel.querySelector('[data-ioc-form]').addEventListener('submit', async (event) => {
            event.preventDefault();
            const ioc = String(new FormData(event.currentTarget).get('ioc') || '').trim();
            showLoading(`Analyzing ${ioc || 'IOC'}`);
            try {
                renderIoc(await apiRequest('/threat-intel/ioc-analysis', {
                    method: 'POST',
                    body: JSON.stringify({ ioc, observations: getLocalIocObservations(ioc) })
                }), ioc);
            } catch (error) {
                showError(error);
            }
        });
        panel.querySelector('[data-mitre-form]').addEventListener('submit', async (event) => {
            event.preventDefault();
            const attackType = String(new FormData(event.currentTarget).get('attack') || '').trim();
            showLoading(`Mapping ${attackType || 'attack behavior'}`);
            try {
                renderMitre(await apiRequest('/threat-intel/mitre-map', {
                    method: 'POST',
                    body: JSON.stringify({ attackType })
                }), attackType);
            } catch (error) {
                showError(error);
            }
        });
    }

    function App() {
        const [route, setRoute] = useState(getRouteFromHash());

        useEffect(() => {
            const onHashChange = () => setRoute(getRouteFromHash());
            const onClick = (event) => {
                const link = event.target.closest('a[href$=".html"]');
                if (!link) return;
                const routeName = link.getAttribute('href').replace(/\.html$/, '');
                if (!routes[routeName]) return;
                event.preventDefault();
                navigateTo(routeName);
            };

            window.addEventListener('hashchange', onHashChange);
            document.addEventListener('click', onClick);

            if (!window.location.hash) navigateTo('login');

            return () => {
                window.removeEventListener('hashchange', onHashChange);
                document.removeEventListener('click', onClick);
            };
        }, []);

        return React.createElement(HtmlPage, { route, key: route });
    }

    createRoot(document.getElementById('root')).render(React.createElement(App));
}());
