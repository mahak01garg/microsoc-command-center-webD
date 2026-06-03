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
        analytics: 'analytics'
    };

    const protectedRoutes = new Set(['dashboard', 'incidents', 'logs', 'analytics']);
    const loadedExternalScripts = new Set();
    const pages = window.MICROSOC_PAGES || {};
    const LOCAL_API_BASE_URL = 'http://localhost:5001/api';
    const HOSTED_API_BASE_URL = 'https://microsoc-backend.onrender.com/api';

    window.MICROSOC_API_BASE_URL = ['localhost', '127.0.0.1'].includes(window.location.hostname)
        ? LOCAL_API_BASE_URL
        : HOSTED_API_BASE_URL;

    function getRouteFromHash() {
        const route = window.location.hash.replace(/^#\/?/, '').split('?')[0];
        return routes[route] ? route : 'login';
    }

    function navigateTo(route) {
        const normalized = String(route || 'login').replace(/\.html$/, '');
        window.location.hash = `#/${routes[normalized] ? normalized : 'login'}`;
    }

    window.navigateTo = navigateTo;

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
            .replace(/window\.location\.href\s*=\s*['"]analytics\.html['"]/g, "window.navigateTo('analytics')");
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

    function enhanceSecurityUi(route) {
        const mainContent = document.querySelector('.main-content');
        installNotificationDropdown();
        if (!mainContent) {
            document.querySelector('.ai-assistant')?.remove();
            return;
        }

        installAIAssistant(route);
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
                const payload = await response.json();
                if (!response.ok || !payload.success) {
                    throw new Error(payload.message || 'Assistant failed');
                }

                const data = payload.data || {};
                const answer = data.answer || data.summary || JSON.stringify(data);
                const nextActions = Array.isArray(data.nextActions) && data.nextActions.length
                    ? `\n\nNext: ${data.nextActions.join(' | ')}`
                    : '';
                thinking.textContent = `${answer}${nextActions}`;
            } catch (error) {
                console.error('AI assistant failed:', error);
                thinking.textContent = 'AI assistant could not respond. Please check backend login/session.';
            }
        });
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
    }

    async function getNotificationItems() {
        try {
            const payload = await apiRequest('/dashboard/alerts');
            return (payload.alerts || []).map((alert) => ({
                type: alert.severity === 'critical' ? 'critical' : alert.severity === 'high' ? 'warning' : 'info',
                icon: alert.severity === 'critical' ? 'fa-exclamation-circle' : alert.severity === 'high' ? 'fa-exclamation-triangle' : 'fa-info-circle',
                title: alert.title,
                message: alert.description || alert.source || 'Security alert',
                time: new Date(alert.timestamp || Date.now()).toLocaleString()
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
            navigateTo('login');
            return false;
        }
        return true;
    }

    function HtmlPage({ route }) {
        const [readyPage, setReadyPage] = useState({ body: '', scripts: [], error: '' });

        useEffect(() => {
            if (!guardRoute(route)) return;

            const page = pages[route];
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

    function installFeatureSuite(route, root) {
        if (!protectedRoutes.has(route) || !root || root.dataset.featureSuiteInstalled) return;
        root.dataset.featureSuiteInstalled = 'true';
        renderRoleDashboard(root);
        refreshLiveCounts(root);
        if (route === 'dashboard') {
            refreshLegacyDashboardData(root);
            renderThreatFeed(root);
            renderAttackVisualization(root);
            renderThreatIntel(root);
        }
        if (route === 'logs') renderThreatFeed(root);
        if (route === 'incidents') {
            refreshLegacyIncidentStats(root);
            renderIncidentConsole(root);
        }
        if (route === 'analytics') {
            renderAttackVisualization(root);
            renderThreatIntel(root);
        }
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

    async function refreshLiveCounts(root) {
        try {
            const [incidentPayload, logPayload, alertPayload] = await Promise.all([
                apiRequest('/incidents/stats'),
                apiRequest('/logs/stats?timeRange=24h'),
                apiRequest('/dashboard/alerts')
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
                const requiringAction = alertPayload.summary?.requiringAction || 0;
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
            </div>
        `;
        host.insertAdjacentElement(host.classList.contains('threat-ribbon') ? 'afterend' : 'afterbegin', strip);
    }

    function renderThreatFeed(root) {
        const host = findContentHost(root);
        if (root.querySelector('.feature-threat-feed')) return;
        const panel = document.createElement('section');
        panel.className = 'feature-panel feature-threat-feed';
        panel.innerHTML = `
            <div class="feature-panel-header">
                <div>
                    <h2>Real-Time Threat Feed</h2>
                    <p>Live log stream, WebSocket updates, and auto-refresh alerts.</p>
                </div>
                <button type="button" class="btn btn-primary" data-generate-log><i class="fas fa-bolt"></i> Generate Event</button>
            </div>
            <div class="feed-status"><span class="pulse"></span><strong data-feed-state>Connecting</strong><span data-feed-meta>Waiting for backend feed</span></div>
            <div class="live-log-stream" data-live-log-stream></div>
        `;
        host.appendChild(panel);
        const stream = panel.querySelector('[data-live-log-stream]');
        const state = panel.querySelector('[data-feed-state]');
        const meta = panel.querySelector('[data-feed-meta]');

        function addLog(log) {
            const row = document.createElement('div');
            row.className = `live-log-row ${log.severity || 'medium'}`;
            row.innerHTML = `
                <span>${new Date(log.timestamp || Date.now()).toLocaleTimeString()}</span>
                <strong>${log.attackType || 'Threat'}</strong>
                <code>${log.sourceIP || '0.0.0.0'}</code>
                <span>${log.targetSystem || 'unknown'}</span>
                <em>${log.severity || 'medium'}</em>
            `;
            stream.prepend(row);
            Array.from(stream.children).slice(20).forEach(child => child.remove());
        }

        apiRequest('/logs?limit=8&timeRange=all')
            .then(data => (data.logs || []).reverse().forEach(addLog))
            .catch(() => {
                meta.textContent = 'Login session or backend is unavailable';
            });

        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${new URL(window.MICROSOC_API_BASE_URL).host}/ws/threat-feed`;
        try {
            const socket = new WebSocket(wsUrl);
            socket.addEventListener('open', () => {
                state.textContent = 'WebSocket live';
                meta.textContent = 'New logs appear automatically';
            });
            socket.addEventListener('message', (event) => {
                const payload = JSON.parse(event.data);
                if (payload.log) addLog(payload.log);
                if (payload.alert && typeof window.showNotification === 'function') {
                    window.showNotification(payload.alert.message, payload.alert.severity === 'critical' ? 'error' : 'warning');
                }
            });
            socket.addEventListener('close', () => {
                state.textContent = 'Feed paused';
                meta.textContent = 'Refresh to reconnect';
            });
        } catch (error) {
            state.textContent = 'Unavailable';
        }

        panel.querySelector('[data-generate-log]').addEventListener('click', async () => {
            try {
                const data = await apiRequest('/logs/generate-mock', {
                    method: 'POST',
                    body: JSON.stringify({ count: 1 })
                });
                (data.logs || []).forEach(addLog);
            } catch (error) {
                meta.textContent = error.message;
            }
        });
    }

    function renderIncidentConsole(root) {
        const host = findContentHost(root);
        if (root.querySelector('.feature-incident-console')) return;
        const panel = document.createElement('section');
        panel.className = 'feature-panel feature-incident-console';
        panel.innerHTML = `
            <div class="feature-panel-header">
                <div>
                    <h2>Incident Management</h2>
                    <p>Create, assign status, resolve, and track timeline events.</p>
                </div>
            </div>
            <form class="incident-quick-form">
                <input name="title" placeholder="Incident title" required>
                <select name="severity"><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
                <input name="sourceIP" placeholder="Source IP">
                <button type="submit" class="btn btn-primary"><i class="fas fa-plus"></i> Create</button>
            </form>
            <div class="incident-workbench" data-incident-workbench></div>
        `;
        host.prepend(panel);
        const workbench = panel.querySelector('[data-incident-workbench]');

        async function loadIncidents() {
            const data = await apiRequest('/incidents?limit=8');
            workbench.innerHTML = (data.incidents || []).map(incident => `
                <article class="incident-ticket ${incident.severity}">
                    <div>
                        <strong>${incident.title}</strong>
                        <span>${incident.status.replace('_', ' ')} · ${incident.severity}</span>
                    </div>
                    <div class="ticket-actions">
                        <button type="button" data-status="${incident._id}:in_progress">In Progress</button>
                        <button type="button" data-status="${incident._id}:resolved">Resolve</button>
                        <button type="button" data-timeline="${incident._id}">Timeline</button>
                    </div>
                </article>
            `).join('') || '<p class="empty-state">No incidents yet.</p>';
        }

        panel.querySelector('form').addEventListener('submit', async (event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            await apiRequest('/incidents', {
                method: 'POST',
                body: JSON.stringify({
                    title: form.get('title'),
                    description: `${form.get('severity')} incident created from analyst console`,
                    severity: form.get('severity'),
                    sourceIP: form.get('sourceIP') || undefined,
                    category: 'other'
                })
            });
            event.currentTarget.reset();
            loadIncidents();
        });

        workbench.addEventListener('click', async (event) => {
            const statusButton = event.target.closest('[data-status]');
            const timelineButton = event.target.closest('[data-timeline]');
            if (statusButton) {
                const [id, status] = statusButton.dataset.status.split(':');
                await apiRequest(`/incidents/${id}/status`, {
                    method: 'PUT',
                    body: JSON.stringify({ status, note: `Status changed to ${status}` })
                });
                loadIncidents();
            }
            if (timelineButton) {
                await apiRequest(`/incidents/${timelineButton.dataset.timeline}/timeline`, {
                    method: 'POST',
                    body: JSON.stringify({ action: 'Analyst review', note: 'Timeline checkpoint added from console' })
                });
                loadIncidents();
            }
        });

        loadIncidents().catch(error => {
            workbench.innerHTML = `<p class="empty-state">${error.message}</p>`;
        });
    }

    async function renderAttackVisualization(root) {
        const host = findContentHost(root);
        if (root.querySelector('.feature-attack-viz')) return;
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

        try {
            const [realtime, stats] = await Promise.all([
                apiRequest('/dashboard/realtime'),
                apiRequest('/logs/stats?timeRange=24h')
            ]);
            const coordinates = {
                US: [24, 38], USA: [24, 38], RU: [63, 28], Russia: [63, 28],
                CN: [76, 44], China: [76, 44], IN: [69, 55], India: [69, 55],
                BR: [36, 70], Brazil: [36, 70], DE: [52, 35], Germany: [52, 35],
                JP: [82, 46], Japan: [82, 46], KR: [79, 43], UK: [48, 33]
            };
            const attackers = realtime.realtimeData?.topAttackers || [];
            const maxCount = Math.max(...attackers.map(item => item.count || item.attacks || 1), 1);
            map.innerHTML = attackers.length
                ? attackers.map((attacker, index) => {
                    const country = attacker.country || 'Unknown';
                    const [x, y] = coordinates[country] || [20 + ((index * 17) % 60), 28 + ((index * 13) % 44)];
                    const count = attacker.count || attacker.attacks || 0;
                    const sev = count >= maxCount * 0.75 ? 'critical' : count >= maxCount * 0.5 ? 'high' : count >= maxCount * 0.25 ? 'medium' : 'low';
                    return `<button class="map-pip ${sev}" style="left:${x}%;top:${y}%;" title="${attacker.ip || attacker._id} · ${country} · ${count} attacks">${country.slice(0, 2).toUpperCase()}</button>`;
                }).join('')
                : '<div class="empty-state">No source IP activity yet.</div>';

            const hourlyTrend = stats.stats?.hourlyTrend || [];
            const maxTrend = Math.max(...hourlyTrend.map(item => item.count || 1), 1);
            bars.innerHTML = hourlyTrend.length
                ? hourlyTrend.map((item) => {
                    const value = item.count || 0;
                    const label = item._id?.hour !== undefined ? `${item._id.hour}:00` : 'bucket';
                    return `<span style="height:${Math.max(8, (value / maxTrend) * 220)}px" title="${label}: ${value} attacks"></span>`;
                }).join('')
                : '<div class="empty-state">No trend data yet.</div>';
        } catch (error) {
            console.error('Attack visualization failed:', error);
            map.innerHTML = '<div class="empty-state">Live attack sources unavailable.</div>';
            bars.innerHTML = '<div class="empty-state">Live trends unavailable.</div>';
        }
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
            <pre class="intel-result" data-intel-result>Ready for enrichment.</pre>
        `;
        host.appendChild(panel);
        const result = panel.querySelector('[data-intel-result]');
        const show = data => {
            result.textContent = JSON.stringify(data, null, 2);
        };
        panel.querySelector('[data-cve-form]').addEventListener('submit', async (event) => {
            event.preventDefault();
            show(await apiRequest(`/threat-intel/cve/${new FormData(event.currentTarget).get('cve') || 'CVE-2021-44228'}`));
        });
        panel.querySelector('[data-ioc-form]').addEventListener('submit', async (event) => {
            event.preventDefault();
            show(await apiRequest('/threat-intel/ioc-analysis', {
                method: 'POST',
                body: JSON.stringify({ ioc: new FormData(event.currentTarget).get('ioc') })
            }));
        });
        panel.querySelector('[data-mitre-form]').addEventListener('submit', async (event) => {
            event.preventDefault();
            show(await apiRequest('/threat-intel/mitre-map', {
                method: 'POST',
                body: JSON.stringify({ attackType: new FormData(event.currentTarget).get('attack') })
            }));
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
