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
                const response = await fetch('http://localhost:5001/api/ai/chat', {
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

    function getNotificationItems() {
        return [
            {
                type: 'critical',
                icon: 'fa-exclamation-circle',
                title: 'Critical XSS Attack Detected',
                message: 'Multiple payload attempts from 192.168.1.105',
                time: '5 minutes ago'
            },
            {
                type: 'warning',
                icon: 'fa-exclamation-triangle',
                title: 'Security Patch Pending',
                message: 'Gateway WAF rule update is ready to apply',
                time: '1 hour ago'
            },
            {
                type: 'info',
                icon: 'fa-info-circle',
                title: 'Weekly Threat Report',
                message: 'Analytics report has been generated successfully',
                time: '2 hours ago'
            }
        ];
    }

    function installNotificationDropdown() {
        const bell = document.querySelector('.notification');
        if (!bell) return;

        bell.setAttribute('onclick', 'window.showNotifications(event)');
        bell.setAttribute('role', 'button');
        bell.setAttribute('aria-label', 'Notifications');

        window.showNotifications = function (event) {
            if (event) event.stopPropagation();

            let dropdown = document.querySelector('.notification-dropdown');
            if (!dropdown) {
                dropdown = document.createElement('div');
                dropdown.className = 'notification-dropdown hidden';
                document.body.appendChild(dropdown);
            }

            const items = getNotificationItems();
            dropdown.innerHTML = `
                <div class="notification-dropdown-header">
                    <strong>Notifications</strong>
                    <button type="button" onclick="window.markAllAsRead(event)">Mark all read</button>
                </div>
                <div class="notification-dropdown-list">
                    ${items.map((item) => `
                        <div class="notification-dropdown-item ${item.type}">
                            <i class="fas ${item.icon}"></i>
                            <div>
                                <div class="notification-dropdown-title">${item.title}</div>
                                <div class="notification-dropdown-message">${item.message}</div>
                                <div class="notification-dropdown-time">${item.time}</div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;

            const rect = bell.getBoundingClientRect();
            const width = 340;
            const left = Math.max(12, Math.min(rect.right - width, window.innerWidth - width - 12));
            dropdown.style.top = `${rect.bottom + window.scrollY + 12}px`;
            dropdown.style.left = `${left + window.scrollX}px`;
            dropdown.classList.toggle('hidden');
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
