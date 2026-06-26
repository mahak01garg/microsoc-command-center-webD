# MicroSOC Command Center

MicroSOC Command Center is a full-stack Security Operations Center dashboard built for portfolio/demo use. It simulates a SOC workflow where security logs are generated, normalized, converted into alerts, correlated into incidents, enriched with MITRE ATT&CK and CVE context, and recorded in audit logs.

The project is designed to show more than a static dashboard. It demonstrates how security telemetry can move through a detection pipeline and become analyst-ready information.

## Live Demo

```text
https://microsoc-command-center-web-d.vercel.app/
```

## What This Project Does

MicroSOC helps an analyst/admin monitor and investigate security events through:

- Real-time security log streaming
- Automatic alert generation based on configurable thresholds
- Automatic incident creation from repeated/correlated alerts
- MITRE ATT&CK mapping for logs, alerts, and incidents
- CVE enrichment for known vulnerability exploit incidents
- IOC, CVE, and MITRE lookup cards
- Admin/user role management
- Audit logs for admin and system actions
- Archive support for logs, alerts, and incidents
- Dashboard metrics, analytics, attack map, and system health
- Optional AI-assisted summaries and recommendations

## Tech Stack

| Layer | Technology |
| --- | --- |
| Frontend | HTML, CSS, JavaScript, React runtime bundle pattern |
| Frontend server | Custom Node dev server |
| Backend | Node.js, Express.js |
| Database | MongoDB Atlas with Mongoose |
| Auth | JWT, bcrypt |
| Realtime | WebSocket/SSE style threat feed support |
| Security helpers | Helmet, CORS, role-based access checks |
| AI integration | OpenAI/OpenRouter or Gemini-compatible configuration |
| Email integration | SendGrid for approval/reset flows |
| Deployment | Frontend on Vercel, backend on Render, database on MongoDB Atlas |

## Folder Structure

```text
microsoc-command-center-webD/
+-- microsoc-backend/
|   +-- controllers/
|   +-- models/
|   +-- routes/
|   +-- utils/
|   +-- middleware/
|   +-- server.js
|   +-- .env.example
+-- microsoc-frontend/
|   +-- css/
|   +-- js/
|   +-- src/
|   +-- index.html
|   +-- dev-server.js
+-- README.md
```

## High-Level Flow

```text
Live Stream / Mock Generator / Backend Pipeline
        |
        v
Security Log Created
        |
        v
Normalize Attack Type + Attach MITRE Context
        |
        v
Compare Against Alert Threshold Settings
        |
        v
Alert Auto Generated
        |
        v
Correlate Similar Alerts by Source IP or Target System
        |
        v
Incident Auto Created / Updated
        |
        v
Incident Gets MITRE + CVE + Risk Context
        |
        v
Audit Log Records System Action
```

## Core Pages

| Page | Purpose |
| --- | --- |
| Dashboard | SOC overview, key metrics, live logs, attack map, attackers, system health |
| Security Logs | Stream and inspect security events; archive logs; create alerts/incidents from logs |
| Alerts | Alert queue, investigation drawer, resolve/archive actions, alert-to-incident workflow |
| Incidents | Incident tracking, assignment, severity, MITRE/CVE context, archive support |
| Analytics | Trends, attack distribution, response metrics, risk view, AI insights |
| User Management | Admin view for users, approvals, role visibility |
| Audit Logs | Admin/system audit trail with details drawer |
| Settings | Thresholds, theme, notification preferences, AI toggles, system status |
| Threat Intelligence | CVE lookup, MITRE mapping, and IOC analysis in analyst-friendly cards |

## Authentication And Email Flow

MicroSOC includes a complete auth flow, not only a login screen.

### Signup Approval Flow

When a new user creates an account:

```text
User Signup
    |
    v
Account Created As Analyst
    |
    v
Status = Pending Approval
    |
    v
SendGrid Sends Approval Email To Admin
    |
    v
Admin Clicks Approve Or Reject Link
    |
    v
SendGrid Sends Decision Email To Analyst
    |
    v
User Can Login Only After Approval
```

Important behavior:

- New self-registered users are created as analysts.
- The account remains pending until an admin approves it.
- SendGrid sends an access request email to the primary admin.
- The email contains approve and reject links.
- After the admin approves or rejects, SendGrid emails the analyst with the decision.
- Pending users cannot login.
- Rejected users cannot login.
- Disabled users cannot login until an admin enables them again.
- Approved users can login normally.

### User Management Email Notifications

Admin actions from User Management also notify the analyst by email.

| Admin Action | Email Sent To Analyst | Result |
| --- | --- | --- |
| Approve pending analyst | Access approved email with login link | Analyst can login |
| Reject pending analyst | Access rejected email | Analyst cannot login |
| Disable approved analyst | Access disabled email | Analyst cannot login until enabled again |
| Enable disabled analyst | Access enabled/restored email with login link | Analyst can login again |

These emails are sent through SendGrid. If SendGrid is not configured in local development, the backend writes fallback notification details to the console.

These access-control emails are treated as account/security lifecycle emails. They are intentionally separate from SOC notification preferences so that approval, rejection, disable, enable, and password reset messages are not accidentally hidden by dashboard notification toggles.

Approval routes:

```text
GET /api/auth/approve/:token
GET /api/auth/reject/:token
```

### Forgot Password Flow

The project also supports forgot password using an OTP email.

```text
User Clicks Forgot Password
    |
    v
User Enters Email
    |
    v
Backend Generates OTP
    |
    v
SendGrid Sends OTP To User Email
    |
    v
User Enters OTP + New Password
    |
    v
Password Is Updated
```

Important behavior:

- OTP is sent to the registered user's email.
- OTP expires in 10 minutes.
- Password is changed only when email, OTP, and new password are valid.
- If SendGrid is not configured in local development, the backend logs fallback approval/reset details to the console.

Auth routes:

```text
POST /api/auth/register
POST /api/auth/login
POST /api/auth/request-password-reset
POST /api/auth/reset-password
GET  /api/auth/me
```

SendGrid-related environment variables:

```env
SENDGRID_API_KEY=
SENDGRID_FROM_EMAIL=MicroSOC <verified-sender@example.com>
APPROVAL_EMAIL_FROM=MicroSOC <verified-sender@example.com>
APPROVAL_REPLY_TO=you@example.com
BACKEND_PUBLIC_URL=https://your-backend.onrender.com
```

`SENDGRID_FROM_EMAIL` or `APPROVAL_EMAIL_FROM` must be a verified SendGrid sender or authenticated domain.

## Detection Pipeline Explained

### 1. Security Log Generation

Security logs can come from:

- Live stream simulation in the frontend
- Backend/mock log generation
- Manual or generated records stored in MongoDB

Each log contains fields such as:

- Timestamp
- Attack type
- Source IP
- Target system
- Severity
- Country
- Protocol and port
- Blocked status
- MITRE technique
- Description

The live generator includes common SOC-style events such as brute force, port scan, SQL injection, XSS, DDoS, malware, phishing, credential attacks, ransomware, PowerShell abuse, and known exploit attempts.

### 2. Alert Generation

Logs do not automatically mean incidents. First, they are evaluated against alert rules.

Alert thresholds are controlled from Settings:

| Setting | Meaning |
| --- | --- |
| Failed Login Threshold | Number of brute-force style login failures needed before an alert |
| Other Alerts Threshold | Number of non-login attack logs needed before an alert |

Example:

```text
Failed Login Threshold = 5
Other Alerts Threshold = 1
```

This means:

- 5 brute force login failures from the same source can generate an alert.
- 1 SQL injection, DDoS, XSS, exploit, or other non-login attack log can generate an alert.

### 3. Incident Creation

Incidents are created only after alerts repeat enough times.

The setting that controls this is:

```text
Create Incident After = N similar alerts
```

If the value is `3`, the system creates or updates an incident after 3 similar alerts are observed.

### 4. Correlation Logic

Incidents are not created from random alerts. Alerts are correlated by attack type and the correct scope.

| Attack Category | Correlation Scope |
| --- | --- |
| Brute Force | Same source IP |
| Port Scan | Same source IP |
| Credential Stuffing | Same source IP |
| Password Spraying | Same source IP |
| SQL Injection | Same API/endpoint or target system |
| XSS | Same web application/endpoint |
| DDoS | Same target server/service |
| Microsoft Outlook Exploit | Same mail server |
| Apache Struts Exploit | Same web server |
| Exchange Server Exploit | Same Exchange server |
| Log4Shell Exploit | Same target server |

This prevents unrelated alerts from becoming one fake incident.

## MITRE ATT&CK Mapping

MITRE ATT&CK is used to explain attacker behavior in a standard security language.

| Attack Type | MITRE ID | Technique |
| --- | --- | --- |
| Brute Force | T1110 | Brute Force |
| Port Scan | T1046 | Network Service Discovery |
| SQL Injection | T1190 | Exploit Public-Facing Application |
| XSS | T1190 | Exploit Public-Facing Application |
| Phishing | T1566 | Phishing |
| Credential Stuffing | T1110 | Brute Force |
| Password Spraying | T1110.003 | Password Spraying |
| Malware | T1204 | User Execution |
| PowerShell Abuse | T1059.001 | PowerShell |
| Ransomware | T1486 | Data Encrypted for Impact |
| DDoS | T1498/T1499 style denial-of-service mapping | Network/endpoint denial impact |
| Microsoft Outlook Exploit | T1203 | Exploitation for Client Execution |
| Apache Struts Exploit | T1190 | Exploit Public-Facing Application |
| Exchange Server Exploit | T1190 | Exploit Public-Facing Application |
| Log4Shell Exploit | T1190 | Exploit Public-Facing Application |

MITRE values are displayed across logs, alerts, incidents, and threat intelligence views so the analyst does not see "Unknown" for common attack types.

## CVE Enrichment

CVE values are shown only where they make sense: incidents related to known vulnerability exploits.

Security logs and alerts may describe attack behavior. Incidents represent investigated/correlated cases, so known vulnerability CVEs are attached there.

| Exploit Incident | CVE |
| --- | --- |
| Microsoft Outlook Exploit | CVE-2023-23397 |
| Apache Struts Exploit | CVE-2017-5638 |
| Exchange Server Exploit | CVE-2021-26855, CVE-2021-34473 |
| Log4Shell Exploit | CVE-2021-44228 |

Example incident description:

```text
3 similar alerts reached the incident threshold.
Attack Type: Log4Shell Exploit
Correlation: same target server
MITRE: T1190 - Exploit Public-Facing Application
Related CVEs: CVE-2021-44228
```

## Threat Intelligence Cards

The Threat Intelligence section avoids raw JSON output and presents analyst-friendly cards.

### CVE Lookup

Input:

```text
CVE-2021-44228
```

Output includes:

- CVE ID
- Title
- Severity
- CVSS score
- Description
- Affected product
- Recommended mitigation
- References

### MITRE Mapping

Input:

```text
SQL Injection
```

Output includes:

- Technique ID
- Technique name
- Tactic
- Description
- Mitigation

### IOC Analysis

Input:

```text
185.220.101.10
```

Output includes:

- IOC
- Reputation
- Country, if available from logs/intel
- Known activity
- Threat score
- Recommendation

## Audit Logging

Audit logs are split into human/admin actions and system actions.

### Admin Actions

Examples:

- User login
- Settings changed by an admin
- Incident assigned
- Alert resolved
- Log archived
- Incident archived

### System Actions

Examples:

- Security Log Generated
- Alert Auto Generated
- Auto Incident Created
- Auto Incident Updated
- Mock Logs Generated
- Bulk Logs Created
- Status/health events

Audit detail drawers show useful fields such as:

- Timestamp
- Actor
- Role
- Target
- Result
- Details
- Session ID
- Record ID
- IP address, only when captured by backend
- User agent, only when captured by backend

If a field is not available, the UI hides it instead of showing noisy values like "Unknown" or "Not Captured".

## Role Model

| Role | Capabilities |
| --- | --- |
| Admin | Full command view, user management, settings, archive, incident assignment, alert lifecycle |
| Analyst | Investigation-focused access with limited admin controls hidden |
| Viewer | Read-oriented access where applicable |

## Admin vs Analyst Access Flow

The project uses role-based access at two levels:

- Frontend: hides routes, buttons, and admin-only actions from analysts.
- Backend: protects sensitive API endpoints with role checks.

### Sidebar Access

| Page | Admin | Analyst |
| --- | --- | --- |
| Dashboard | Yes | Yes |
| Security Logs | Yes | Yes, view-focused |
| Alerts | Yes | Yes, investigation-focused |
| Incidents | Yes | Yes, limited workflow |
| Analytics | Yes | Yes |
| Audit Logs | Yes | No |
| User Management | Yes | No |
| Settings | Yes | No |

### Action Access Matrix

| Feature / Action | Admin | Analyst |
| --- | --- | --- |
| View dashboard metrics | Yes | Yes |
| View security logs | Yes | Yes |
| Start live stream | Yes | No |
| Generate mock logs | Yes | No |
| Create log manually | Yes | No |
| Archive logs | Yes | No |
| Export logs | Yes | No |
| View alerts | Yes | Yes |
| Investigate alerts | Yes | Yes |
| Resolve alerts | Yes | No |
| Archive alerts | Yes | No |
| Create alerts from logs | Yes | No |
| View incidents | Yes | Yes |
| Create incidents | Yes | No |
| Edit incidents | Yes | No |
| Assign incidents | Yes | No |
| Add admin remediation steps | Yes | No |
| Add analyst note/update where allowed | Yes | No |
| View audit logs | Yes | No |
| View user management | Yes | No |
| Update SOC settings | Yes | No |
| Change AI/notification settings | Yes | No |

### Frontend Role Behavior

When the logged-in user is an admin, the sidebar shows:

```text
Dashboard -> Security Logs -> Alerts -> Incidents -> Analytics -> Audit Logs -> User Management -> Settings
```

When the logged-in user is an analyst, the sidebar shows:

```text
Dashboard -> Security Logs -> Alerts -> Incidents -> Analytics
```

Admin-only controls such as archive, delete, export, generate, create incident, user management, audit logs, and settings are hidden for analysts.

### Backend Protected Routes

Sensitive routes are protected using admin-only authorization.

| Backend Area | Admin-only Operations |
| --- | --- |
| `/api/settings` | Read/update SOC settings |
| `/api/audit-logs` | View audit history |
| `/api/users` | User management and approvals |
| `/api/logs` | Create, update, archive/delete, bulk create, generate mock logs, export |
| `/api/alerts` | Create, update, bulk update, archive |
| `/api/incidents` | Create, update, archive/delete, assign, remediation |

Analysts can still use the product meaningfully, but their experience is focused on triage and investigation rather than system administration.

The backend syncs authorized admin accounts on startup. Demo/admin emails are available from:

```text
GET /api/demo-credentials
```

Passwords should not be committed into public documentation. Use environment variables or the backend user sync configuration for local demo setup.

## API Overview

Base URL:

```text
http://localhost:5001/api
```

Important routes:

| Route | Purpose |
| --- | --- |
| `/auth` | Login, signup, approvals, password reset |
| `/logs` | Security logs, mock logs, streaming, archive/update |
| `/alerts` | Alert queue, stats, create/update/archive |
| `/incidents` | Incident lifecycle and assignment |
| `/dashboard` | Dashboard metrics and recent activity |
| `/analytics` | Analytics and trend data |
| `/audit-logs` | Audit log listing and stats |
| `/settings` | SOC thresholds and system configuration |
| `/ai` | AI status and AI-assisted analysis |
| `/threat-intel` | CVE, MITRE, and IOC intelligence |
| `/health` | Backend and database health |
| `/realtime/status` | Realtime channel status |

## Local Setup

### Prerequisites

- Node.js 18 or newer
- MongoDB local or MongoDB Atlas
- npm

### 1. Clone and install backend

```bash
cd microsoc-backend
npm install
```

### 2. Configure backend environment

Create a backend `.env` file using the example:

```bash
cp .env.example .env
```

Minimum required values:

```env
PORT=5001
NODE_ENV=development
MONGODB_URI=mongodb://localhost:27017/microsoc
JWT_SECRET=replace-with-a-long-random-secret
JWT_EXPIRE=7d
FRONTEND_URL=http://localhost:5173
```

Optional AI values:

```env
AI_PROVIDER=openai
AI_BASE_URL=https://openrouter.ai/api/v1
AI_MODEL=openrouter/owl-alpha
OPENAI_API_KEY=
AI_REQUIRE_PROVIDER=true
```

Optional email values:

```env
SENDGRID_API_KEY=
SENDGRID_FROM_EMAIL=
APPROVAL_EMAIL_FROM=
APPROVAL_REPLY_TO=
```

### 3. Start backend

```bash
npm run dev
```

Backend runs on:

```text
http://localhost:5001
```

Health check:

```text
http://localhost:5001/api/health
```

### 4. Install frontend

Open a second terminal:

```bash
cd microsoc-frontend
npm install
```

### 5. Start frontend

```bash
npm run dev
```

Frontend runs on:

```text
http://localhost:5173
```

## Demo Flow

Use this flow when presenting the project:

### Step 1: Login

Login as an admin or approved analyst.

Admin users can access:

- Settings
- User Management
- Audit Logs
- Archive actions
- Incident assignment

### Step 2: Open Dashboard

Show:

- Security score
- Active incidents
- Critical threats
- Attack prevention
- Blocked attacks
- Live logs
- Attack map
- Top attackers
- System health

### Step 3: Start Security Log Live Stream

Go to Security Logs and start the live stream.

New logs will appear with:

- Attack type
- Source IP
- Target
- Severity
- Country
- MITRE mapping

### Step 4: Watch Alerts Auto Generate

When logs cross configured thresholds, alerts are created automatically.

Example:

```text
Other Alerts Threshold = 1
One DDoS log arrives
One DDoS alert is generated
```

### Step 5: Watch Incidents Auto Create

When repeated similar alerts cross the incident threshold:

```text
Create Incident After = 3
3 Log4Shell alerts target the same server
1 Log4Shell incident is created
```

The incident includes:

- Attack type
- MITRE technique
- CVE values, if known exploit
- Source/target context
- Related logs
- Timeline

### Step 6: Use Threat Intelligence

Try:

```text
CVE-2021-44228
SQL Injection
185.220.101.10
```

The output should be analyst-friendly cards, not raw JSON.

### Step 7: Review Audit Logs

Open Audit Logs and show:

- Admin actions
- System actions
- Alert auto-generated events
- Auto incident created/updated events
- Settings updated events
- Technical details drawer

## Settings Explained

Settings control behavior for new data generated after the setting is changed.

| Setting | Purpose |
| --- | --- |
| Theme | Switch light/dark UI |
| Auto Refresh | Keep dashboards updated |
| Refresh Interval | Dashboard refresh timing in seconds |
| Failed Login Threshold | Brute force alert trigger |
| Other Alerts Threshold | Non-login attack alert trigger |
| Create Incident After | Similar alert count required for incident |
| Severity Escalation | Allows repeated alerts to raise existing incident severity/priority |
| AI Analysis | Enables AI-assisted analysis |
| Auto Generate Recommendations | Allows AI-generated response suggestions |
| Email Notifications | Master switch for SOC operational email notifications |
| Critical Alert Notifications | Sends admin email notifications for critical detections |
| Incident Assignment Notifications | Notifies analysts when an incident is assigned to them |

Detailed incident rule logic is documented in this README instead of the Settings UI to keep the product screen clean.

### Settings Enforcement Matrix

The Settings page is not only visual. These controls are connected to runtime behavior.

| Setting | Applies To | Behavior |
| --- | --- | --- |
| Theme | Frontend UI | Changes the command center theme instantly and persists it |
| Auto Refresh | Dashboard | Enables/disables dashboard polling |
| Refresh Interval | Dashboard | Controls dashboard refresh interval in seconds, from 5 to 300 |
| Failed Login Threshold | Threat pipeline | Controls how many failed login/brute-force style logs create an alert |
| Other Alerts Threshold | Threat pipeline | Controls how many non-login attack logs create an alert |
| Create Incident After | Threat pipeline and alert correlation | Controls how many similar alerts create/update an incident |
| Severity Escalation | Existing incident updates | When off, repeated alerts can attach to incidents without auto-raising severity/priority |
| AI Analysis | AI chat/search/report endpoints | When off, AI-assisted analysis is blocked |
| Auto Generate Recommendations | AI report/recommendation generation | When off, generated recommendation/report responses are blocked |
| Email Notifications | SOC operational notifications | Master switch for critical alert and assignment emails |
| Critical Alert Notifications | Critical alert email flow | Sends admin email only when master email notifications are also on |
| Incident Assignment Notifications | Incident assignment email flow | Sends analyst assignment email only when master email notifications are also on |

Important note:

```text
Settings affect new activity after the setting is saved.
Existing logs, alerts, incidents, and audit records are not rewritten.
```

For example, if `Create Incident After` is changed from `3` to `2`, the next correlation run uses `2`; old incidents remain unchanged.

## Security Score Formula

The dashboard security score is a derived presentation metric. It is meant to summarize security posture, not replace a real enterprise risk model.

Current dashboard implementation:

```text
severityTotal = criticalLogs + highLogs + mediumLogs

logPressure =
  (criticalLogs / severityTotal * 45)
  + (highLogs / severityTotal * 25)
  + (mediumLogs / severityTotal * 12)

responsePressure = 0

resilienceBonus =
  min(15, blockedPercentage / 7)
  + min(10, uniqueSources / 20)

totalThreatSignals =
  totalLogs + blockedAttacks + uniqueSources

securityScore =
  clamp(
    92 - logPressure - responsePressure + resilienceBonus + activityBonus,
    minimum = totalThreatSignals > 0 ? 20 : 45,
    maximum = 100
  )

activityBonus = 4 when threat signals exist, otherwise 0
```

In simple words:

```text
More critical/high/medium logs reduce the score.
Higher blocked attack percentage improves the score.
More unique sources add a small resilience/context bonus.
If there is no telemetry yet, the score does not pretend to be perfect.
```

The score is capped at 100 and has a minimum floor so the dashboard remains readable during demos. It is a presentation metric for SOC posture, not a certified enterprise risk score.

## Archive Strategy

Delete actions are intentionally avoided for logs/incidents where audit integrity matters.

Instead:

- Logs can be archived.
- Alerts can be archived.
- Incidents can be archived.
- Archived records are removed from active views.
- Audit history remains available.

This is closer to real SOC tools, where security records should usually be retained.

## Deployment Notes

Actual deployment stack used:

| Layer | Platform |
| --- | --- |
| Frontend | Vercel |
| Backend | Render |
| Database | MongoDB Atlas |

Production URLs:

| Service | URL |
| --- | --- |
| Frontend | `https://microsoc-command-center-web-d.vercel.app/` |
| Backend | `https://microsoc-backend.onrender.com` |

### Backend

The backend is deployed on Render as a Node.js service.

Set environment variables:

```env
NODE_ENV=production
PORT=5001
MONGODB_URI=your_mongodb_atlas_connection_string
JWT_SECRET=your_secret
FRONTEND_URL=https://microsoc-command-center-web-d.vercel.app
BACKEND_PUBLIC_URL=https://microsoc-backend.onrender.com
```

`MONGODB_URI` points to the MongoDB Atlas cluster.

The backend uses:

```js
app.set('trust proxy', 1)
```

This allows deployed environments behind a proxy to capture the real client IP from forwarded headers when available.

### Frontend

The frontend is deployed on Vercel:

```text
https://microsoc-command-center-web-d.vercel.app/
```

Make sure the frontend API base URL points to the deployed backend.

Also make sure the backend `FRONTEND_URL` matches the deployed frontend origin for CORS.

### Database

MongoDB Atlas is used as the production database.

The backend connects to Atlas through:

```env
MONGODB_URI=mongodb+srv://USER:PASSWORD@HOST/DATABASE
```

Atlas stores:

- Users and approval status
- Security logs
- Alerts
- Incidents
- Audit logs
- System settings

## Why This Project Is Strong For A Portfolio

This project demonstrates:

- Practical SOC workflow design
- Security event modeling
- Alert thresholding
- Incident correlation
- MITRE ATT&CK awareness
- CVE enrichment
- Role-based access control
- Auditability
- API integration
- Realistic admin/system separation
- Clean analyst-facing UI instead of raw JSON output

It is not just a UI dashboard. It shows how raw telemetry becomes security decisions.
