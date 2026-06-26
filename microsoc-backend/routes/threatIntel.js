const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const Log = require('../models/Log');

const cveCatalog = {
  'CVE-2021-44228': {
    title: 'Apache Log4j remote code execution',
    severity: 'critical',
    cvss: 10,
    summary: 'JNDI lookup injection can allow unauthenticated remote code execution in vulnerable Log4j deployments.',
    mitigations: ['Patch Log4j to a fixed version', 'Block exploit strings at WAF', 'Hunt for outbound LDAP/RMI callbacks']
  },
  'CVE-2023-34362': {
    title: 'MOVEit Transfer SQL injection',
    severity: 'critical',
    cvss: 9.8,
    summary: 'SQL injection in exposed MOVEit Transfer systems has been exploited for data theft.',
    mitigations: ['Apply vendor patches', 'Review file-transfer audit logs', 'Rotate credentials and secrets exposed through the app']
  },
  'CVE-2024-3094': {
    title: 'XZ Utils backdoor',
    severity: 'critical',
    cvss: 10,
    summary: 'Malicious code in affected XZ Utils releases can weaken SSH authentication paths on some Linux systems.',
    mitigations: ['Downgrade or patch affected XZ packages', 'Inventory exposed Linux hosts', 'Review SSH access anomalies']
  },
  'CVE-2023-23397': {
    title: 'Microsoft Outlook elevation of privilege',
    severity: 'critical',
    cvss: 9.8,
    affectedProduct: 'Microsoft Outlook',
    summary: 'A crafted Outlook message can trigger credential exposure without user interaction on vulnerable clients.',
    mitigations: ['Apply the latest Microsoft security update', 'Audit suspicious calendar and message activity', 'Monitor NTLM authentication to untrusted hosts']
  },
  'CVE-2022-1388': {
    title: 'F5 BIG-IP iControl REST authentication bypass',
    severity: 'critical',
    cvss: 9.8,
    affectedProduct: 'F5 BIG-IP',
    summary: 'Authentication bypass in iControl REST can allow attackers to execute commands on exposed management interfaces.',
    mitigations: ['Restrict management interface exposure', 'Apply F5 vendor patches', 'Review administrative command history']
  },
  'CVE-2023-44487': {
    title: 'HTTP/2 rapid reset denial of service',
    severity: 'high',
    cvss: 7.5,
    affectedProduct: 'HTTP/2 enabled web services',
    summary: 'Attackers can abuse HTTP/2 stream resets to consume server resources and disrupt service availability.',
    mitigations: ['Patch HTTP/2 server components', 'Tune rate limits and request caps', 'Monitor edge traffic for rapid reset patterns']
  },
  'CVE-2022-22965': {
    title: 'Spring Framework remote code execution',
    severity: 'critical',
    cvss: 9.8,
    affectedProduct: 'Spring Framework',
    summary: 'Spring4Shell-style exploitation can allow remote code execution in vulnerable Spring MVC deployments.',
    mitigations: ['Upgrade Spring Framework', 'Review exposed Java web applications', 'Deploy WAF rules for exploit probes']
  },
  'CVE-2017-5638': {
    title: 'Apache Struts Jakarta Multipart parser remote code execution',
    severity: 'critical',
    cvss: 10,
    affectedProduct: 'Apache Struts',
    summary: 'A crafted Content-Type header can trigger remote code execution in vulnerable Apache Struts deployments.',
    mitigations: ['Upgrade Apache Struts immediately', 'Block exploit headers at WAF', 'Review web server process execution history']
  },
  'CVE-2021-26855': {
    title: 'Microsoft Exchange Server SSRF vulnerability',
    severity: 'critical',
    cvss: 9.8,
    affectedProduct: 'Microsoft Exchange Server',
    summary: 'Server-side request forgery in Exchange Server can allow attackers to authenticate as the Exchange server.',
    mitigations: ['Apply Microsoft Exchange security updates', 'Restrict external Exchange exposure', 'Hunt for web shell indicators']
  },
  'CVE-2021-34473': {
    title: 'Microsoft Exchange Server remote code execution',
    severity: 'critical',
    cvss: 9.8,
    affectedProduct: 'Microsoft Exchange Server',
    summary: 'Exchange Server exploitation chain can allow remote code execution on vulnerable systems.',
    mitigations: ['Patch Exchange Server', 'Review IIS and Exchange logs', 'Rotate credentials if compromise is suspected']
  }
};

const mitreMap = [
  { match: /sql|injection/i, techniques: ['T1190 Exploit Public-Facing Application', 'T1059 Command and Scripting Interpreter'] },
  { match: /xss|script/i, techniques: ['T1189 Drive-by Compromise', 'T1059.007 JavaScript'] },
  { match: /brute|password|credential/i, techniques: ['T1110 Brute Force', 'T1078 Valid Accounts'] },
  { match: /scan|port|recon/i, techniques: ['T1046 Network Service Discovery', 'T1595 Active Scanning'] },
  { match: /ddos|denial/i, techniques: ['T1498 Network Denial of Service'] },
  { match: /malware|phish|ransom/i, techniques: ['T1566 Phishing', 'T1204 User Execution', 'T1486 Data Encrypted for Impact'] }
];

function escapeRegex(value = '') {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function mostCommon(values = []) {
  return Object.entries(values.filter(Boolean).reduce((counts, value) => {
    const key = String(value).trim();
    if (!key || key.toLowerCase() === 'unknown') return counts;
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {})).sort((a, b) => b[1] - a[1])[0]?.[0];
}

function inferCountryFromIoc(value = '') {
  const text = String(value).trim().toLowerCase();
  if (/^185\.220\.101\./.test(text)) return 'Germany';
  if (/^45\./.test(text)) return 'Netherlands';
  if (/^103\./.test(text)) return 'India';
  if (/^91\./.test(text)) return 'India';
  if (/\.ru$/.test(text)) return 'Russia';
  if (/\.de$/.test(text)) return 'Germany';
  if (/\.in$/.test(text)) return 'India';
  if (/\.cn$/.test(text)) return 'China';
  return 'Unknown';
}

function summarizeObservedActivity(observations = []) {
  const attackCounts = observations.reduce((counts, log) => {
    const key = String(log.attackType || 'Suspicious Activity').trim();
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
  return Object.entries(attackCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([attackType, count]) => `${attackType}${count > 1 ? ` (${count})` : ''}`)
    .join(', ');
}

function scoreIoc(value = '', observations = []) {
  const text = String(value).trim();
  const isIp = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?\d\d?)$/.test(text);
  const isHash = /^[a-f0-9]{32,64}$/i.test(text);
  const isDomain = /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(text);
  const suspicious = /(^185\.|^45\.|\.ru$|\.top$|paste|login|verify|update)/i.test(text);
  const observedLogs = observations.filter(Boolean);
  const observedCount = observedLogs.length;
  const criticalCount = observedLogs.filter(log => String(log.severity || '').toLowerCase() === 'critical').length;
  const highCount = observedLogs.filter(log => String(log.severity || '').toLowerCase() === 'high').length;
  const blockedCount = observedLogs.filter(log => log.isBlocked === true || log.blocked === true).length;
  const country = mostCommon(observedLogs.map(log => log.country)) || inferCountryFromIoc(text);
  const knownActivity = summarizeObservedActivity(observedLogs)
    || (/^185\.220\.101\./.test(text) ? 'Tor Exit Node' : suspicious ? 'Suspicious indicator pattern' : 'No matching log activity found');
  const malicious = criticalCount > 0 || (highCount > 0 && blockedCount < observedCount) || observedCount >= 5;
  const reputation = malicious ? 'malicious' : (observedCount > 0 || suspicious ? 'suspicious' : 'unknown');
  const confidence = Math.min(
    98,
    Math.max(
      suspicious ? 78 : 45,
      45 + observedCount * 8 + criticalCount * 18 + highCount * 10
    )
  );

  return {
    type: isIp ? 'ip' : isHash ? 'hash' : isDomain ? 'domain' : 'unknown',
    reputation,
    country,
    knownActivity,
    confidence,
    observedCount,
    lastSeen: observedLogs
      .map(log => log.timestamp || log.createdAt)
      .filter(Boolean)
      .sort()
      .at(-1),
    recommendations: [
      observedCount ? `Correlate ${observedCount} matching log event${observedCount === 1 ? '' : 's'} with alerts and incidents` : 'Correlate IOC with recent logs and incidents',
      country !== 'Unknown' ? `Review traffic from ${country} for the same IOC` : 'Check source reputation before blocking broadly',
      reputation === 'malicious' ? 'Block or isolate this IOC if no business dependency exists' : 'Monitor for repeats before permanent blocking'
    ]
  };
}

function normalizeObservation(log = {}) {
  return {
    sourceIP: log.sourceIP,
    country: log.country,
    attackType: log.attackType,
    severity: log.severity,
    isBlocked: log.isBlocked,
    timestamp: log.timestamp || log.createdAt,
    description: log.description
  };
}

async function getObservedLogsForIoc(value, requestObservations = []) {
  const text = String(value || '').trim();
  const localMatches = requestObservations
    .filter(log => {
      const haystack = `${log.sourceIP || ''} ${log.description || ''} ${log.targetSystem || ''}`.toLowerCase();
      return text && haystack.includes(text.toLowerCase());
    })
    .map(normalizeObservation);

  try {
    const escaped = escapeRegex(text);
    const dbLogs = await Log.find({
      $or: [
        { sourceIP: text },
        { description: { $regex: escaped, $options: 'i' } },
        { targetSystem: { $regex: escaped, $options: 'i' } }
      ]
    })
      .sort({ timestamp: -1 })
      .limit(50)
      .select('timestamp createdAt attackType sourceIP severity country description targetSystem isBlocked')
      .lean();

    const combined = [...localMatches, ...dbLogs.map(normalizeObservation)];
    const seen = new Set();
    return combined.filter(log => {
      const key = `${log.timestamp || ''}-${log.sourceIP || ''}-${log.attackType || ''}-${log.severity || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  } catch (error) {
    return localMatches;
  }
}

router.use(protect);

router.get('/cve/:id', (req, res) => {
  const id = String(req.params.id || '').toUpperCase();
  const result = cveCatalog[id] || {
    title: `${id} lookup`,
    severity: 'unknown',
    cvss: null,
    summary: 'No local catalog entry found. Add an external NVD integration for production enrichment.',
    mitigations: ['Validate affected asset inventory', 'Check vendor advisories', 'Apply compensating controls until confirmed']
  };
  res.json({ success: true, cve: { id, ...result } });
});

router.post('/mitre-map', (req, res) => {
  const text = `${req.body.attackType || ''} ${req.body.description || ''}`;
  const matched = mitreMap.find(item => item.match.test(text));
  res.json({
    success: true,
    mapping: {
      input: text.trim(),
      techniques: matched?.techniques || ['T1082 System Information Discovery', 'T1071 Application Layer Protocol'],
      confidence: matched ? 86 : 52
    }
  });
});

router.post('/ioc-analysis', async (req, res) => {
  const values = Array.isArray(req.body.iocs) ? req.body.iocs : [req.body.ioc].filter(Boolean);
  const requestObservations = Array.isArray(req.body.observations)
    ? req.body.observations.slice(0, 100)
    : [];
  const results = await Promise.all(values.map(async value => {
    const observations = await getObservedLogsForIoc(value, requestObservations);
    return { value, ...scoreIoc(value, observations) };
  }));
  res.json({
    success: true,
    results
  });
});

module.exports = router;
