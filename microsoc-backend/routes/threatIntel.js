const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');

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

function scoreIoc(value = '') {
  const text = String(value).trim();
  const isIp = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?\d\d?)$/.test(text);
  const isHash = /^[a-f0-9]{32,64}$/i.test(text);
  const isDomain = /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(text);
  const suspicious = /(^185\.|^45\.|\.ru$|\.top$|paste|login|verify|update)/i.test(text);

  return {
    type: isIp ? 'ip' : isHash ? 'hash' : isDomain ? 'domain' : 'unknown',
    reputation: suspicious ? 'suspicious' : 'unknown',
    confidence: suspicious ? 78 : 45,
    recommendations: [
      'Correlate IOC with recent logs and incidents',
      'Check source reputation before blocking broadly',
      suspicious ? 'Temporarily deny or challenge this IOC at edge controls' : 'Monitor for repeats before permanent blocking'
    ]
  };
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

router.post('/ioc-analysis', (req, res) => {
  const values = Array.isArray(req.body.iocs) ? req.body.iocs : [req.body.ioc].filter(Boolean);
  res.json({
    success: true,
    results: values.map(value => ({ value, ...scoreIoc(value) }))
  });
});

module.exports = router;
