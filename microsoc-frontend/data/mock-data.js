// Mock Data for the Application

const MOCK_DATA = {
    // Incident Data
    incidents: [
        {
            id: 1,
            title: "Multiple XSS Attack Attempts",
            description: "Detected 12 XSS attack attempts from IP 192.168.1.105 targeting login forms",
            severity: "critical",
            status: "open",
            assignedTo: "Honey Tiwari",
            createdAt: "2024-01-15T10:30:00Z",
            logs: 12,
            sourceIP: "192.168.1.105"
        },
        {
            id: 2,
            title: "SQL Injection Attempt",
            description: "SQL injection detected in user search functionality",
            severity: "high",
            status: "in_progress",
            assignedTo: "Mahak Garg",
            createdAt: "2024-01-15T09:15:00Z",
            logs: 5,
            sourceIP: "10.0.0.42"
        },
        {
            id: 3,
            title: "Port Scanning Activity",
            description: "Multiple port scan attempts from external IP",
            severity: "medium",
            status: "open",
            assignedTo: null,
            createdAt: "2024-01-15T08:45:00Z",
            logs: 23,
            sourceIP: "203.0.113.25"
        },
        {
            id: 4,
            title: "Failed Login Attempts",
            description: "45 failed login attempts detected within 5 minutes",
            severity: "high",
            status: "resolved",
            assignedTo: "Honey Tiwari",
            createdAt: "2024-01-14T22:10:00Z",
            logs: 45,
            sourceIP: "198.51.100.13"
        },
        {
            id: 5,
            title: "DDoS Attack Mitigated",
            description: "Successfully mitigated DDoS attack from botnet",
            severity: "critical",
            status: "closed",
            assignedTo: "Mahak Garg",
            createdAt: "2024-01-14T15:20:00Z",
            logs: 1250,
            sourceIP: "Multiple"
        }
    ],
    
    // Log Data
    logs: [
        {
            id: 1,
            timestamp: "2024-01-15T10:25:00Z",
            attackType: "XSS",
            sourceIP: "192.168.1.105",
            targetSystem: "web-server-01",
            severity: "critical",
            description: "XSS script injection attempt in contact form"
        },
        {
            id: 2,
            timestamp: "2024-01-15T10:20:00Z",
            attackType: "SQL Injection",
            sourceIP: "10.0.0.42",
            targetSystem: "db-server-01",
            severity: "high",
            description: "SQL injection attempt in user query"
        },
        {
            id: 3,
            timestamp: "2024-01-15T10:15:00Z",
            attackType: "Port Scan",
            sourceIP: "203.0.113.25",
            targetSystem: "firewall-01",
            severity: "medium",
            description: "Port scan detected on ports 22, 80, 443"
        }
    ],
    
    // Analytics Data
    analytics: {
        attackTrends: {
            labels: ["Jan 8", "Jan 9", "Jan 10", "Jan 11", "Jan 12", "Jan 13", "Jan 14"],
            datasets: {
                xss: [45, 32, 56, 28, 39, 25, 42],
                sql: [28, 35, 31, 42, 26, 38, 29],
                portScan: [78, 65, 89, 72, 81, 68, 75],
                bruteForce: [42, 38, 51, 34, 47, 41, 39]
            }
        },
        
        threatDistribution: {
            xss: 25,
            sqlInjection: 20,
            portScan: 30,
            bruteForce: 15,
            ddos: 5,
            malware: 5
        },
        
        topAttackers: [
            { ip: "192.168.1.105", count: 245, country: "USA" },
            { ip: "10.0.0.42", count: 189, country: "China" },
            { ip: "172.16.0.88", count: 156, country: "Russia" }
        ]
    }
};

// Export data
window.MOCK_DATA = MOCK_DATA;