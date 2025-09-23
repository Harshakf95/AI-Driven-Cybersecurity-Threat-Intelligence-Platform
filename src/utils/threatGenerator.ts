import { ThreatData, WebThreat, NetworkThreat, SystemMetrics, NetworkGraph } from '../types';

// Generate random IP address
const generateIP = () => {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
};

// Generate random port number
const generatePort = () => {
  return Math.floor(Math.random() * 65535) + 1;
};

// Generate random timestamp within the last 24 hours
const generateTimestamp = () => {
  const now = new Date();
  const hoursAgo = Math.floor(Math.random() * 24);
  const minutesAgo = Math.floor(Math.random() * 60);
  const secondsAgo = Math.floor(Math.random() * 60);
  now.setHours(now.getHours() - hoursAgo);
  now.setMinutes(now.getMinutes() - minutesAgo);
  now.setSeconds(now.getSeconds() - secondsAgo);
  return now;
};

// Web attack types
const webAttackTypes = [
  'SQL Injection',
  'Cross-Site Scripting (XSS)',
  'Cross-Site Request Forgery (CSRF)',
  'Path Traversal',
  'Command Injection',
  'Session Hijacking',
  'Credential Stuffing',
  'Brute Force Login',
  'API Key Theft',
  'Server-Side Request Forgery'
];

// Network anomaly types
const networkAnomalyTypes = [
  'Port Scanning',
  'DDoS Attack',
  'Data Exfiltration',
  'Unusual Protocol Activity',
  'Unauthorized Connection',
  'Lateral Movement',
  'DNS Tunneling',
  'Suspicious Data Transfer',
  'C2 Communication',
  'Port Probing'
];

// Web endpoints
const webEndpoints = [
  '/api/login',
  '/api/users',
  '/api/data',
  '/admin/dashboard',
  '/wp-admin',
  '/api/auth',
  '/api/payment',
  '/admin/settings',
  '/user/profile',
  '/api/documents'
];

// Network protocols
const networkProtocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'SMTP', 'SSH', 'FTP', 'SFTP'];

// Severity distributions
const severities = ['low', 'medium', 'high'] as const;
const severityDistribution = [0.5, 0.3, 0.2]; // 50% low, 30% medium, 20% high

// Status distributions
const statuses = ['active', 'blocked', 'ignored'] as const;
const statusDistribution = [0.7, 0.2, 0.1]; // 70% active, 20% blocked, 10% ignored

// Generate a random value based on distribution
const getRandomWithDistribution = <T>(items: readonly T[], distribution: number[]): T => {
  const rand = Math.random();
  let cumulativeProbability = 0;
  
  for (let i = 0; i < distribution.length; i++) {
    cumulativeProbability += distribution[i];
    if (rand < cumulativeProbability) {
      return items[i];
    }
  }
  
  return items[0]; // Fallback
};

// Generate a single web threat
const generateWebThreat = (id: number): WebThreat => {
  const severity = getRandomWithDistribution(severities, severityDistribution);
  const status = getRandomWithDistribution(statuses, statusDistribution);
  const attackType = webAttackTypes[Math.floor(Math.random() * webAttackTypes.length)];
  
  let payload = '';
  if (attackType === 'SQL Injection') {
    payload = "' OR 1=1; --";
  } else if (attackType === 'Cross-Site Scripting (XSS)') {
    payload = "<script>alert('XSS');</script>";
  } else if (attackType === 'Command Injection') {
    payload = "; cat /etc/passwd";
  }
  
  return {
    id: `web-${id}`,
    timestamp: generateTimestamp(),
    sourceIP: generateIP(),
    targetEndpoint: webEndpoints[Math.floor(Math.random() * webEndpoints.length)],
    attackType,
    severity,
    payload,
    status,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    description: `Attempted ${attackType} attack detected from ${generateIP()}`,
    confidence: Math.floor(Math.random() * 30) + 70 // 70-100%
  };
};

// Generate a single network threat
const generateNetworkThreat = (id: number): NetworkThreat => {
  const severity = getRandomWithDistribution(severities, severityDistribution);
  const status = getRandomWithDistribution(statuses, statusDistribution);
  const anomalyType = networkAnomalyTypes[Math.floor(Math.random() * networkAnomalyTypes.length)];
  const protocol = networkProtocols[Math.floor(Math.random() * networkProtocols.length)];
  
  return {
    id: `net-${id}`,
    timestamp: generateTimestamp(),
    sourceIP: generateIP(),
    destinationIP: generateIP(),
    protocol,
    port: generatePort(),
    trafficVolume: Math.floor(Math.random() * 1000) + 1, // 1-1000 KB
    anomalyType,
    severity,
    status,
    description: `${anomalyType} detected from ${generateIP()} to ${generateIP()}`,
    confidence: Math.floor(Math.random() * 30) + 70 // 70-100%
  };
};

// Generate system metrics
export const generateSystemMetrics = (): SystemMetrics => {
  return {
    cpuUsage: Math.floor(Math.random() * 50) + 10, // 10-60%
    memoryUsage: Math.floor(Math.random() * 40) + 30, // 30-70%
    networkIn: Math.floor(Math.random() * 400) + 100, // 100-500 Mbps
    networkOut: Math.floor(Math.random() * 200) + 50, // 50-250 Mbps
    threatScore: Math.floor(Math.random() * 60) + 10, // 10-70
    activeConnections: Math.floor(Math.random() * 1000) + 100, // 100-1100
    totalRequests: Math.floor(Math.random() * 10000) + 5000, // 5000-15000
    blockedRequests: Math.floor(Math.random() * 500) + 100 // 100-600
  };
};

// Generate network graph data
export const generateNetworkGraph = (): NetworkGraph => {
  const nodes: any[] = [];
  const links: any[] = [];
  
  // Generate nodes
  const numNodes = Math.floor(Math.random() * 20) + 30; // 30-50 nodes
  
  // Create root node (your server)
  nodes.push({
    id: 'server-main',
    name: 'Main Server',
    type: 'target',
    value: 20,
    threat: false
  });
  
  // Create router nodes
  for (let i = 0; i < 5; i++) {
    nodes.push({
      id: `router-${i}`,
      name: `Router ${i + 1}`,
      type: 'router',
      value: 10,
      threat: false
    });
    
    // Link routers to main server
    links.push({
      source: `router-${i}`,
      target: 'server-main',
      value: Math.floor(Math.random() * 10) + 5,
      status: 'normal'
    });
  }
  
  // Create source nodes (clients and potential threats)
  for (let i = 0; i < numNodes - 6; i++) {
    const isThreat = Math.random() < 0.15; // 15% chance of being a threat
    const routerIndex = Math.floor(Math.random() * 5);
    
    nodes.push({
      id: `node-${i}`,
      name: isThreat ? `Malicious Client ${i}` : `Client ${i}`,
      type: 'source',
      value: isThreat ? 8 : 5,
      threat: isThreat,
      anomaly: isThreat && Math.random() < 0.7 // 70% of threats show anomalous behavior
    });
    
    // Link to a random router
    links.push({
      source: `node-${i}`,
      target: `router-${routerIndex}`,
      value: Math.floor(Math.random() * 5) + 1,
      status: isThreat ? (Math.random() < 0.7 ? 'malicious' : 'suspicious') : 'normal'
    });
  }
  
  return { nodes, links };
};

// Generate full threat data
export const generateThreats = (): ThreatData => {
  const numWebThreats = Math.floor(Math.random() * 15) + 10; // 10-25
  const numNetworkThreats = Math.floor(Math.random() * 15) + 5; // 5-20
  
  const webThreats: WebThreat[] = [];
  const networkThreats: NetworkThreat[] = [];
  
  for (let i = 0; i < numWebThreats; i++) {
    webThreats.push(generateWebThreat(i));
  }
  
  for (let i = 0; i < numNetworkThreats; i++) {
    networkThreats.push(generateNetworkThreat(i));
  }
  
  // Sort by timestamp (newest first)
  webThreats.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  networkThreats.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  
  return { webThreats, networkThreats };
};