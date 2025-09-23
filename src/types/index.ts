export interface WebThreat {
  id: string;
  timestamp: Date | string;
  sourceIP: string;
  targetEndpoint: string;
  attackType: string;
  severity: 'low' | 'medium' | 'high';
  payload?: string;
  status: 'active' | 'blocked' | 'ignored';
  userAgent?: string;
  description: string;
  confidence: number;
}

export interface NetworkThreat {
  id: string;
  timestamp: Date | string;
  sourceIP: string;
  destinationIP: string;
  protocol: string;
  port: number;
  trafficVolume?: number;
  anomalyType: string;
  severity: 'low' | 'medium' | 'high';
  status: 'active' | 'blocked' | 'ignored';
  description: string;
  confidence: number;
}

export interface ThreatData {
  webThreats: WebThreat[];
  networkThreats: NetworkThreat[];
}

export interface SystemMetrics {
  cpuUsage: number;
  memoryUsage: number;
  networkIn: number;
  networkOut: number;
  threatScore: number;
  activeConnections: number;
  totalRequests: number;
  blockedRequests: number;
}

export interface GraphNode {
  id: string;
  name: string;
  type: 'source' | 'target' | 'router';
  value: number;
  threat?: boolean;
  anomaly?: boolean;
}

export interface GraphLink {
  source: string;
  target: string;
  value: number;
  status?: 'normal' | 'suspicious' | 'malicious';
}

export interface NetworkGraph {
  nodes: GraphNode[];
  links: GraphLink[];
}