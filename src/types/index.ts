/**
 * Vajra - AI-Powered Security Scanner
 * Type Definitions
 */

// ============================================================================
// Core Types
// ============================================================================

export interface VajraConfig {
  target: TargetConfig;
  ai: AIConfig;
  scanning: ScanConfig;
  reporting: ReportConfig;
  authentication?: AuthConfig;
}

export interface TargetConfig {
  url: string;
  scope: ScopeConfig;
  excludePaths?: string[];
  includePaths?: string[];
  maxDepth?: number;
}

export interface ScopeConfig {
  includeSubdomains: boolean;
  followRedirects: boolean;
  respectRobotsTxt: boolean;
  maxUrls?: number;
}

export interface AIConfig {
  provider: 'anthropic' | 'openai' | 'local';
  model: string;
  apiKey?: string;
  maxTokens?: number;
  temperature?: number;
  timeout?: number;
}

export interface ScanConfig {
  modules: ScanModule[];
  concurrency: number;
  timeout: number;
  retries: number;
  delayBetweenRequests?: number;
  userAgent?: string;
  headers?: Record<string, string>;
}

export type ScanModule = 
  | 'reconnaissance'
  | 'xss'
  | 'sqli'
  | 'ssrf'
  | 'auth-bypass'
  | 'idor'
  | 'lfi'
  | 'rfi'
  | 'command-injection'
  | 'xxe'
  | 'csrf'
  | 'cors'
  | 'security-headers'
  | 'ssl-tls'
  | 'information-disclosure';

export interface ReportConfig {
  format: ReportFormat[];
  outputDir: string;
  includeScreenshots: boolean;
  includeProofOfConcept: boolean;
  severity: SeverityLevel[];
}

export type ReportFormat = 'html' | 'json' | 'markdown' | 'pdf' | 'sarif';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface AuthConfig {
  type: 'basic' | 'bearer' | 'cookie' | 'oauth2' | 'custom';
  credentials: Record<string, string>;
  loginUrl?: string;
  loginFlow?: LoginFlowStep[];
}

export interface LoginFlowStep {
  action: 'navigate' | 'click' | 'type' | 'wait' | 'submit';
  selector?: string;
  value?: string;
  timeout?: number;
}

// ============================================================================
// Vulnerability Types
// ============================================================================

export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: SeverityLevel;
  title: string;
  description: string;
  url: string;
  parameter?: string;
  payload?: string;
  evidence: Evidence;
  remediation: string;
  references: string[];
  cvss?: CVSSScore;
  cwe?: string[];
  owasp?: string[];
  timestamp: Date;
  verified: boolean;
  proofOfConcept?: ProofOfConcept;
}

export type VulnerabilityType =
  | 'xss-reflected'
  | 'xss-stored'
  | 'xss-dom'
  | 'sqli-error'
  | 'sqli-blind'
  | 'sqli-time'
  | 'sqli-union'
  | 'ssrf'
  | 'auth-bypass'
  | 'idor'
  | 'lfi'
  | 'rfi'
  | 'command-injection'
  | 'xxe'
  | 'csrf'
  | 'cors-misconfiguration'
  | 'missing-security-header'
  | 'ssl-tls-issue'
  | 'information-disclosure'
  | 'open-redirect'
  | 'path-traversal'
  | 'insecure-deserialization'
  | 'broken-access-control';

export interface Evidence {
  request: HTTPRequest;
  response: HTTPResponse;
  screenshot?: string;
  logs?: string[];
}

export interface HTTPRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  cookies?: Record<string, string>;
}

export interface HTTPResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  responseTime: number;
}

export interface CVSSScore {
  version: '3.0' | '3.1' | '4.0';
  score: number;
  vector: string;
  severity: SeverityLevel;
}

export interface ProofOfConcept {
  steps: string[];
  code?: string;
  curlCommand?: string;
  browserSteps?: BrowserStep[];
}

export interface BrowserStep {
  action: string;
  description: string;
  screenshot?: string;
}

// ============================================================================
// Agent Types
// ============================================================================

export interface Agent {
  id: string;
  name: string;
  type: AgentType;
  status: AgentStatus;
  capabilities: string[];
  execute(context: AgentContext): Promise<AgentResult>;
}

export type AgentType =
  | 'orchestrator'
  | 'reconnaissance'
  | 'vulnerability-analyzer'
  | 'exploiter'
  | 'reporter';

export type AgentStatus = 'idle' | 'running' | 'completed' | 'failed' | 'paused';

export interface AgentContext {
  target: TargetConfig;
  config: VajraConfig;
  previousResults?: AgentResult[];
  sharedState: Map<string, unknown>;
  logger: Logger;
  browser?: BrowserContext;
}

export interface AgentResult {
  agentId: string;
  agentType: AgentType;
  status: 'success' | 'partial' | 'failed';
  data: unknown;
  vulnerabilities?: Vulnerability[];
  errors?: AgentError[];
  metrics: AgentMetrics;
  timestamp: Date;
}

export interface AgentError {
  code: string;
  message: string;
  stack?: string;
  recoverable: boolean;
}

export interface AgentMetrics {
  startTime: Date;
  endTime: Date;
  duration: number;
  requestCount: number;
  errorCount: number;
  memoryUsage: number;
}

// ============================================================================
// Scanner Types
// ============================================================================

export interface Scanner {
  id: string;
  name: string;
  type: ScanModule;
  description: string;
  scan(context: ScanContext): Promise<ScanResult>;
}

export interface ScanContext {
  target: TargetInfo;
  config: ScanConfig;
  endpoints: Endpoint[];
  parameters: Parameter[];
  cookies: Cookie[];
  headers: Record<string, string>;
  browser?: BrowserContext;
  ai: AIEngine;
}

export interface ScanResult {
  scannerId: string;
  scannerType: ScanModule;
  status: 'completed' | 'partial' | 'failed';
  vulnerabilities: Vulnerability[];
  coverage: ScanCoverage;
  errors?: string[];
  duration: number;
}

export interface ScanCoverage {
  endpointsTested: number;
  totalEndpoints: number;
  parametersTested: number;
  totalParameters: number;
  payloadsUsed: number;
}

// ============================================================================
// Reconnaissance Types
// ============================================================================

export interface TargetInfo {
  url: string;
  domain: string;
  ip?: string;
  ports?: PortInfo[];
  technologies: Technology[];
  endpoints: Endpoint[];
  parameters: Parameter[];
  forms: FormInfo[];
  cookies: Cookie[];
  headers: Record<string, string>;
  robots?: RobotsInfo;
  sitemap?: string[];
  subdomains?: string[];
}

export interface PortInfo {
  port: number;
  protocol: 'tcp' | 'udp';
  service?: string;
  version?: string;
  state: 'open' | 'closed' | 'filtered';
}

export interface Technology {
  name: string;
  version?: string;
  category: TechnologyCategory;
  confidence: number;
}

export type TechnologyCategory =
  | 'web-server'
  | 'programming-language'
  | 'framework'
  | 'cms'
  | 'database'
  | 'cdn'
  | 'waf'
  | 'analytics'
  | 'javascript-library'
  | 'security'
  | 'other';

export interface Endpoint {
  url: string;
  method: string;
  parameters: Parameter[];
  headers: Record<string, string>;
  authenticated: boolean;
  contentType?: string;
  responseType?: string;
}

export interface Parameter {
  name: string;
  type: ParameterType;
  location: ParameterLocation;
  value?: string;
  required?: boolean;
  dataType?: string;
}

export type ParameterType = 'string' | 'number' | 'boolean' | 'array' | 'object' | 'file';
export type ParameterLocation = 'query' | 'body' | 'header' | 'cookie' | 'path';

export interface FormInfo {
  action: string;
  method: string;
  inputs: FormInput[];
  hasFileUpload: boolean;
  hasCsrfToken: boolean;
}

export interface FormInput {
  name: string;
  type: string;
  required: boolean;
  value?: string;
  pattern?: string;
}

export interface Cookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
  expires?: Date;
}

export interface RobotsInfo {
  allowed: string[];
  disallowed: string[];
  sitemaps: string[];
  crawlDelay?: number;
}

// ============================================================================
// AI Engine Types
// ============================================================================

export interface AIEngine {
  provider: string;
  model: string;
  analyze(prompt: string, context?: AIContext): Promise<AIResponse>;
  generatePayloads(type: VulnerabilityType, context: PayloadContext): Promise<string[]>;
  classifyVulnerability(evidence: Evidence): Promise<VulnerabilityClassification>;
  suggestRemediation(vulnerability: Vulnerability): Promise<string>;
}

export interface AIContext {
  systemPrompt?: string;
  previousMessages?: AIMessage[];
  maxTokens?: number;
  temperature?: number;
}

export interface AIMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface AIResponse {
  content: string;
  usage: TokenUsage;
  model: string;
  finishReason: string;
}

export interface TokenUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

export interface PayloadContext {
  endpoint: Endpoint;
  parameter: Parameter;
  technology?: Technology;
  previousPayloads?: string[];
  successfulPayloads?: string[];
}

export interface VulnerabilityClassification {
  type: VulnerabilityType;
  severity: SeverityLevel;
  confidence: number;
  reasoning: string;
}

// ============================================================================
// Browser Types
// ============================================================================

export interface BrowserContext {
  launch(): Promise<void>;
  close(): Promise<void>;
  newPage(): Promise<BrowserPage>;
  setCookies(cookies: Cookie[]): Promise<void>;
  setHeaders(headers: Record<string, string>): Promise<void>;
}

export interface BrowserPage {
  goto(url: string, options?: NavigationOptions): Promise<void>;
  click(selector: string): Promise<void>;
  type(selector: string, text: string): Promise<void>;
  evaluate<T>(fn: () => T): Promise<T>;
  screenshot(options?: ScreenshotOptions): Promise<Buffer>;
  waitForSelector(selector: string, options?: WaitOptions): Promise<void>;
  waitForNavigation(options?: WaitOptions): Promise<void>;
  content(): Promise<string>;
  url(): string;
  close(): Promise<void>;
}

export interface NavigationOptions {
  timeout?: number;
  waitUntil?: 'load' | 'domcontentloaded' | 'networkidle';
}

export interface ScreenshotOptions {
  fullPage?: boolean;
  type?: 'png' | 'jpeg';
  quality?: number;
}

export interface WaitOptions {
  timeout?: number;
  visible?: boolean;
}

// ============================================================================
// Logging Types
// ============================================================================

export interface Logger {
  debug(message: string, meta?: Record<string, unknown>): void;
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
  verbose(message: string, meta?: Record<string, unknown>): void;
}

export interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: Date;
  meta?: Record<string, unknown>;
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'verbose';

// ============================================================================
// Report Types
// ============================================================================

export interface Report {
  id: string;
  title: string;
  target: TargetInfo;
  summary: ReportSummary;
  vulnerabilities: Vulnerability[];
  scanInfo: ScanInfo;
  recommendations: Recommendation[];
  generatedAt: Date;
}

export interface ReportSummary {
  totalVulnerabilities: number;
  bySeverity: Record<SeverityLevel, number>;
  byType: Record<VulnerabilityType, number>;
  riskScore: number;
  riskLevel: SeverityLevel;
}

export interface ScanInfo {
  startTime: Date;
  endTime: Date;
  duration: number;
  modulesRun: ScanModule[];
  coverage: ScanCoverage;
  configuration: Partial<VajraConfig>;
}

export interface Recommendation {
  priority: number;
  title: string;
  description: string;
  affectedVulnerabilities: string[];
  effort: 'low' | 'medium' | 'high';
  impact: 'low' | 'medium' | 'high';
}

// ============================================================================
// Event Types
// ============================================================================

export type VajraEvent =
  | ScanStartedEvent
  | ScanCompletedEvent
  | VulnerabilityFoundEvent
  | AgentStartedEvent
  | AgentCompletedEvent
  | ErrorEvent
  | ProgressEvent;

export interface ScanStartedEvent {
  type: 'scan:started';
  target: string;
  modules: ScanModule[];
  timestamp: Date;
}

export interface ScanCompletedEvent {
  type: 'scan:completed';
  target: string;
  duration: number;
  vulnerabilityCount: number;
  timestamp: Date;
}

export interface VulnerabilityFoundEvent {
  type: 'vulnerability:found';
  vulnerability: Vulnerability;
  timestamp: Date;
}

export interface AgentStartedEvent {
  type: 'agent:started';
  agentId: string;
  agentType: AgentType;
  timestamp: Date;
}

export interface AgentCompletedEvent {
  type: 'agent:completed';
  agentId: string;
  agentType: AgentType;
  status: 'success' | 'partial' | 'failed';
  timestamp: Date;
}

export interface ErrorEvent {
  type: 'error';
  error: AgentError;
  context?: string;
  timestamp: Date;
}

export interface ProgressEvent {
  type: 'progress';
  phase: string;
  current: number;
  total: number;
  message: string;
  timestamp: Date;
}

export type EventHandler = (event: VajraEvent) => void;
