/**
 * Vajra - AI-Powered Security Scanner
 * Orchestrator - Coordinates all scanning phases
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import {
  VajraConfig,
  TargetInfo,
  Vulnerability,
  ScanModule,
  ScanResult,
  AgentResult,
  AgentContext,
  VajraEvent,
  EventHandler,
  Logger,
  Report,
  ReportSummary,
  SeverityLevel,
  AIEngine,
} from '../types/index.js';
import { createAIEngine } from './ai-engine.js';
import { createLogger } from '../utils/logger.js';
import { ReconnaissanceAgent } from '../agents/reconnaissance.js';
import { VulnerabilityAnalyzer } from '../agents/vulnerability-analyzer.js';
import { ExploitationAgent } from '../agents/exploitation.js';
import { ReportGenerator } from '../reporters/report-generator.js';
import { BrowserManager } from './browser-manager.js';

// ============================================================================
// Vajra Orchestrator
// ============================================================================

export class VajraOrchestrator extends EventEmitter {
  private config: VajraConfig;
  private logger: Logger;
  private aiEngine: AIEngine;
  private browserManager: BrowserManager;
  private vulnerabilities: Vulnerability[] = [];
  private targetInfo: TargetInfo | null = null;
  private scanId: string;
  private startTime: Date | null = null;
  private endTime: Date | null = null;
  
  constructor(config: VajraConfig) {
    super();
    this.config = config;
    this.scanId = uuidv4();
    this.logger = createLogger(config.reporting.outputDir, this.scanId);
    this.aiEngine = createAIEngine(config.ai);
    this.browserManager = new BrowserManager();
  }
  
  /**
   * Start the security scan
   */
  async scan(): Promise<Report> {
    this.startTime = new Date();
    this.emitEvent({
      type: 'scan:started',
      target: this.config.target.url,
      modules: this.config.scanning.modules,
      timestamp: this.startTime,
    });
    
    this.logger.info('Starting Vajra security scan', {
      scanId: this.scanId,
      target: this.config.target.url,
      modules: this.config.scanning.modules,
    });
    
    try {
      // Initialize browser if needed
      await this.initializeBrowser();
      
      // Phase 1: Reconnaissance
      this.targetInfo = await this.runReconnaissance();
      
      // Phase 2: Vulnerability Analysis
      const analysisResults = await this.runVulnerabilityAnalysis();
      
      // Phase 3: Exploitation (Verification)
      const exploitResults = await this.runExploitation(analysisResults);
      
      // Phase 4: Generate Report
      const report = await this.generateReport();
      
      this.endTime = new Date();
      this.emitEvent({
        type: 'scan:completed',
        target: this.config.target.url,
        duration: this.endTime.getTime() - this.startTime.getTime(),
        vulnerabilityCount: this.vulnerabilities.length,
        timestamp: this.endTime,
      });
      
      return report;
    } catch (error) {
      this.logger.error('Scan failed', { error: String(error) });
      throw error;
    } finally {
      await this.cleanup();
    }
  }
  
  /**
   * Initialize browser for dynamic testing
   */
  private async initializeBrowser(): Promise<void> {
    this.logger.info('Initializing browser for dynamic testing');
    await this.browserManager.launch();
    
    if (this.config.authentication) {
      await this.handleAuthentication();
    }
  }
  
  /**
   * Handle authentication flow
   */
  private async handleAuthentication(): Promise<void> {
    const auth = this.config.authentication;
    if (!auth) return;
    
    this.logger.info('Performing authentication', { type: auth.type });
    
    switch (auth.type) {
      case 'basic':
        await this.browserManager.setBasicAuth(
          auth.credentials['username'] || '',
          auth.credentials['password'] || ''
        );
        break;
      case 'bearer':
        await this.browserManager.setBearerToken(auth.credentials['token'] || '');
        break;
      case 'cookie':
        await this.browserManager.setCookies(
          Object.entries(auth.credentials).map(([name, value]) => ({
            name,
            value,
            domain: new URL(this.config.target.url).hostname,
            path: '/',
            secure: this.config.target.url.startsWith('https'),
            httpOnly: false,
          }))
        );
        break;
      case 'custom':
        if (auth.loginFlow) {
          await this.browserManager.executeLoginFlow(auth.loginUrl || '', auth.loginFlow);
        }
        break;
    }
  }
  
  /**
   * Phase 1: Reconnaissance
   */
  private async runReconnaissance(): Promise<TargetInfo> {
    this.emitEvent({
      type: 'agent:started',
      agentId: 'recon-agent',
      agentType: 'reconnaissance',
      timestamp: new Date(),
    });
    
    this.logger.info('Starting reconnaissance phase');
    
    const reconAgent = new ReconnaissanceAgent(
      this.config,
      this.aiEngine,
      this.browserManager,
      this.logger
    );
    
    const context: AgentContext = {
      target: this.config.target,
      config: this.config,
      sharedState: new Map(),
      logger: this.logger,
      browser: this.browserManager.getContext(),
    };
    
    const result = await reconAgent.execute(context);
    
    this.emitEvent({
      type: 'agent:completed',
      agentId: 'recon-agent',
      agentType: 'reconnaissance',
      status: result.status,
      timestamp: new Date(),
    });
    
    return result.data as TargetInfo;
  }
  
  /**
   * Phase 2: Vulnerability Analysis
   */
  private async runVulnerabilityAnalysis(): Promise<ScanResult[]> {
    if (!this.targetInfo) {
      throw new Error('Target info not available. Run reconnaissance first.');
    }
    
    this.logger.info('Starting vulnerability analysis phase');
    
    const results: ScanResult[] = [];
    const modulesToRun = this.config.scanning.modules.filter(m => m !== 'reconnaissance');
    
    for (const module of modulesToRun) {
      this.emitEvent({
        type: 'progress',
        phase: 'vulnerability-analysis',
        current: modulesToRun.indexOf(module) + 1,
        total: modulesToRun.length,
        message: `Running ${module} scanner`,
        timestamp: new Date(),
      });
      
      const analyzer = new VulnerabilityAnalyzer(
        module,
        this.config,
        this.aiEngine,
        this.browserManager,
        this.logger
      );
      
      const result = await analyzer.scan(this.targetInfo);
      results.push(result);
      
      // Collect vulnerabilities
      for (const vuln of result.vulnerabilities) {
        this.addVulnerability(vuln);
      }
    }
    
    return results;
  }
  
  /**
   * Phase 3: Exploitation (Verification)
   */
  private async runExploitation(analysisResults: ScanResult[]): Promise<AgentResult[]> {
    this.logger.info('Starting exploitation/verification phase');
    
    const exploitAgent = new ExploitationAgent(
      this.config,
      this.aiEngine,
      this.browserManager,
      this.logger
    );
    
    const results: AgentResult[] = [];
    
    for (const vuln of this.vulnerabilities) {
      if (!vuln.verified) {
        this.emitEvent({
          type: 'progress',
          phase: 'exploitation',
          current: this.vulnerabilities.indexOf(vuln) + 1,
          total: this.vulnerabilities.length,
          message: `Verifying ${vuln.type} vulnerability`,
          timestamp: new Date(),
        });
        
        const result = await exploitAgent.verify(vuln, this.targetInfo!);
        results.push(result);
        
        if (result.status === 'success') {
          vuln.verified = true;
          vuln.proofOfConcept = result.data as typeof vuln.proofOfConcept;
        }
      }
    }
    
    return results;
  }
  
  /**
   * Phase 4: Generate Report
   */
  private async generateReport(): Promise<Report> {
    this.logger.info('Generating security report');
    
    const reportGenerator = new ReportGenerator(
      this.config,
      this.aiEngine,
      this.logger
    );
    
    const report = await reportGenerator.generate({
      scanId: this.scanId,
      targetInfo: this.targetInfo!,
      vulnerabilities: this.vulnerabilities,
      startTime: this.startTime!,
      endTime: this.endTime || new Date(),
      config: this.config,
    });
    
    return report;
  }
  
  /**
   * Add a discovered vulnerability
   */
  private addVulnerability(vulnerability: Vulnerability): void {
    this.vulnerabilities.push(vulnerability);
    
    this.emitEvent({
      type: 'vulnerability:found',
      vulnerability,
      timestamp: new Date(),
    });
    
    this.logger.warn('Vulnerability discovered', {
      type: vulnerability.type,
      severity: vulnerability.severity,
      url: vulnerability.url,
    });
  }
  
  /**
   * Emit a Vajra event
   */
  private emitEvent(event: VajraEvent): void {
    this.emit(event.type, event);
    this.emit('*', event);
  }
  
  /**
   * Subscribe to events
   */
  onEvent(handler: EventHandler): void {
    this.on('*', handler);
  }
  
  /**
   * Cleanup resources
   */
  private async cleanup(): Promise<void> {
    this.logger.info('Cleaning up resources');
    await this.browserManager.close();
  }
  
  /**
   * Get current scan status
   */
  getStatus(): ScanStatus {
    return {
      scanId: this.scanId,
      target: this.config.target.url,
      startTime: this.startTime,
      endTime: this.endTime,
      vulnerabilityCount: this.vulnerabilities.length,
      vulnerabilitiesBySeverity: this.getVulnerabilitiesBySeverity(),
    };
  }
  
  /**
   * Get vulnerabilities grouped by severity
   */
  private getVulnerabilitiesBySeverity(): Record<SeverityLevel, number> {
    const counts: Record<SeverityLevel, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    
    for (const vuln of this.vulnerabilities) {
      counts[vuln.severity]++;
    }
    
    return counts;
  }
}

// ============================================================================
// Types
// ============================================================================

interface ScanStatus {
  scanId: string;
  target: string;
  startTime: Date | null;
  endTime: Date | null;
  vulnerabilityCount: number;
  vulnerabilitiesBySeverity: Record<SeverityLevel, number>;
}

// ============================================================================
// Factory Function
// ============================================================================

export function createVajra(config: VajraConfig): VajraOrchestrator {
  return new VajraOrchestrator(config);
}

export default VajraOrchestrator;
