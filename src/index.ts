/**
 * Vajra - AI-Powered Autonomous Security Scanner
 * 
 * Main entry point for programmatic usage
 */

// Core exports
export { AIEngine, type AIProvider, type AIEngineConfig } from './core/ai-engine';
export { Orchestrator, type OrchestratorConfig } from './core/orchestrator';
export { BrowserManager, type BrowserConfig } from './core/browser-manager';

// Agent exports
export { ReconnaissanceAgent, type ReconResult } from './agents/reconnaissance';
export { VulnerabilityAnalyzer, type VulnerabilityResult } from './agents/vulnerability-analyzer';
export { ExploitationAgent, type ExploitResult } from './agents/exploitation';

// Reporter exports
export { ReportGenerator, type ReportConfig, type ReportFormat } from './reporters/report-generator';

// Configuration exports
export { ConfigLoader, type VajraConfig } from './config/loader';

// Type exports
export * from './types';

// Utility exports
export { logger, createLogger } from './utils/logger';

// Version
export const VERSION = '1.0.0';

/**
 * Quick scan function for simple usage
 * 
 * @example
 * ```typescript
 * import { scan } from 'vajra';
 * 
 * const results = await scan('https://example.com', {
 *   modules: ['xss', 'sqli'],
 *   aiProvider: 'anthropic'
 * });
 * ```
 */
export async function scan(
  targetUrl: string,
  options: {
    modules?: string[];
    aiProvider?: 'anthropic' | 'openai';
    apiKey?: string;
    outputDir?: string;
    reportFormats?: ('html' | 'json' | 'markdown' | 'sarif')[];
    concurrency?: number;
    timeout?: number;
    maxDepth?: number;
    authentication?: {
      type: 'basic' | 'bearer' | 'cookie';
      credentials: Record<string, string>;
    };
    verbose?: boolean;
  } = {}
): Promise<{
  vulnerabilities: any[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  reportPaths: string[];
}> {
  const { Orchestrator } = await import('./core/orchestrator');
  const { ConfigLoader } = await import('./config/loader');
  const { logger } = await import('./utils/logger');

  // Set log level
  if (options.verbose) {
    logger.level = 'debug';
  }

  // Build configuration
  const config = ConfigLoader.buildConfig({
    target: {
      url: targetUrl,
      scope: {
        includeSubdomains: false,
        followRedirects: true,
        respectRobotsTxt: true,
      },
      maxDepth: options.maxDepth || 3,
    },
    ai: {
      provider: options.aiProvider || 'anthropic',
      apiKey: options.apiKey || process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY || '',
      model: options.aiProvider === 'openai' ? 'gpt-4o' : 'claude-sonnet-4-20250514',
      maxTokens: 4096,
    },
    scanning: {
      modules: options.modules || ['reconnaissance', 'xss', 'sqli', 'ssrf', 'lfi', 'command-injection'],
      concurrency: options.concurrency || 5,
      timeout: options.timeout || 30000,
      delayBetweenRequests: 100,
    },
    reporting: {
      format: options.reportFormats || ['html', 'json'],
      outputDir: options.outputDir || './vajra-reports',
      includeScreenshots: true,
      includeProofOfConcept: true,
    },
    authentication: options.authentication,
  });

  // Create and run orchestrator
  const orchestrator = new Orchestrator(config);
  const results = await orchestrator.run();

  // Calculate summary
  const summary = {
    total: results.vulnerabilities.length,
    critical: results.vulnerabilities.filter(v => v.severity === 'critical').length,
    high: results.vulnerabilities.filter(v => v.severity === 'high').length,
    medium: results.vulnerabilities.filter(v => v.severity === 'medium').length,
    low: results.vulnerabilities.filter(v => v.severity === 'low').length,
    info: results.vulnerabilities.filter(v => v.severity === 'info').length,
  };

  return {
    vulnerabilities: results.vulnerabilities,
    summary,
    reportPaths: results.reportPaths || [],
  };
}

// Default export
export default {
  scan,
  VERSION,
  AIEngine: require('./core/ai-engine').AIEngine,
  Orchestrator: require('./core/orchestrator').Orchestrator,
  BrowserManager: require('./core/browser-manager').BrowserManager,
  ReconnaissanceAgent: require('./agents/reconnaissance').ReconnaissanceAgent,
  VulnerabilityAnalyzer: require('./agents/vulnerability-analyzer').VulnerabilityAnalyzer,
  ExploitationAgent: require('./agents/exploitation').ExploitationAgent,
  ReportGenerator: require('./reporters/report-generator').ReportGenerator,
  ConfigLoader: require('./config/loader').ConfigLoader,
};
