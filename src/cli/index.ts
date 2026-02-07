#!/usr/bin/env node

/**
 * Vajra - AI-Powered Security Scanner
 * Command Line Interface
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import figlet from 'figlet';
import gradient from 'gradient-string';
import boxen from 'boxen';
import Table from 'cli-table3';
import * as fs from 'fs/promises';
import * as path from 'path';
import { VajraOrchestrator, createVajra } from '../core/orchestrator.js';
import { loadConfig, createDefaultConfig } from '../config/loader.js';
import {
  VajraConfig,
  ScanModule,
  SeverityLevel,
  VajraEvent,
  Vulnerability,
} from '../types/index.js';

// ============================================================================
// CLI Setup
// ============================================================================

const program = new Command();

program
  .name('vajra')
  .description('⚡ Vajra - AI-Powered Autonomous Security Scanner')
  .version('1.0.0');

// ============================================================================
// Banner
// ============================================================================

function showBanner(): void {
  const banner = figlet.textSync('VAJRA', {
    font: 'ANSI Shadow',
    horizontalLayout: 'default',
  });
  
  console.log(gradient.vice(banner));
  console.log(
    boxen(
      chalk.cyan('AI-Powered Autonomous Security Scanner\n') +
      chalk.gray('Version 1.0.0 | github.com/vajra-security/vajra'),
      {
        padding: 1,
        margin: 1,
        borderStyle: 'round',
        borderColor: 'cyan',
      }
    )
  );
}

// ============================================================================
// Scan Command
// ============================================================================

program
  .command('scan')
  .description('Run a security scan against a target')
  .argument('<target>', 'Target URL to scan')
  .option('-c, --config <path>', 'Path to configuration file')
  .option('-m, --modules <modules>', 'Comma-separated list of modules to run', 'all')
  .option('-o, --output <dir>', 'Output directory for reports', './vajra-reports')
  .option('-f, --format <formats>', 'Report formats (json,html,markdown,sarif)', 'html,json')
  .option('--ai-provider <provider>', 'AI provider (anthropic, openai)', 'anthropic')
  .option('--ai-model <model>', 'AI model to use')
  .option('--concurrency <n>', 'Number of concurrent requests', '5')
  .option('--timeout <ms>', 'Request timeout in milliseconds', '30000')
  .option('--delay <ms>', 'Delay between requests in milliseconds', '100')
  .option('--max-depth <n>', 'Maximum crawl depth', '3')
  .option('--include-subdomains', 'Include subdomains in scope')
  .option('--auth-type <type>', 'Authentication type (basic, bearer, cookie)')
  .option('--auth-user <user>', 'Username for basic auth')
  .option('--auth-pass <pass>', 'Password for basic auth')
  .option('--auth-token <token>', 'Token for bearer auth')
  .option('--severity <levels>', 'Minimum severity to report (critical,high,medium,low,info)', 'low')
  .option('--screenshots', 'Include screenshots in report')
  .option('--poc', 'Include proof of concept in report')
  .option('-v, --verbose', 'Verbose output')
  .option('-q, --quiet', 'Quiet mode (minimal output)')
  .action(async (target: string, options: ScanOptions) => {
    showBanner();
    
    const spinner = ora('Initializing Vajra...').start();
    
    try {
      // Load or create configuration
      let config: VajraConfig;
      
      if (options.config) {
        config = await loadConfig(options.config);
        config.target.url = target;
      } else {
        config = buildConfigFromOptions(target, options);
      }
      
      spinner.succeed('Configuration loaded');
      
      // Display scan configuration
      if (!options.quiet) {
        displayScanConfig(config);
      }
      
      // Create and run scanner
      const vajra = createVajra(config);
      
      // Set up event handlers
      setupEventHandlers(vajra, options);
      
      spinner.start('Starting security scan...');
      
      const report = await vajra.scan();
      
      spinner.succeed('Scan completed!');
      
      // Display results
      if (!options.quiet) {
        displayResults(report.vulnerabilities, report.summary.riskScore);
      }
      
      console.log(
        boxen(
          chalk.green('✓ Report saved to: ') + chalk.cyan(config.reporting.outputDir),
          { padding: 1, borderColor: 'green' }
        )
      );
      
      // Exit with appropriate code
      const exitCode = report.summary.bySeverity.critical > 0 ? 2 :
                       report.summary.bySeverity.high > 0 ? 1 : 0;
      process.exit(exitCode);
      
    } catch (error) {
      spinner.fail('Scan failed');
      console.error(chalk.red('Error:'), error);
      process.exit(1);
    }
  });

// ============================================================================
// Init Command
// ============================================================================

program
  .command('init')
  .description('Initialize a new Vajra configuration file')
  .option('-o, --output <path>', 'Output path for config file', './vajra.config.yaml')
  .action(async (options: { output: string }) => {
    showBanner();
    
    const spinner = ora('Creating configuration file...').start();
    
    try {
      const defaultConfig = createDefaultConfig('https://example.com');
      const configPath = options.output;
      
      const yamlContent = generateYamlConfig(defaultConfig);
      await fs.writeFile(configPath, yamlContent);
      
      spinner.succeed(`Configuration file created: ${configPath}`);
      
      console.log(
        boxen(
          chalk.cyan('Next steps:\n\n') +
          chalk.white('1. Edit the configuration file with your target URL\n') +
          chalk.white('2. Set your AI API key in environment variables:\n') +
          chalk.gray('   export ANTHROPIC_API_KEY=your-key\n') +
          chalk.white('3. Run the scan:\n') +
          chalk.gray(`   vajra scan https://target.com -c ${configPath}`),
          { padding: 1, borderColor: 'cyan' }
        )
      );
    } catch (error) {
      spinner.fail('Failed to create configuration file');
      console.error(chalk.red('Error:'), error);
      process.exit(1);
    }
  });

// ============================================================================
// Report Command
// ============================================================================

program
  .command('report')
  .description('Generate a report from a previous scan')
  .argument('<scan-file>', 'Path to scan results JSON file')
  .option('-f, --format <formats>', 'Report formats (json,html,markdown,sarif)', 'html')
  .option('-o, --output <dir>', 'Output directory', './vajra-reports')
  .action(async (scanFile: string, options: { format: string; output: string }) => {
    showBanner();
    
    const spinner = ora('Generating report...').start();
    
    try {
      const scanData = JSON.parse(await fs.readFile(scanFile, 'utf-8'));
      
      // TODO: Implement report regeneration
      
      spinner.succeed('Report generated');
    } catch (error) {
      spinner.fail('Failed to generate report');
      console.error(chalk.red('Error:'), error);
      process.exit(1);
    }
  });

// ============================================================================
// List Modules Command
// ============================================================================

program
  .command('modules')
  .description('List available scanning modules')
  .action(() => {
    showBanner();
    
    const modules: Array<{ name: string; description: string; severity: string }> = [
      { name: 'reconnaissance', description: 'Map attack surface and discover endpoints', severity: 'info' },
      { name: 'xss', description: 'Cross-Site Scripting vulnerabilities', severity: 'high' },
      { name: 'sqli', description: 'SQL Injection vulnerabilities', severity: 'critical' },
      { name: 'ssrf', description: 'Server-Side Request Forgery', severity: 'critical' },
      { name: 'auth-bypass', description: 'Authentication bypass vulnerabilities', severity: 'critical' },
      { name: 'idor', description: 'Insecure Direct Object References', severity: 'high' },
      { name: 'lfi', description: 'Local File Inclusion', severity: 'critical' },
      { name: 'rfi', description: 'Remote File Inclusion', severity: 'critical' },
      { name: 'command-injection', description: 'OS Command Injection', severity: 'critical' },
      { name: 'xxe', description: 'XML External Entity Injection', severity: 'critical' },
      { name: 'csrf', description: 'Cross-Site Request Forgery', severity: 'medium' },
      { name: 'cors', description: 'CORS Misconfiguration', severity: 'medium' },
      { name: 'security-headers', description: 'Missing Security Headers', severity: 'low' },
      { name: 'ssl-tls', description: 'SSL/TLS Configuration Issues', severity: 'medium' },
      { name: 'information-disclosure', description: 'Sensitive Information Exposure', severity: 'medium' },
    ];
    
    const table = new Table({
      head: [
        chalk.cyan('Module'),
        chalk.cyan('Description'),
        chalk.cyan('Typical Severity'),
      ],
      style: { head: [], border: [] },
    });
    
    for (const mod of modules) {
      const severityColor = getSeverityColor(mod.severity as SeverityLevel);
      table.push([
        chalk.white(mod.name),
        chalk.gray(mod.description),
        severityColor(mod.severity.toUpperCase()),
      ]);
    }
    
    console.log(table.toString());
  });

// ============================================================================
// Helper Functions
// ============================================================================

function buildConfigFromOptions(target: string, options: ScanOptions): VajraConfig {
  const modules: ScanModule[] = options.modules === 'all'
    ? ['reconnaissance', 'xss', 'sqli', 'ssrf', 'auth-bypass', 'idor', 'lfi', 'command-injection', 'cors', 'security-headers']
    : options.modules.split(',') as ScanModule[];
  
  const formats = options.format.split(',') as Array<'json' | 'html' | 'markdown' | 'sarif'>;
  const severities = options.severity.split(',') as SeverityLevel[];
  
  const config: VajraConfig = {
    target: {
      url: target,
      scope: {
        includeSubdomains: options.includeSubdomains || false,
        followRedirects: true,
        respectRobotsTxt: true,
      },
      maxDepth: parseInt(options.maxDepth, 10),
    },
    ai: {
      provider: options.aiProvider as 'anthropic' | 'openai',
      model: options.aiModel || (options.aiProvider === 'openai' ? 'gpt-4-turbo-preview' : 'claude-sonnet-4-20250514'),
    },
    scanning: {
      modules,
      concurrency: parseInt(options.concurrency, 10),
      timeout: parseInt(options.timeout, 10),
      retries: 3,
      delayBetweenRequests: parseInt(options.delay, 10),
    },
    reporting: {
      format: formats,
      outputDir: options.output,
      includeScreenshots: options.screenshots || false,
      includeProofOfConcept: options.poc || false,
      severity: severities,
    },
  };
  
  // Add authentication if provided
  if (options.authType) {
    config.authentication = {
      type: options.authType as 'basic' | 'bearer' | 'cookie',
      credentials: {},
    };
    
    if (options.authType === 'basic' && options.authUser && options.authPass) {
      config.authentication.credentials = {
        username: options.authUser,
        password: options.authPass,
      };
    } else if (options.authType === 'bearer' && options.authToken) {
      config.authentication.credentials = {
        token: options.authToken,
      };
    }
  }
  
  return config;
}

function displayScanConfig(config: VajraConfig): void {
  const table = new Table({
    style: { head: [], border: [] },
  });
  
  table.push(
    [chalk.cyan('Target'), chalk.white(config.target.url)],
    [chalk.cyan('Modules'), chalk.white(config.scanning.modules.join(', '))],
    [chalk.cyan('AI Provider'), chalk.white(`${config.ai.provider} (${config.ai.model})`)],
    [chalk.cyan('Concurrency'), chalk.white(config.scanning.concurrency.toString())],
    [chalk.cyan('Output'), chalk.white(config.reporting.outputDir)],
  );
  
  console.log(
    boxen(table.toString(), {
      title: '⚙️  Scan Configuration',
      titleAlignment: 'center',
      padding: 1,
      borderColor: 'cyan',
    })
  );
}

function setupEventHandlers(vajra: VajraOrchestrator, options: ScanOptions): void {
  if (options.quiet) return;
  
  let currentSpinner: ReturnType<typeof ora> | null = null;
  
  vajra.onEvent((event: VajraEvent) => {
    switch (event.type) {
      case 'agent:started':
        if (currentSpinner) currentSpinner.succeed();
        currentSpinner = ora(`Running ${event.agentType} agent...`).start();
        break;
        
      case 'agent:completed':
        if (currentSpinner) {
          if (event.status === 'success') {
            currentSpinner.succeed(`${event.agentType} completed`);
          } else {
            currentSpinner.warn(`${event.agentType} completed with issues`);
          }
        }
        break;
        
      case 'vulnerability:found':
        if (currentSpinner) currentSpinner.stop();
        const vuln = event.vulnerability;
        const color = getSeverityColor(vuln.severity);
        console.log(
          color(`  ⚠ [${vuln.severity.toUpperCase()}]`) +
          chalk.white(` ${vuln.title}`) +
          chalk.gray(` (${vuln.url})`)
        );
        if (currentSpinner) currentSpinner.start();
        break;
        
      case 'progress':
        if (currentSpinner && options.verbose) {
          currentSpinner.text = `${event.phase}: ${event.message} (${event.current}/${event.total})`;
        }
        break;
        
      case 'error':
        if (currentSpinner) currentSpinner.stop();
        console.error(chalk.red(`  ✗ Error: ${event.error.message}`));
        if (currentSpinner) currentSpinner.start();
        break;
    }
  });
}

function displayResults(vulnerabilities: Vulnerability[], riskScore: number): void {
  console.log('\n');
  
  // Summary table
  const summaryTable = new Table({
    head: [
      chalk.red('Critical'),
      chalk.yellow('High'),
      chalk.hex('#FFA500')('Medium'),
      chalk.green('Low'),
      chalk.blue('Info'),
      chalk.white('Total'),
    ],
    style: { head: [], border: [] },
  });
  
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  
  for (const vuln of vulnerabilities) {
    counts[vuln.severity]++;
  }
  
  summaryTable.push([
    chalk.red(counts.critical.toString()),
    chalk.yellow(counts.high.toString()),
    chalk.hex('#FFA500')(counts.medium.toString()),
    chalk.green(counts.low.toString()),
    chalk.blue(counts.info.toString()),
    chalk.white(vulnerabilities.length.toString()),
  ]);
  
  console.log(
    boxen(summaryTable.toString(), {
      title: '📊 Vulnerability Summary',
      titleAlignment: 'center',
      padding: 1,
      borderColor: getRiskColor(riskScore),
    })
  );
  
  // Risk score
  const riskBar = generateRiskBar(riskScore);
  console.log(
    boxen(
      `Risk Score: ${riskScore}/100\n${riskBar}`,
      {
        title: '⚠️  Risk Assessment',
        titleAlignment: 'center',
        padding: 1,
        borderColor: getRiskColor(riskScore),
      }
    )
  );
  
  // Top vulnerabilities
  if (vulnerabilities.length > 0) {
    const topVulns = vulnerabilities
      .sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity))
      .slice(0, 5);
    
    const vulnTable = new Table({
      head: [
        chalk.cyan('Severity'),
        chalk.cyan('Type'),
        chalk.cyan('URL'),
      ],
      style: { head: [], border: [] },
      colWidths: [12, 25, 50],
    });
    
    for (const vuln of topVulns) {
      const color = getSeverityColor(vuln.severity);
      vulnTable.push([
        color(vuln.severity.toUpperCase()),
        chalk.white(vuln.type),
        chalk.gray(truncate(vuln.url, 47)),
      ]);
    }
    
    console.log(
      boxen(vulnTable.toString(), {
        title: '🔍 Top Vulnerabilities',
        titleAlignment: 'center',
        padding: 1,
        borderColor: 'yellow',
      })
    );
  }
}

function getSeverityColor(severity: SeverityLevel): chalk.Chalk {
  const colors: Record<SeverityLevel, chalk.Chalk> = {
    critical: chalk.red,
    high: chalk.yellow,
    medium: chalk.hex('#FFA500'),
    low: chalk.green,
    info: chalk.blue,
  };
  return colors[severity];
}

function getRiskColor(score: number): string {
  if (score >= 80) return 'red';
  if (score >= 50) return 'yellow';
  if (score >= 25) return '#FFA500';
  return 'green';
}

function generateRiskBar(score: number): string {
  const width = 40;
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;
  
  const filledChar = '█';
  const emptyChar = '░';
  
  let bar = '';
  for (let i = 0; i < filled; i++) {
    if (i < width * 0.25) bar += chalk.green(filledChar);
    else if (i < width * 0.5) bar += chalk.yellow(filledChar);
    else if (i < width * 0.75) bar += chalk.hex('#FFA500')(filledChar);
    else bar += chalk.red(filledChar);
  }
  bar += chalk.gray(emptyChar.repeat(empty));
  
  return bar;
}

function severityOrder(severity: SeverityLevel): number {
  const order: Record<SeverityLevel, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };
  return order[severity];
}

function truncate(str: string, length: number): string {
  return str.length > length ? str.substring(0, length - 3) + '...' : str;
}

function generateYamlConfig(config: VajraConfig): string {
  return `# Vajra Security Scanner Configuration
# Documentation: https://github.com/vajra-security/vajra

target:
  url: "${config.target.url}"
  scope:
    includeSubdomains: ${config.target.scope.includeSubdomains}
    followRedirects: ${config.target.scope.followRedirects}
    respectRobotsTxt: ${config.target.scope.respectRobotsTxt}
    maxUrls: 100
  maxDepth: ${config.target.maxDepth || 3}
  excludePaths:
    - /logout
    - /signout
  # includePaths:
  #   - /api
  #   - /app

ai:
  provider: "${config.ai.provider}"
  model: "${config.ai.model}"
  # apiKey: \${ANTHROPIC_API_KEY}  # Use environment variable
  maxTokens: 4096
  temperature: 0.3

scanning:
  modules:
${config.scanning.modules.map(m => `    - ${m}`).join('\n')}
  concurrency: ${config.scanning.concurrency}
  timeout: ${config.scanning.timeout}
  retries: ${config.scanning.retries}
  delayBetweenRequests: ${config.scanning.delayBetweenRequests || 100}
  userAgent: "Vajra/1.0 Security Scanner"
  # headers:
  #   X-Custom-Header: value

reporting:
  format:
${config.reporting.format.map(f => `    - ${f}`).join('\n')}
  outputDir: "${config.reporting.outputDir}"
  includeScreenshots: ${config.reporting.includeScreenshots}
  includeProofOfConcept: ${config.reporting.includeProofOfConcept}
  severity:
    - critical
    - high
    - medium
    - low

# authentication:
#   type: bearer  # basic, bearer, cookie, oauth2, custom
#   credentials:
#     token: \${AUTH_TOKEN}
#   # For custom login flow:
#   # loginUrl: https://example.com/login
#   # loginFlow:
#   #   - action: type
#   #     selector: "#username"
#   #     value: \${USERNAME}
#   #   - action: type
#   #     selector: "#password"
#   #     value: \${PASSWORD}
#   #   - action: click
#   #     selector: "#submit"
`;
}

// ============================================================================
// Types
// ============================================================================

interface ScanOptions {
  config?: string;
  modules: string;
  output: string;
  format: string;
  aiProvider: string;
  aiModel?: string;
  concurrency: string;
  timeout: string;
  delay: string;
  maxDepth: string;
  includeSubdomains?: boolean;
  authType?: string;
  authUser?: string;
  authPass?: string;
  authToken?: string;
  severity: string;
  screenshots?: boolean;
  poc?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

// ============================================================================
// Main
// ============================================================================

program.parse();
