/**
 * Vajra - AI-Powered Security Scanner
 * Report Generator - Creates comprehensive security reports
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import {
  VajraConfig,
  TargetInfo,
  Vulnerability,
  Report,
  ReportSummary,
  ReportFormat,
  ScanInfo,
  Recommendation,
  SeverityLevel,
  VulnerabilityType,
  AIEngine,
  Logger,
} from '../types/index.js';
import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// Report Generator
// ============================================================================

export class ReportGenerator {
  private config: VajraConfig;
  private aiEngine: AIEngine;
  private logger: Logger;
  
  constructor(config: VajraConfig, aiEngine: AIEngine, logger: Logger) {
    this.config = config;
    this.aiEngine = aiEngine;
    this.logger = logger;
  }
  
  /**
   * Generate the security report
   */
  async generate(data: ReportData): Promise<Report> {
    this.logger.info('Generating security report');
    
    const summary = this.generateSummary(data.vulnerabilities);
    const recommendations = await this.generateRecommendations(data.vulnerabilities);
    
    const report: Report = {
      id: data.scanId,
      title: `Vajra Security Assessment Report - ${new URL(data.targetInfo.url).hostname}`,
      target: data.targetInfo,
      summary,
      vulnerabilities: data.vulnerabilities,
      scanInfo: {
        startTime: data.startTime,
        endTime: data.endTime,
        duration: data.endTime.getTime() - data.startTime.getTime(),
        modulesRun: data.config.scanning.modules,
        coverage: {
          endpointsTested: data.targetInfo.endpoints.length,
          totalEndpoints: data.targetInfo.endpoints.length,
          parametersTested: data.targetInfo.parameters.length,
          totalParameters: data.targetInfo.parameters.length,
          payloadsUsed: 0,
        },
        configuration: {
          target: data.config.target,
          scanning: data.config.scanning,
        },
      },
      recommendations,
      generatedAt: new Date(),
    };
    
    // Generate reports in all requested formats
    for (const format of this.config.reporting.format) {
      await this.saveReport(report, format);
    }
    
    return report;
  }
  
  /**
   * Generate report summary
   */
  private generateSummary(vulnerabilities: Vulnerability[]): ReportSummary {
    const bySeverity: Record<SeverityLevel, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    
    const byType: Record<string, number> = {};
    
    for (const vuln of vulnerabilities) {
      bySeverity[vuln.severity]++;
      byType[vuln.type] = (byType[vuln.type] || 0) + 1;
    }
    
    const riskScore = this.calculateRiskScore(bySeverity);
    const riskLevel = this.getRiskLevel(riskScore);
    
    return {
      totalVulnerabilities: vulnerabilities.length,
      bySeverity,
      byType: byType as Record<VulnerabilityType, number>,
      riskScore,
      riskLevel,
    };
  }
  
  /**
   * Calculate overall risk score
   */
  private calculateRiskScore(bySeverity: Record<SeverityLevel, number>): number {
    const weights = {
      critical: 40,
      high: 25,
      medium: 10,
      low: 3,
      info: 1,
    };
    
    let score = 0;
    for (const [severity, count] of Object.entries(bySeverity)) {
      score += weights[severity as SeverityLevel] * count;
    }
    
    return Math.min(100, score);
  }
  
  /**
   * Get risk level from score
   */
  private getRiskLevel(score: number): SeverityLevel {
    if (score >= 80) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    if (score >= 10) return 'low';
    return 'info';
  }
  
  /**
   * Generate recommendations using AI
   */
  private async generateRecommendations(vulnerabilities: Vulnerability[]): Promise<Recommendation[]> {
    const recommendations: Recommendation[] = [];
    
    // Group vulnerabilities by type
    const byType = new Map<VulnerabilityType, Vulnerability[]>();
    for (const vuln of vulnerabilities) {
      const existing = byType.get(vuln.type) || [];
      existing.push(vuln);
      byType.set(vuln.type, existing);
    }
    
    let priority = 1;
    
    for (const [type, vulns] of byType) {
      const prompt = `Based on the following ${vulns.length} ${type} vulnerabilities found, provide a concise remediation recommendation:

Vulnerabilities:
${vulns.map(v => `- ${v.title}: ${v.description}`).join('\n')}

Provide:
1. A brief title for the recommendation
2. A description of what needs to be done
3. Estimated effort (low/medium/high)
4. Expected impact (low/medium/high)`;

      try {
        const response = await this.aiEngine.analyze(prompt);
        
        recommendations.push({
          priority: priority++,
          title: `Fix ${type} Vulnerabilities`,
          description: response.content,
          affectedVulnerabilities: vulns.map(v => v.id),
          effort: this.estimateEffort(type),
          impact: this.estimateImpact(vulns[0]?.severity || 'medium'),
        });
      } catch (error) {
        this.logger.debug('Failed to generate AI recommendation', { error: String(error) });
        
        recommendations.push({
          priority: priority++,
          title: `Fix ${type} Vulnerabilities`,
          description: vulns[0]?.remediation || 'Review and fix the identified vulnerabilities.',
          affectedVulnerabilities: vulns.map(v => v.id),
          effort: this.estimateEffort(type),
          impact: this.estimateImpact(vulns[0]?.severity || 'medium'),
        });
      }
    }
    
    return recommendations.sort((a, b) => a.priority - b.priority);
  }
  
  /**
   * Estimate remediation effort
   */
  private estimateEffort(type: VulnerabilityType): 'low' | 'medium' | 'high' {
    const highEffort: VulnerabilityType[] = [
      'sqli-error', 'sqli-blind', 'sqli-time', 'sqli-union',
      'auth-bypass', 'insecure-deserialization',
    ];
    
    const mediumEffort: VulnerabilityType[] = [
      'xss-stored', 'ssrf', 'xxe', 'command-injection',
      'broken-access-control', 'idor',
    ];
    
    if (highEffort.includes(type)) return 'high';
    if (mediumEffort.includes(type)) return 'medium';
    return 'low';
  }
  
  /**
   * Estimate impact of fixing
   */
  private estimateImpact(severity: SeverityLevel): 'low' | 'medium' | 'high' {
    if (severity === 'critical' || severity === 'high') return 'high';
    if (severity === 'medium') return 'medium';
    return 'low';
  }
  
  /**
   * Save report in specified format
   */
  private async saveReport(report: Report, format: ReportFormat): Promise<void> {
    const outputDir = this.config.reporting.outputDir;
    await fs.mkdir(outputDir, { recursive: true });
    
    const filename = `vajra-report-${report.id}`;
    
    switch (format) {
      case 'json':
        await this.saveJsonReport(report, path.join(outputDir, `${filename}.json`));
        break;
      case 'html':
        await this.saveHtmlReport(report, path.join(outputDir, `${filename}.html`));
        break;
      case 'markdown':
        await this.saveMarkdownReport(report, path.join(outputDir, `${filename}.md`));
        break;
      case 'sarif':
        await this.saveSarifReport(report, path.join(outputDir, `${filename}.sarif.json`));
        break;
    }
    
    this.logger.info(`Report saved: ${filename}.${format}`);
  }
  
  /**
   * Save JSON report
   */
  private async saveJsonReport(report: Report, filepath: string): Promise<void> {
    await fs.writeFile(filepath, JSON.stringify(report, null, 2));
  }
  
  /**
   * Save HTML report
   */
  private async saveHtmlReport(report: Report, filepath: string): Promise<void> {
    const html = this.generateHtmlReport(report);
    await fs.writeFile(filepath, html);
  }
  
  /**
   * Generate HTML report content
   */
  private generateHtmlReport(report: Report): string {
    const severityColors = {
      critical: '#dc3545',
      high: '#fd7e14',
      medium: '#ffc107',
      low: '#28a745',
      info: '#17a2b8',
    };
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${report.title}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      line-height: 1.6;
      color: #333;
      background: #f5f5f5;
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 40px 20px;
      text-align: center;
    }
    header h1 { font-size: 2.5em; margin-bottom: 10px; }
    header .subtitle { opacity: 0.9; }
    .summary-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin: 30px 0;
    }
    .card {
      background: white;
      border-radius: 10px;
      padding: 20px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .card h3 { color: #666; font-size: 0.9em; text-transform: uppercase; }
    .card .value { font-size: 2.5em; font-weight: bold; margin: 10px 0; }
    .card.critical .value { color: ${severityColors.critical}; }
    .card.high .value { color: ${severityColors.high}; }
    .card.medium .value { color: ${severityColors.medium}; }
    .card.low .value { color: ${severityColors.low}; }
    .card.info .value { color: ${severityColors.info}; }
    .section { background: white; border-radius: 10px; padding: 30px; margin: 20px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .section h2 { color: #333; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #eee; }
    .vulnerability {
      border: 1px solid #eee;
      border-radius: 8px;
      padding: 20px;
      margin: 15px 0;
      border-left: 4px solid;
    }
    .vulnerability.critical { border-left-color: ${severityColors.critical}; }
    .vulnerability.high { border-left-color: ${severityColors.high}; }
    .vulnerability.medium { border-left-color: ${severityColors.medium}; }
    .vulnerability.low { border-left-color: ${severityColors.low}; }
    .vulnerability.info { border-left-color: ${severityColors.info}; }
    .vulnerability h3 { display: flex; align-items: center; gap: 10px; }
    .severity-badge {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 20px;
      font-size: 0.75em;
      font-weight: bold;
      text-transform: uppercase;
      color: white;
    }
    .severity-badge.critical { background: ${severityColors.critical}; }
    .severity-badge.high { background: ${severityColors.high}; }
    .severity-badge.medium { background: ${severityColors.medium}; }
    .severity-badge.low { background: ${severityColors.low}; }
    .severity-badge.info { background: ${severityColors.info}; }
    .vulnerability-details { margin-top: 15px; }
    .vulnerability-details dt { font-weight: bold; color: #666; margin-top: 10px; }
    .vulnerability-details dd { margin-left: 0; }
    code {
      background: #f4f4f4;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: 'Fira Code', monospace;
    }
    pre {
      background: #2d2d2d;
      color: #f8f8f2;
      padding: 15px;
      border-radius: 8px;
      overflow-x: auto;
      margin: 10px 0;
    }
    .risk-meter {
      height: 20px;
      background: #eee;
      border-radius: 10px;
      overflow: hidden;
      margin: 10px 0;
    }
    .risk-meter-fill {
      height: 100%;
      background: linear-gradient(90deg, #28a745, #ffc107, #dc3545);
      transition: width 0.5s;
    }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
    th { background: #f8f9fa; font-weight: 600; }
    .tech-badge {
      display: inline-block;
      background: #e9ecef;
      padding: 4px 12px;
      border-radius: 20px;
      margin: 3px;
      font-size: 0.85em;
    }
    footer {
      text-align: center;
      padding: 30px;
      color: #666;
    }
    @media print {
      body { background: white; }
      .card, .section { box-shadow: none; border: 1px solid #ddd; }
    }
  </style>
</head>
<body>
  <header>
    <h1>⚡ Vajra Security Report</h1>
    <p class="subtitle">${report.target.domain} | ${report.generatedAt.toISOString()}</p>
  </header>
  
  <div class="container">
    <div class="summary-cards">
      <div class="card">
        <h3>Total Vulnerabilities</h3>
        <div class="value">${report.summary.totalVulnerabilities}</div>
      </div>
      <div class="card critical">
        <h3>Critical</h3>
        <div class="value">${report.summary.bySeverity.critical}</div>
      </div>
      <div class="card high">
        <h3>High</h3>
        <div class="value">${report.summary.bySeverity.high}</div>
      </div>
      <div class="card medium">
        <h3>Medium</h3>
        <div class="value">${report.summary.bySeverity.medium}</div>
      </div>
      <div class="card low">
        <h3>Low</h3>
        <div class="value">${report.summary.bySeverity.low}</div>
      </div>
    </div>
    
    <div class="section">
      <h2>📊 Risk Assessment</h2>
      <p>Overall Risk Score: <strong>${report.summary.riskScore}/100</strong> (${report.summary.riskLevel.toUpperCase()})</p>
      <div class="risk-meter">
        <div class="risk-meter-fill" style="width: ${report.summary.riskScore}%"></div>
      </div>
    </div>
    
    <div class="section">
      <h2>🎯 Target Information</h2>
      <table>
        <tr><th>URL</th><td>${report.target.url}</td></tr>
        <tr><th>Domain</th><td>${report.target.domain}</td></tr>
        <tr><th>Endpoints Discovered</th><td>${report.target.endpoints.length}</td></tr>
        <tr><th>Parameters Found</th><td>${report.target.parameters.length}</td></tr>
        <tr>
          <th>Technologies</th>
          <td>${report.target.technologies.map(t => `<span class="tech-badge">${t.name}</span>`).join('')}</td>
        </tr>
      </table>
    </div>
    
    <div class="section">
      <h2>🔍 Vulnerabilities</h2>
      ${report.vulnerabilities.map(vuln => `
        <div class="vulnerability ${vuln.severity}">
          <h3>
            <span class="severity-badge ${vuln.severity}">${vuln.severity}</span>
            ${vuln.title}
          </h3>
          <dl class="vulnerability-details">
            <dt>Type</dt>
            <dd>${vuln.type}</dd>
            <dt>URL</dt>
            <dd><code>${vuln.url}</code></dd>
            ${vuln.parameter ? `<dt>Parameter</dt><dd><code>${vuln.parameter}</code></dd>` : ''}
            <dt>Description</dt>
            <dd>${vuln.description}</dd>
            ${vuln.payload ? `<dt>Payload</dt><dd><pre>${this.escapeHtml(vuln.payload)}</pre></dd>` : ''}
            <dt>Remediation</dt>
            <dd>${vuln.remediation}</dd>
            ${vuln.cwe?.length ? `<dt>CWE</dt><dd>${vuln.cwe.join(', ')}</dd>` : ''}
            ${vuln.owasp?.length ? `<dt>OWASP</dt><dd>${vuln.owasp.join(', ')}</dd>` : ''}
          </dl>
        </div>
      `).join('')}
    </div>
    
    <div class="section">
      <h2>💡 Recommendations</h2>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Recommendation</th>
            <th>Effort</th>
            <th>Impact</th>
          </tr>
        </thead>
        <tbody>
          ${report.recommendations.map(rec => `
            <tr>
              <td>${rec.priority}</td>
              <td>
                <strong>${rec.title}</strong>
                <p>${rec.description.substring(0, 200)}...</p>
              </td>
              <td>${rec.effort}</td>
              <td>${rec.impact}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
    
    <div class="section">
      <h2>📋 Scan Information</h2>
      <table>
        <tr><th>Scan ID</th><td>${report.id}</td></tr>
        <tr><th>Start Time</th><td>${report.scanInfo.startTime.toISOString()}</td></tr>
        <tr><th>End Time</th><td>${report.scanInfo.endTime.toISOString()}</td></tr>
        <tr><th>Duration</th><td>${Math.round(report.scanInfo.duration / 1000)}s</td></tr>
        <tr><th>Modules Run</th><td>${report.scanInfo.modulesRun.join(', ')}</td></tr>
      </table>
    </div>
  </div>
  
  <footer>
    <p>Generated by <strong>Vajra</strong> - AI-Powered Security Scanner</p>
    <p>Report generated on ${report.generatedAt.toISOString()}</p>
  </footer>
</body>
</html>`;
  }
  
  /**
   * Save Markdown report
   */
  private async saveMarkdownReport(report: Report, filepath: string): Promise<void> {
    const md = this.generateMarkdownReport(report);
    await fs.writeFile(filepath, md);
  }
  
  /**
   * Generate Markdown report content
   */
  private generateMarkdownReport(report: Report): string {
    return `# ⚡ Vajra Security Report

**Target:** ${report.target.url}  
**Generated:** ${report.generatedAt.toISOString()}  
**Scan ID:** ${report.id}

---

## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| Total Vulnerabilities | ${report.summary.totalVulnerabilities} |
| Critical | ${report.summary.bySeverity.critical} |
| High | ${report.summary.bySeverity.high} |
| Medium | ${report.summary.bySeverity.medium} |
| Low | ${report.summary.bySeverity.low} |
| Info | ${report.summary.bySeverity.info} |
| **Risk Score** | **${report.summary.riskScore}/100 (${report.summary.riskLevel.toUpperCase()})** |

---

## 🎯 Target Information

- **URL:** ${report.target.url}
- **Domain:** ${report.target.domain}
- **Endpoints Discovered:** ${report.target.endpoints.length}
- **Parameters Found:** ${report.target.parameters.length}
- **Technologies:** ${report.target.technologies.map(t => t.name).join(', ')}

---

## 🔍 Vulnerabilities

${report.vulnerabilities.map(vuln => `
### ${this.getSeverityEmoji(vuln.severity)} ${vuln.title}

| Property | Value |
|----------|-------|
| Severity | **${vuln.severity.toUpperCase()}** |
| Type | ${vuln.type} |
| URL | \`${vuln.url}\` |
${vuln.parameter ? `| Parameter | \`${vuln.parameter}\` |` : ''}
${vuln.cwe?.length ? `| CWE | ${vuln.cwe.join(', ')} |` : ''}
${vuln.owasp?.length ? `| OWASP | ${vuln.owasp.join(', ')} |` : ''}

**Description:**  
${vuln.description}

${vuln.payload ? `**Payload:**\n\`\`\`\n${vuln.payload}\n\`\`\`` : ''}

**Remediation:**  
${vuln.remediation}

---
`).join('\n')}

## 💡 Recommendations

${report.recommendations.map(rec => `
### ${rec.priority}. ${rec.title}

- **Effort:** ${rec.effort}
- **Impact:** ${rec.impact}
- **Affected Vulnerabilities:** ${rec.affectedVulnerabilities.length}

${rec.description}
`).join('\n')}

---

## 📋 Scan Information

| Property | Value |
|----------|-------|
| Scan ID | ${report.id} |
| Start Time | ${report.scanInfo.startTime.toISOString()} |
| End Time | ${report.scanInfo.endTime.toISOString()} |
| Duration | ${Math.round(report.scanInfo.duration / 1000)}s |
| Modules Run | ${report.scanInfo.modulesRun.join(', ')} |

---

*Generated by **Vajra** - AI-Powered Security Scanner*
`;
  }
  
  /**
   * Save SARIF report (for CI/CD integration)
   */
  private async saveSarifReport(report: Report, filepath: string): Promise<void> {
    const sarif = this.generateSarifReport(report);
    await fs.writeFile(filepath, JSON.stringify(sarif, null, 2));
  }
  
  /**
   * Generate SARIF report content
   */
  private generateSarifReport(report: Report): SarifReport {
    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'Vajra',
            version: '1.0.0',
            informationUri: 'https://github.com/vajra-security/vajra',
            rules: this.generateSarifRules(report.vulnerabilities),
          },
        },
        results: report.vulnerabilities.map(vuln => ({
          ruleId: vuln.type,
          level: this.severityToSarifLevel(vuln.severity),
          message: {
            text: vuln.description,
          },
          locations: [{
            physicalLocation: {
              artifactLocation: {
                uri: vuln.url,
              },
            },
          }],
          fingerprints: {
            vajraId: vuln.id,
          },
        })),
      }],
    };
  }
  
  /**
   * Generate SARIF rules from vulnerabilities
   */
  private generateSarifRules(vulnerabilities: Vulnerability[]): SarifRule[] {
    const ruleMap = new Map<string, SarifRule>();
    
    for (const vuln of vulnerabilities) {
      if (!ruleMap.has(vuln.type)) {
        ruleMap.set(vuln.type, {
          id: vuln.type,
          name: vuln.type.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
          shortDescription: {
            text: vuln.title,
          },
          fullDescription: {
            text: vuln.description,
          },
          help: {
            text: vuln.remediation,
          },
          defaultConfiguration: {
            level: this.severityToSarifLevel(vuln.severity),
          },
        });
      }
    }
    
    return Array.from(ruleMap.values());
  }
  
  /**
   * Convert severity to SARIF level
   */
  private severityToSarifLevel(severity: SeverityLevel): 'error' | 'warning' | 'note' {
    switch (severity) {
      case 'critical':
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      default:
        return 'note';
    }
  }
  
  /**
   * Get emoji for severity
   */
  private getSeverityEmoji(severity: SeverityLevel): string {
    const emojis = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      info: '🔵',
    };
    return emojis[severity];
  }
  
  /**
   * Escape HTML special characters
   */
  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}

// ============================================================================
// Types
// ============================================================================

interface ReportData {
  scanId: string;
  targetInfo: TargetInfo;
  vulnerabilities: Vulnerability[];
  startTime: Date;
  endTime: Date;
  config: VajraConfig;
}

interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  defaultConfiguration: { level: string };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }>;
  fingerprints: Record<string, string>;
}

export default ReportGenerator;
