/**
 * Vajra - AI-Powered Security Scanner
 * Configuration Loader
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import YAML from 'yaml';
import { z } from 'zod';
import {
  VajraConfig,
  ScanModule,
  ReportFormat,
  SeverityLevel,
} from '../types/index.js';

// ============================================================================
// Configuration Schema
// ============================================================================

const ScopeConfigSchema = z.object({
  includeSubdomains: z.boolean().default(false),
  followRedirects: z.boolean().default(true),
  respectRobotsTxt: z.boolean().default(true),
  maxUrls: z.number().optional(),
});

const TargetConfigSchema = z.object({
  url: z.string().url(),
  scope: ScopeConfigSchema,
  excludePaths: z.array(z.string()).optional(),
  includePaths: z.array(z.string()).optional(),
  maxDepth: z.number().default(3),
});

const AIConfigSchema = z.object({
  provider: z.enum(['anthropic', 'openai', 'local']),
  model: z.string(),
  apiKey: z.string().optional(),
  maxTokens: z.number().default(4096),
  temperature: z.number().default(0.3),
  timeout: z.number().optional(),
});

const ScanModuleSchema = z.enum([
  'reconnaissance',
  'xss',
  'sqli',
  'ssrf',
  'auth-bypass',
  'idor',
  'lfi',
  'rfi',
  'command-injection',
  'xxe',
  'csrf',
  'cors',
  'security-headers',
  'ssl-tls',
  'information-disclosure',
]);

const ScanConfigSchema = z.object({
  modules: z.array(ScanModuleSchema),
  concurrency: z.number().default(5),
  timeout: z.number().default(30000),
  retries: z.number().default(3),
  delayBetweenRequests: z.number().optional(),
  userAgent: z.string().optional(),
  headers: z.record(z.string()).optional(),
});

const ReportFormatSchema = z.enum(['html', 'json', 'markdown', 'pdf', 'sarif']);
const SeverityLevelSchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);

const ReportConfigSchema = z.object({
  format: z.array(ReportFormatSchema),
  outputDir: z.string().default('./vajra-reports'),
  includeScreenshots: z.boolean().default(false),
  includeProofOfConcept: z.boolean().default(true),
  severity: z.array(SeverityLevelSchema).default(['critical', 'high', 'medium', 'low']),
});

const LoginFlowStepSchema = z.object({
  action: z.enum(['navigate', 'click', 'type', 'wait', 'submit']),
  selector: z.string().optional(),
  value: z.string().optional(),
  timeout: z.number().optional(),
});

const AuthConfigSchema = z.object({
  type: z.enum(['basic', 'bearer', 'cookie', 'oauth2', 'custom']),
  credentials: z.record(z.string()),
  loginUrl: z.string().optional(),
  loginFlow: z.array(LoginFlowStepSchema).optional(),
});

const VajraConfigSchema = z.object({
  target: TargetConfigSchema,
  ai: AIConfigSchema,
  scanning: ScanConfigSchema,
  reporting: ReportConfigSchema,
  authentication: AuthConfigSchema.optional(),
});

// ============================================================================
// Configuration Loader
// ============================================================================

/**
 * Load configuration from a file
 */
export async function loadConfig(configPath: string): Promise<VajraConfig> {
  const absolutePath = path.resolve(configPath);
  const content = await fs.readFile(absolutePath, 'utf-8');
  
  let rawConfig: unknown;
  
  if (configPath.endsWith('.yaml') || configPath.endsWith('.yml')) {
    rawConfig = YAML.parse(content);
  } else if (configPath.endsWith('.json')) {
    rawConfig = JSON.parse(content);
  } else {
    throw new Error(`Unsupported configuration file format: ${configPath}`);
  }
  
  // Expand environment variables
  const expandedConfig = expandEnvVars(rawConfig);
  
  // Validate configuration
  const result = VajraConfigSchema.safeParse(expandedConfig);
  
  if (!result.success) {
    const errors = result.error.errors.map(e => `  - ${e.path.join('.')}: ${e.message}`);
    throw new Error(`Invalid configuration:\n${errors.join('\n')}`);
  }
  
  return result.data as VajraConfig;
}

/**
 * Create a default configuration
 */
export function createDefaultConfig(targetUrl: string): VajraConfig {
  return {
    target: {
      url: targetUrl,
      scope: {
        includeSubdomains: false,
        followRedirects: true,
        respectRobotsTxt: true,
      },
      maxDepth: 3,
    },
    ai: {
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      maxTokens: 4096,
      temperature: 0.3,
    },
    scanning: {
      modules: [
        'reconnaissance',
        'xss',
        'sqli',
        'ssrf',
        'auth-bypass',
        'idor',
        'lfi',
        'command-injection',
        'cors',
        'security-headers',
      ],
      concurrency: 5,
      timeout: 30000,
      retries: 3,
      delayBetweenRequests: 100,
    },
    reporting: {
      format: ['html', 'json'],
      outputDir: './vajra-reports',
      includeScreenshots: false,
      includeProofOfConcept: true,
      severity: ['critical', 'high', 'medium', 'low'],
    },
  };
}

/**
 * Expand environment variables in configuration
 */
function expandEnvVars(obj: unknown): unknown {
  if (typeof obj === 'string') {
    // Match ${VAR_NAME} or $VAR_NAME patterns
    return obj.replace(/\$\{([^}]+)\}|\$([A-Z_][A-Z0-9_]*)/gi, (match, p1, p2) => {
      const varName = p1 || p2;
      return process.env[varName] || match;
    });
  }
  
  if (Array.isArray(obj)) {
    return obj.map(expandEnvVars);
  }
  
  if (obj !== null && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = expandEnvVars(value);
    }
    return result;
  }
  
  return obj;
}

/**
 * Validate a configuration object
 */
export function validateConfig(config: unknown): { valid: boolean; errors: string[] } {
  const result = VajraConfigSchema.safeParse(config);
  
  if (result.success) {
    return { valid: true, errors: [] };
  }
  
  return {
    valid: false,
    errors: result.error.errors.map(e => `${e.path.join('.')}: ${e.message}`),
  };
}

/**
 * Merge configurations (base with overrides)
 */
export function mergeConfigs(base: VajraConfig, overrides: Partial<VajraConfig>): VajraConfig {
  return {
    target: {
      ...base.target,
      ...overrides.target,
      scope: {
        ...base.target.scope,
        ...overrides.target?.scope,
      },
    },
    ai: {
      ...base.ai,
      ...overrides.ai,
    },
    scanning: {
      ...base.scanning,
      ...overrides.scanning,
    },
    reporting: {
      ...base.reporting,
      ...overrides.reporting,
    },
    authentication: overrides.authentication || base.authentication,
  };
}

export default loadConfig;
