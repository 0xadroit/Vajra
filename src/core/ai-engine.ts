/**
 * Vajra - AI-Powered Security Scanner
 * Core AI Engine Module
 */

import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import {
  AIEngine,
  AIConfig,
  AIContext,
  AIResponse,
  AIMessage,
  PayloadContext,
  VulnerabilityType,
  VulnerabilityClassification,
  Evidence,
  Vulnerability,
  SeverityLevel,
} from '../types/index.js';

// ============================================================================
// AI Provider Implementations
// ============================================================================

abstract class BaseAIProvider implements AIEngine {
  abstract provider: string;
  abstract model: string;
  
  abstract analyze(prompt: string, context?: AIContext): Promise<AIResponse>;
  
  async generatePayloads(type: VulnerabilityType, context: PayloadContext): Promise<string[]> {
    const prompt = this.buildPayloadPrompt(type, context);
    const response = await this.analyze(prompt, {
      systemPrompt: PAYLOAD_GENERATION_SYSTEM_PROMPT,
      temperature: 0.7,
    });
    
    return this.parsePayloads(response.content);
  }
  
  async classifyVulnerability(evidence: Evidence): Promise<VulnerabilityClassification> {
    const prompt = this.buildClassificationPrompt(evidence);
    const response = await this.analyze(prompt, {
      systemPrompt: VULNERABILITY_CLASSIFICATION_SYSTEM_PROMPT,
      temperature: 0.2,
    });
    
    return this.parseClassification(response.content);
  }
  
  async suggestRemediation(vulnerability: Vulnerability): Promise<string> {
    const prompt = this.buildRemediationPrompt(vulnerability);
    const response = await this.analyze(prompt, {
      systemPrompt: REMEDIATION_SYSTEM_PROMPT,
      temperature: 0.3,
    });
    
    return response.content;
  }
  
  protected buildPayloadPrompt(type: VulnerabilityType, context: PayloadContext): string {
    return `Generate security testing payloads for ${type} vulnerability testing.

Target Endpoint: ${context.endpoint.url}
HTTP Method: ${context.endpoint.method}
Parameter: ${context.parameter.name}
Parameter Location: ${context.parameter.location}
Parameter Type: ${context.parameter.type}
${context.technology ? `Technology Stack: ${context.technology.name} ${context.technology.version || ''}` : ''}
${context.previousPayloads?.length ? `Previously Tested Payloads: ${context.previousPayloads.join(', ')}` : ''}
${context.successfulPayloads?.length ? `Successful Payloads: ${context.successfulPayloads.join(', ')}` : ''}

Generate 10 unique, creative payloads that:
1. Are specifically crafted for this context
2. Include both common and advanced techniques
3. Consider potential WAF/filter bypasses
4. Are safe for authorized testing

Return ONLY the payloads, one per line, without explanations.`;
  }
  
  protected buildClassificationPrompt(evidence: Evidence): string {
    return `Analyze the following HTTP request/response and classify any potential vulnerability.

REQUEST:
${evidence.request.method} ${evidence.request.url}
Headers: ${JSON.stringify(evidence.request.headers, null, 2)}
${evidence.request.body ? `Body: ${evidence.request.body}` : ''}

RESPONSE:
Status: ${evidence.response.statusCode}
Headers: ${JSON.stringify(evidence.response.headers, null, 2)}
Body (truncated): ${evidence.response.body.substring(0, 2000)}
Response Time: ${evidence.response.responseTime}ms

Analyze this evidence and provide:
1. Vulnerability type (if any)
2. Severity level (critical/high/medium/low/info)
3. Confidence score (0-100)
4. Reasoning for your classification

Format your response as JSON:
{
  "type": "vulnerability-type",
  "severity": "severity-level",
  "confidence": 85,
  "reasoning": "explanation"
}`;
  }
  
  protected buildRemediationPrompt(vulnerability: Vulnerability): string {
    return `Provide detailed remediation guidance for the following vulnerability:

Type: ${vulnerability.type}
Severity: ${vulnerability.severity}
Title: ${vulnerability.title}
Description: ${vulnerability.description}
URL: ${vulnerability.url}
${vulnerability.parameter ? `Parameter: ${vulnerability.parameter}` : ''}
${vulnerability.payload ? `Payload Used: ${vulnerability.payload}` : ''}

Provide:
1. Immediate mitigation steps
2. Long-term remediation recommendations
3. Code examples (if applicable)
4. Best practices to prevent similar issues
5. Testing recommendations to verify the fix`;
  }
  
  protected parsePayloads(content: string): string[] {
    return content
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0 && !line.startsWith('#') && !line.startsWith('//'));
  }
  
  protected parseClassification(content: string): VulnerabilityClassification {
    try {
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          type: parsed.type as VulnerabilityType,
          severity: parsed.severity as SeverityLevel,
          confidence: parsed.confidence,
          reasoning: parsed.reasoning,
        };
      }
    } catch {
      // Fall through to default
    }
    
    return {
      type: 'information-disclosure',
      severity: 'info',
      confidence: 0,
      reasoning: 'Unable to classify vulnerability from evidence',
    };
  }
}

// ============================================================================
// Anthropic Claude Provider
// ============================================================================

class AnthropicProvider extends BaseAIProvider {
  provider = 'anthropic';
  model: string;
  private client: Anthropic;
  private maxTokens: number;
  
  constructor(config: AIConfig) {
    super();
    this.model = config.model || 'claude-sonnet-4-20250514';
    this.maxTokens = config.maxTokens || 4096;
    this.client = new Anthropic({
      apiKey: config.apiKey || process.env['ANTHROPIC_API_KEY'],
    });
  }
  
  async analyze(prompt: string, context?: AIContext): Promise<AIResponse> {
    const messages: Anthropic.MessageParam[] = [];
    
    if (context?.previousMessages) {
      for (const msg of context.previousMessages) {
        if (msg.role !== 'system') {
          messages.push({
            role: msg.role as 'user' | 'assistant',
            content: msg.content,
          });
        }
      }
    }
    
    messages.push({ role: 'user', content: prompt });
    
    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: context?.maxTokens || this.maxTokens,
      system: context?.systemPrompt || VAJRA_SYSTEM_PROMPT,
      messages,
    });
    
    const textContent = response.content.find(c => c.type === 'text');
    const content = textContent && 'text' in textContent ? textContent.text : '';
    
    return {
      content,
      usage: {
        promptTokens: response.usage.input_tokens,
        completionTokens: response.usage.output_tokens,
        totalTokens: response.usage.input_tokens + response.usage.output_tokens,
      },
      model: response.model,
      finishReason: response.stop_reason || 'stop',
    };
  }
}

// ============================================================================
// OpenAI Provider
// ============================================================================

class OpenAIProvider extends BaseAIProvider {
  provider = 'openai';
  model: string;
  private client: OpenAI;
  private maxTokens: number;
  
  constructor(config: AIConfig) {
    super();
    this.model = config.model || 'gpt-4-turbo-preview';
    this.maxTokens = config.maxTokens || 4096;
    this.client = new OpenAI({
      apiKey: config.apiKey || process.env['OPENAI_API_KEY'],
    });
  }
  
  async analyze(prompt: string, context?: AIContext): Promise<AIResponse> {
    const messages: OpenAI.ChatCompletionMessageParam[] = [
      {
        role: 'system',
        content: context?.systemPrompt || VAJRA_SYSTEM_PROMPT,
      },
    ];
    
    if (context?.previousMessages) {
      for (const msg of context.previousMessages) {
        if (msg.role !== 'system') {
          messages.push({
            role: msg.role as 'user' | 'assistant',
            content: msg.content,
          });
        }
      }
    }
    
    messages.push({ role: 'user', content: prompt });
    
    const response = await this.client.chat.completions.create({
      model: this.model,
      max_tokens: context?.maxTokens || this.maxTokens,
      temperature: context?.temperature || 0.3,
      messages,
    });
    
    const choice = response.choices[0];
    
    return {
      content: choice?.message?.content || '',
      usage: {
        promptTokens: response.usage?.prompt_tokens || 0,
        completionTokens: response.usage?.completion_tokens || 0,
        totalTokens: response.usage?.total_tokens || 0,
      },
      model: response.model,
      finishReason: choice?.finish_reason || 'stop',
    };
  }
}

// ============================================================================
// AI Engine Factory
// ============================================================================

export function createAIEngine(config: AIConfig): AIEngine {
  switch (config.provider) {
    case 'anthropic':
      return new AnthropicProvider(config);
    case 'openai':
      return new OpenAIProvider(config);
    case 'local':
      throw new Error('Local AI provider not yet implemented');
    default:
      throw new Error(`Unknown AI provider: ${config.provider}`);
  }
}

// ============================================================================
// System Prompts
// ============================================================================

const VAJRA_SYSTEM_PROMPT = `You are Vajra, an advanced AI-powered security analysis assistant specialized in web application penetration testing and vulnerability assessment.

Your capabilities include:
- Analyzing web application security vulnerabilities
- Generating context-aware security testing payloads
- Classifying and prioritizing discovered vulnerabilities
- Providing detailed remediation guidance
- Understanding complex attack vectors and exploitation techniques

Guidelines:
1. Always operate within authorized testing boundaries
2. Provide accurate, actionable security insights
3. Consider the full context when analyzing vulnerabilities
4. Prioritize findings based on real-world exploitability
5. Include proof-of-concept details when relevant
6. Reference industry standards (OWASP, CWE, CVSS) when applicable

You are thorough, precise, and focused on delivering high-quality security analysis.`;

const PAYLOAD_GENERATION_SYSTEM_PROMPT = `You are a security payload generation expert. Your task is to create effective, context-aware security testing payloads.

Guidelines:
1. Generate payloads that are specifically tailored to the target context
2. Include variations to bypass common security filters
3. Consider encoding and obfuscation techniques
4. Ensure payloads are safe for authorized testing
5. Include both simple and advanced payloads
6. Consider the technology stack when crafting payloads

Output only the payloads, one per line, without explanations or comments.`;

const VULNERABILITY_CLASSIFICATION_SYSTEM_PROMPT = `You are a vulnerability classification expert. Analyze security evidence and accurately classify vulnerabilities.

Guidelines:
1. Carefully examine request/response patterns
2. Look for indicators of successful exploitation
3. Consider false positive scenarios
4. Assign appropriate severity based on impact
5. Provide confidence scores based on evidence strength
6. Reference relevant CWE/OWASP categories

Always respond with valid JSON in the specified format.`;

const REMEDIATION_SYSTEM_PROMPT = `You are a security remediation expert. Provide comprehensive, actionable guidance for fixing vulnerabilities.

Guidelines:
1. Prioritize immediate mitigation steps
2. Provide specific code examples when applicable
3. Reference security best practices
4. Consider the development context
5. Include testing recommendations
6. Address root causes, not just symptoms`;

// ============================================================================
// Exports
// ============================================================================

export {
  AnthropicProvider,
  OpenAIProvider,
  BaseAIProvider,
  VAJRA_SYSTEM_PROMPT,
  PAYLOAD_GENERATION_SYSTEM_PROMPT,
  VULNERABILITY_CLASSIFICATION_SYSTEM_PROMPT,
  REMEDIATION_SYSTEM_PROMPT,
};
