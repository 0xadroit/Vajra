/**
 * Vajra - AI-Powered Security Scanner
 * Reconnaissance Agent - Maps the attack surface
 */

import axios, { AxiosInstance } from 'axios';
import * as cheerio from 'cheerio';
import { URL } from 'url';
import {
  Agent,
  AgentContext,
  AgentResult,
  AgentType,
  AgentStatus,
  VajraConfig,
  TargetInfo,
  Endpoint,
  Parameter,
  Technology,
  TechnologyCategory,
  FormInfo,
  FormInput,
  Cookie,
  RobotsInfo,
  PortInfo,
  AIEngine,
  Logger,
  BrowserContext,
} from '../types/index.js';
import { BrowserManager } from '../core/browser-manager.js';

// ============================================================================
// Reconnaissance Agent
// ============================================================================

export class ReconnaissanceAgent implements Agent {
  id = 'recon-agent';
  name = 'Reconnaissance Agent';
  type: AgentType = 'reconnaissance';
  status: AgentStatus = 'idle';
  capabilities = [
    'url-discovery',
    'technology-detection',
    'form-analysis',
    'api-endpoint-discovery',
    'subdomain-enumeration',
    'robots-sitemap-parsing',
  ];
  
  private config: VajraConfig;
  private aiEngine: AIEngine;
  private browserManager: BrowserManager;
  private logger: Logger;
  private httpClient: AxiosInstance;
  private discoveredUrls: Set<string> = new Set();
  private endpoints: Endpoint[] = [];
  private technologies: Technology[] = [];
  private forms: FormInfo[] = [];
  private cookies: Cookie[] = [];
  
  constructor(
    config: VajraConfig,
    aiEngine: AIEngine,
    browserManager: BrowserManager,
    logger: Logger
  ) {
    this.config = config;
    this.aiEngine = aiEngine;
    this.browserManager = browserManager;
    this.logger = logger;
    
    this.httpClient = axios.create({
      timeout: config.scanning.timeout,
      headers: {
        'User-Agent': config.scanning.userAgent || 'Vajra/1.0 Security Scanner',
        ...config.scanning.headers,
      },
      maxRedirects: config.target.scope.followRedirects ? 5 : 0,
      validateStatus: () => true, // Accept all status codes
    });
  }
  
  /**
   * Execute reconnaissance
   */
  async execute(context: AgentContext): Promise<AgentResult> {
    this.status = 'running';
    const startTime = new Date();
    let requestCount = 0;
    let errorCount = 0;
    
    try {
      const targetUrl = new URL(this.config.target.url);
      const domain = targetUrl.hostname;
      
      this.logger.info('Starting reconnaissance', { target: this.config.target.url });
      
      // Step 1: Fetch and analyze robots.txt
      const robots = await this.fetchRobotsTxt(targetUrl.origin);
      requestCount++;
      
      // Step 2: Fetch and parse sitemap
      const sitemapUrls = await this.fetchSitemap(targetUrl.origin, robots?.sitemaps || []);
      requestCount += robots?.sitemaps?.length || 1;
      
      // Step 3: Crawl the target
      await this.crawlTarget(targetUrl.origin, context);
      requestCount += this.discoveredUrls.size;
      
      // Step 4: Detect technologies
      await this.detectTechnologies(targetUrl.origin);
      
      // Step 5: Analyze with AI
      const aiAnalysis = await this.analyzeWithAI();
      
      // Step 6: Discover API endpoints
      await this.discoverApiEndpoints(targetUrl.origin);
      
      const targetInfo: TargetInfo = {
        url: this.config.target.url,
        domain,
        technologies: this.technologies,
        endpoints: this.endpoints,
        parameters: this.extractAllParameters(),
        forms: this.forms,
        cookies: this.cookies,
        headers: {},
        robots: robots || undefined,
        sitemap: sitemapUrls,
      };
      
      this.status = 'completed';
      
      return {
        agentId: this.id,
        agentType: this.type,
        status: 'success',
        data: targetInfo,
        metrics: {
          startTime,
          endTime: new Date(),
          duration: Date.now() - startTime.getTime(),
          requestCount,
          errorCount,
          memoryUsage: process.memoryUsage().heapUsed,
        },
        timestamp: new Date(),
      };
    } catch (error) {
      this.status = 'failed';
      errorCount++;
      
      return {
        agentId: this.id,
        agentType: this.type,
        status: 'failed',
        data: null,
        errors: [{
          code: 'RECON_FAILED',
          message: String(error),
          recoverable: false,
        }],
        metrics: {
          startTime,
          endTime: new Date(),
          duration: Date.now() - startTime.getTime(),
          requestCount,
          errorCount,
          memoryUsage: process.memoryUsage().heapUsed,
        },
        timestamp: new Date(),
      };
    }
  }
  
  /**
   * Fetch and parse robots.txt
   */
  private async fetchRobotsTxt(baseUrl: string): Promise<RobotsInfo | null> {
    try {
      const response = await this.httpClient.get(`${baseUrl}/robots.txt`);
      
      if (response.status !== 200) {
        return null;
      }
      
      const content = response.data as string;
      const lines = content.split('\n');
      
      const robots: RobotsInfo = {
        allowed: [],
        disallowed: [],
        sitemaps: [],
      };
      
      for (const line of lines) {
        const trimmed = line.trim().toLowerCase();
        
        if (trimmed.startsWith('allow:')) {
          robots.allowed.push(line.split(':')[1]?.trim() || '');
        } else if (trimmed.startsWith('disallow:')) {
          robots.disallowed.push(line.split(':')[1]?.trim() || '');
        } else if (trimmed.startsWith('sitemap:')) {
          robots.sitemaps.push(line.substring(8).trim());
        } else if (trimmed.startsWith('crawl-delay:')) {
          robots.crawlDelay = parseInt(line.split(':')[1]?.trim() || '0', 10);
        }
      }
      
      this.logger.info('Parsed robots.txt', {
        allowed: robots.allowed.length,
        disallowed: robots.disallowed.length,
        sitemaps: robots.sitemaps.length,
      });
      
      return robots;
    } catch (error) {
      this.logger.debug('Failed to fetch robots.txt', { error: String(error) });
      return null;
    }
  }
  
  /**
   * Fetch and parse sitemap
   */
  private async fetchSitemap(baseUrl: string, sitemapUrls: string[]): Promise<string[]> {
    const urls: string[] = [];
    const sitemapsToFetch = sitemapUrls.length > 0 
      ? sitemapUrls 
      : [`${baseUrl}/sitemap.xml`];
    
    for (const sitemapUrl of sitemapsToFetch) {
      try {
        const response = await this.httpClient.get(sitemapUrl);
        
        if (response.status === 200) {
          const $ = cheerio.load(response.data, { xmlMode: true });
          
          // Parse sitemap URLs
          $('url > loc').each((_, el) => {
            const url = $(el).text();
            if (url) {
              urls.push(url);
              this.discoveredUrls.add(url);
            }
          });
          
          // Check for sitemap index
          $('sitemap > loc').each((_, el) => {
            const nestedSitemap = $(el).text();
            if (nestedSitemap) {
              sitemapsToFetch.push(nestedSitemap);
            }
          });
        }
      } catch (error) {
        this.logger.debug('Failed to fetch sitemap', { url: sitemapUrl, error: String(error) });
      }
    }
    
    this.logger.info('Parsed sitemaps', { urlCount: urls.length });
    return urls;
  }
  
  /**
   * Crawl the target website
   */
  private async crawlTarget(baseUrl: string, context: AgentContext): Promise<void> {
    const maxUrls = this.config.target.scope.maxUrls || 100;
    const maxDepth = this.config.target.maxDepth || 3;
    const visited = new Set<string>();
    const queue: { url: string; depth: number }[] = [{ url: baseUrl, depth: 0 }];
    
    this.discoveredUrls.add(baseUrl);
    
    while (queue.length > 0 && visited.size < maxUrls) {
      const item = queue.shift();
      if (!item || visited.has(item.url) || item.depth > maxDepth) continue;
      
      visited.add(item.url);
      
      try {
        // Use browser for JavaScript-rendered content
        const page = await this.browserManager.newPage();
        await page.goto(item.url, { waitUntil: 'networkidle' });
        
        const content = await page.content();
        const currentUrl = page.url();
        
        // Extract cookies
        const pageCookies = this.browserManager.getCookies();
        for (const cookie of pageCookies) {
          if (!this.cookies.find(c => c.name === cookie.name)) {
            this.cookies.push(cookie);
          }
        }
        
        // Parse the page
        const $ = cheerio.load(content);
        
        // Extract links
        $('a[href]').each((_, el) => {
          const href = $(el).attr('href');
          if (href) {
            const absoluteUrl = this.resolveUrl(href, currentUrl);
            if (absoluteUrl && this.isInScope(absoluteUrl, baseUrl)) {
              if (!this.discoveredUrls.has(absoluteUrl)) {
                this.discoveredUrls.add(absoluteUrl);
                queue.push({ url: absoluteUrl, depth: item.depth + 1 });
              }
            }
          }
        });
        
        // Extract forms
        $('form').each((_, el) => {
          const form = this.parseForm($, el, currentUrl);
          if (form) {
            this.forms.push(form);
            this.endpoints.push(this.formToEndpoint(form));
          }
        });
        
        // Extract API endpoints from scripts
        $('script').each((_, el) => {
          const scriptContent = $(el).html();
          if (scriptContent) {
            this.extractApiEndpointsFromScript(scriptContent, baseUrl);
          }
        });
        
        await page.close();
        
        // Respect crawl delay
        if (this.config.scanning.delayBetweenRequests) {
          await this.delay(this.config.scanning.delayBetweenRequests);
        }
      } catch (error) {
        this.logger.debug('Failed to crawl URL', { url: item.url, error: String(error) });
      }
    }
    
    this.logger.info('Crawling completed', {
      urlsDiscovered: this.discoveredUrls.size,
      formsFound: this.forms.length,
    });
  }
  
  /**
   * Detect technologies used by the target
   */
  private async detectTechnologies(baseUrl: string): Promise<void> {
    try {
      const response = await this.httpClient.get(baseUrl);
      const headers = response.headers;
      const body = response.data as string;
      
      // Detect from headers
      this.detectFromHeaders(headers);
      
      // Detect from HTML
      this.detectFromHtml(body);
      
      // Detect from cookies
      this.detectFromCookies();
      
      this.logger.info('Technology detection completed', {
        technologiesFound: this.technologies.length,
      });
    } catch (error) {
      this.logger.debug('Technology detection failed', { error: String(error) });
    }
  }
  
  /**
   * Detect technologies from HTTP headers
   */
  private detectFromHeaders(headers: Record<string, unknown>): void {
    const headerPatterns: Record<string, { name: string; category: TechnologyCategory }> = {
      'x-powered-by': { name: 'Unknown', category: 'web-server' },
      'server': { name: 'Unknown', category: 'web-server' },
      'x-aspnet-version': { name: 'ASP.NET', category: 'framework' },
      'x-drupal-cache': { name: 'Drupal', category: 'cms' },
      'x-generator': { name: 'Unknown', category: 'cms' },
    };
    
    for (const [header, info] of Object.entries(headerPatterns)) {
      const value = headers[header];
      if (value) {
        this.addTechnology({
          name: typeof value === 'string' ? value : info.name,
          category: info.category,
          confidence: 90,
        });
      }
    }
    
    // Detect specific technologies
    const server = headers['server'];
    if (typeof server === 'string') {
      if (server.includes('nginx')) {
        this.addTechnology({ name: 'Nginx', category: 'web-server', confidence: 95 });
      } else if (server.includes('Apache')) {
        this.addTechnology({ name: 'Apache', category: 'web-server', confidence: 95 });
      } else if (server.includes('Microsoft-IIS')) {
        this.addTechnology({ name: 'IIS', category: 'web-server', confidence: 95 });
      }
    }
  }
  
  /**
   * Detect technologies from HTML content
   */
  private detectFromHtml(html: string): void {
    const patterns: { pattern: RegExp; name: string; category: TechnologyCategory }[] = [
      { pattern: /react/i, name: 'React', category: 'javascript-library' },
      { pattern: /vue\.js|vuejs/i, name: 'Vue.js', category: 'javascript-library' },
      { pattern: /angular/i, name: 'Angular', category: 'javascript-library' },
      { pattern: /jquery/i, name: 'jQuery', category: 'javascript-library' },
      { pattern: /bootstrap/i, name: 'Bootstrap', category: 'framework' },
      { pattern: /wordpress/i, name: 'WordPress', category: 'cms' },
      { pattern: /drupal/i, name: 'Drupal', category: 'cms' },
      { pattern: /joomla/i, name: 'Joomla', category: 'cms' },
      { pattern: /laravel/i, name: 'Laravel', category: 'framework' },
      { pattern: /django/i, name: 'Django', category: 'framework' },
      { pattern: /express/i, name: 'Express.js', category: 'framework' },
      { pattern: /next\.js|nextjs/i, name: 'Next.js', category: 'framework' },
      { pattern: /cloudflare/i, name: 'Cloudflare', category: 'cdn' },
      { pattern: /google-analytics|gtag/i, name: 'Google Analytics', category: 'analytics' },
    ];
    
    for (const { pattern, name, category } of patterns) {
      if (pattern.test(html)) {
        this.addTechnology({ name, category, confidence: 70 });
      }
    }
  }
  
  /**
   * Detect technologies from cookies
   */
  private detectFromCookies(): void {
    const cookiePatterns: Record<string, { name: string; category: TechnologyCategory }> = {
      'PHPSESSID': { name: 'PHP', category: 'programming-language' },
      'JSESSIONID': { name: 'Java', category: 'programming-language' },
      'ASP.NET_SessionId': { name: 'ASP.NET', category: 'framework' },
      'csrftoken': { name: 'Django', category: 'framework' },
      'laravel_session': { name: 'Laravel', category: 'framework' },
      'wp-settings': { name: 'WordPress', category: 'cms' },
    };
    
    for (const cookie of this.cookies) {
      for (const [pattern, info] of Object.entries(cookiePatterns)) {
        if (cookie.name.includes(pattern)) {
          this.addTechnology({ ...info, confidence: 85 });
        }
      }
    }
  }
  
  /**
   * Add a technology if not already present
   */
  private addTechnology(tech: Omit<Technology, 'version'>): void {
    if (!this.technologies.find(t => t.name === tech.name)) {
      this.technologies.push({ ...tech, version: undefined });
    }
  }
  
  /**
   * Analyze findings with AI
   */
  private async analyzeWithAI(): Promise<string> {
    const prompt = `Analyze the following reconnaissance data and identify potential security concerns:

Target: ${this.config.target.url}
Technologies Detected: ${this.technologies.map(t => t.name).join(', ')}
Forms Found: ${this.forms.length}
Endpoints Discovered: ${this.endpoints.length}
URLs Discovered: ${this.discoveredUrls.size}

Based on this information:
1. What are the potential attack vectors?
2. Which technologies might have known vulnerabilities?
3. What should be prioritized for security testing?
4. Are there any immediate security concerns visible?`;

    const response = await this.aiEngine.analyze(prompt);
    return response.content;
  }
  
  /**
   * Discover API endpoints
   */
  private async discoverApiEndpoints(baseUrl: string): Promise<void> {
    const commonApiPaths = [
      '/api', '/api/v1', '/api/v2', '/api/v3',
      '/rest', '/graphql', '/swagger', '/swagger.json',
      '/openapi', '/openapi.json', '/api-docs',
      '/.well-known', '/health', '/status',
    ];
    
    for (const path of commonApiPaths) {
      try {
        const response = await this.httpClient.get(`${baseUrl}${path}`);
        
        if (response.status < 400) {
          this.endpoints.push({
            url: `${baseUrl}${path}`,
            method: 'GET',
            parameters: [],
            headers: {},
            authenticated: false,
            contentType: response.headers['content-type'] as string,
          });
          
          this.logger.debug('API endpoint discovered', { path });
        }
      } catch {
        // Endpoint doesn't exist or is not accessible
      }
    }
  }
  
  /**
   * Extract API endpoints from JavaScript
   */
  private extractApiEndpointsFromScript(script: string, baseUrl: string): void {
    // Match common API patterns
    const patterns = [
      /['"`](\/api\/[^'"`\s]+)['"`]/g,
      /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
      /axios\.[a-z]+\s*\(\s*['"`]([^'"`]+)['"`]/g,
      /\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]/g,
    ];
    
    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(script)) !== null) {
        const path = match[1];
        if (path && !path.startsWith('http')) {
          const fullUrl = this.resolveUrl(path, baseUrl);
          if (fullUrl && !this.endpoints.find(e => e.url === fullUrl)) {
            this.endpoints.push({
              url: fullUrl,
              method: 'GET',
              parameters: this.extractParametersFromUrl(fullUrl),
              headers: {},
              authenticated: false,
            });
          }
        }
      }
    }
  }
  
  /**
   * Parse a form element
   */
  private parseForm($: cheerio.CheerioAPI, el: cheerio.Element, baseUrl: string): FormInfo | null {
    const $form = $(el);
    const action = $form.attr('action') || '';
    const method = ($form.attr('method') || 'GET').toUpperCase();
    
    const inputs: FormInput[] = [];
    let hasFileUpload = false;
    let hasCsrfToken = false;
    
    $form.find('input, textarea, select').each((_, inputEl) => {
      const $input = $(inputEl);
      const name = $input.attr('name') || '';
      const type = $input.attr('type') || 'text';
      const required = $input.attr('required') !== undefined;
      const value = $input.attr('value') || '';
      const pattern = $input.attr('pattern');
      
      if (type === 'file') hasFileUpload = true;
      if (name.toLowerCase().includes('csrf') || name.toLowerCase().includes('token')) {
        hasCsrfToken = true;
      }
      
      if (name) {
        inputs.push({ name, type, required, value, pattern });
      }
    });
    
    return {
      action: this.resolveUrl(action, baseUrl) || baseUrl,
      method,
      inputs,
      hasFileUpload,
      hasCsrfToken,
    };
  }
  
  /**
   * Convert form to endpoint
   */
  private formToEndpoint(form: FormInfo): Endpoint {
    return {
      url: form.action,
      method: form.method,
      parameters: form.inputs.map(input => ({
        name: input.name,
        type: this.inputTypeToParamType(input.type),
        location: form.method === 'GET' ? 'query' : 'body',
        required: input.required,
      })),
      headers: {},
      authenticated: false,
      contentType: form.hasFileUpload ? 'multipart/form-data' : 'application/x-www-form-urlencoded',
    };
  }
  
  /**
   * Convert HTML input type to parameter type
   */
  private inputTypeToParamType(inputType: string): 'string' | 'number' | 'boolean' | 'file' {
    switch (inputType) {
      case 'number':
      case 'range':
        return 'number';
      case 'checkbox':
        return 'boolean';
      case 'file':
        return 'file';
      default:
        return 'string';
    }
  }
  
  /**
   * Extract parameters from URL
   */
  private extractParametersFromUrl(url: string): Parameter[] {
    try {
      const urlObj = new URL(url);
      const params: Parameter[] = [];
      
      urlObj.searchParams.forEach((value, name) => {
        params.push({
          name,
          type: 'string',
          location: 'query',
          value,
        });
      });
      
      return params;
    } catch {
      return [];
    }
  }
  
  /**
   * Extract all parameters from endpoints
   */
  private extractAllParameters(): Parameter[] {
    const allParams: Parameter[] = [];
    const seen = new Set<string>();
    
    for (const endpoint of this.endpoints) {
      for (const param of endpoint.parameters) {
        const key = `${param.name}-${param.location}`;
        if (!seen.has(key)) {
          seen.add(key);
          allParams.push(param);
        }
      }
    }
    
    return allParams;
  }
  
  /**
   * Resolve relative URL to absolute
   */
  private resolveUrl(href: string, base: string): string | null {
    try {
      return new URL(href, base).href;
    } catch {
      return null;
    }
  }
  
  /**
   * Check if URL is in scope
   */
  private isInScope(url: string, baseUrl: string): boolean {
    try {
      const targetUrl = new URL(url);
      const baseUrlObj = new URL(baseUrl);
      
      // Check if same domain
      if (targetUrl.hostname !== baseUrlObj.hostname) {
        if (!this.config.target.scope.includeSubdomains) {
          return false;
        }
        // Check if subdomain
        if (!targetUrl.hostname.endsWith(`.${baseUrlObj.hostname}`)) {
          return false;
        }
      }
      
      // Check excluded paths
      if (this.config.target.excludePaths) {
        for (const excluded of this.config.target.excludePaths) {
          if (targetUrl.pathname.startsWith(excluded)) {
            return false;
          }
        }
      }
      
      // Check included paths
      if (this.config.target.includePaths && this.config.target.includePaths.length > 0) {
        let included = false;
        for (const includePath of this.config.target.includePaths) {
          if (targetUrl.pathname.startsWith(includePath)) {
            included = true;
            break;
          }
        }
        if (!included) return false;
      }
      
      return true;
    } catch {
      return false;
    }
  }
  
  /**
   * Delay execution
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

export default ReconnaissanceAgent;
