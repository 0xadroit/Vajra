/**
 * Vajra - AI-Powered Security Scanner
 * Browser Manager - Handles browser automation for dynamic testing
 */

import { chromium, Browser, BrowserContext as PlaywrightContext, Page } from 'playwright';
import {
  BrowserContext,
  BrowserPage,
  Cookie,
  LoginFlowStep,
  NavigationOptions,
  ScreenshotOptions,
  WaitOptions,
} from '../types/index.js';

// ============================================================================
// Browser Manager
// ============================================================================

export class BrowserManager implements BrowserContext {
  private browser: Browser | null = null;
  private context: PlaywrightContext | null = null;
  private pages: Map<string, Page> = new Map();
  private headers: Record<string, string> = {};
  private cookies: Cookie[] = [];
  
  /**
   * Launch the browser
   */
  async launch(): Promise<void> {
    this.browser = await chromium.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--window-size=1920,1080',
      ],
    });
    
    this.context = await this.browser.newContext({
      viewport: { width: 1920, height: 1080 },
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vajra/1.0',
      ignoreHTTPSErrors: true,
    });
    
    // Set default headers
    await this.context.setExtraHTTPHeaders(this.headers);
  }
  
  /**
   * Close the browser
   */
  async close(): Promise<void> {
    for (const page of this.pages.values()) {
      await page.close();
    }
    this.pages.clear();
    
    if (this.context) {
      await this.context.close();
      this.context = null;
    }
    
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }
  
  /**
   * Create a new page
   */
  async newPage(): Promise<BrowserPage> {
    if (!this.context) {
      throw new Error('Browser not launched. Call launch() first.');
    }
    
    const page = await this.context.newPage();
    const pageId = `page-${Date.now()}`;
    this.pages.set(pageId, page);
    
    return new VajraBrowserPage(page, pageId, this.pages);
  }
  
  /**
   * Set cookies
   */
  async setCookies(cookies: Cookie[]): Promise<void> {
    if (!this.context) {
      throw new Error('Browser not launched. Call launch() first.');
    }
    
    this.cookies = cookies;
    
    const playwrightCookies = cookies.map(c => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite as 'Strict' | 'Lax' | 'None' | undefined,
      expires: c.expires ? Math.floor(c.expires.getTime() / 1000) : undefined,
    }));
    
    await this.context.addCookies(playwrightCookies);
  }
  
  /**
   * Set headers
   */
  async setHeaders(headers: Record<string, string>): Promise<void> {
    this.headers = { ...this.headers, ...headers };
    
    if (this.context) {
      await this.context.setExtraHTTPHeaders(this.headers);
    }
  }
  
  /**
   * Set basic authentication
   */
  async setBasicAuth(username: string, password: string): Promise<void> {
    const credentials = Buffer.from(`${username}:${password}`).toString('base64');
    await this.setHeaders({
      'Authorization': `Basic ${credentials}`,
    });
  }
  
  /**
   * Set bearer token
   */
  async setBearerToken(token: string): Promise<void> {
    await this.setHeaders({
      'Authorization': `Bearer ${token}`,
    });
  }
  
  /**
   * Execute login flow
   */
  async executeLoginFlow(loginUrl: string, steps: LoginFlowStep[]): Promise<void> {
    const page = await this.newPage();
    
    try {
      await page.goto(loginUrl, { waitUntil: 'networkidle' });
      
      for (const step of steps) {
        switch (step.action) {
          case 'navigate':
            if (step.value) {
              await page.goto(step.value, { waitUntil: 'networkidle' });
            }
            break;
          case 'click':
            if (step.selector) {
              await page.click(step.selector);
            }
            break;
          case 'type':
            if (step.selector && step.value) {
              await page.type(step.selector, step.value);
            }
            break;
          case 'wait':
            if (step.selector) {
              await page.waitForSelector(step.selector, { timeout: step.timeout });
            } else if (step.timeout) {
              await new Promise(resolve => setTimeout(resolve, step.timeout));
            }
            break;
          case 'submit':
            if (step.selector) {
              await page.click(step.selector);
              await page.waitForNavigation({ timeout: step.timeout });
            }
            break;
        }
      }
      
      // Store cookies from the authenticated session
      if (this.context) {
        const cookies = await this.context.cookies();
        this.cookies = cookies.map(c => ({
          name: c.name,
          value: c.value,
          domain: c.domain,
          path: c.path,
          secure: c.secure,
          httpOnly: c.httpOnly,
          sameSite: c.sameSite as 'Strict' | 'Lax' | 'None' | undefined,
          expires: c.expires ? new Date(c.expires * 1000) : undefined,
        }));
      }
    } finally {
      await page.close();
    }
  }
  
  /**
   * Get the browser context
   */
  getContext(): BrowserContext {
    return this;
  }
  
  /**
   * Get current cookies
   */
  getCookies(): Cookie[] {
    return this.cookies;
  }
  
  /**
   * Get current headers
   */
  getHeaders(): Record<string, string> {
    return this.headers;
  }
  
  /**
   * Check if browser is launched
   */
  isLaunched(): boolean {
    return this.browser !== null;
  }
}

// ============================================================================
// Browser Page Wrapper
// ============================================================================

class VajraBrowserPage implements BrowserPage {
  private page: Page;
  private pageId: string;
  private pagesMap: Map<string, Page>;
  
  constructor(page: Page, pageId: string, pagesMap: Map<string, Page>) {
    this.page = page;
    this.pageId = pageId;
    this.pagesMap = pagesMap;
  }
  
  async goto(url: string, options?: NavigationOptions): Promise<void> {
    await this.page.goto(url, {
      timeout: options?.timeout || 30000,
      waitUntil: options?.waitUntil || 'load',
    });
  }
  
  async click(selector: string): Promise<void> {
    await this.page.click(selector);
  }
  
  async type(selector: string, text: string): Promise<void> {
    await this.page.fill(selector, text);
  }
  
  async evaluate<T>(fn: () => T): Promise<T> {
    return await this.page.evaluate(fn);
  }
  
  async screenshot(options?: ScreenshotOptions): Promise<Buffer> {
    return await this.page.screenshot({
      fullPage: options?.fullPage || false,
      type: options?.type || 'png',
      quality: options?.type === 'jpeg' ? options?.quality : undefined,
    });
  }
  
  async waitForSelector(selector: string, options?: WaitOptions): Promise<void> {
    await this.page.waitForSelector(selector, {
      timeout: options?.timeout || 30000,
      state: options?.visible ? 'visible' : 'attached',
    });
  }
  
  async waitForNavigation(options?: WaitOptions): Promise<void> {
    await this.page.waitForLoadState('load', {
      timeout: options?.timeout || 30000,
    });
  }
  
  async content(): Promise<string> {
    return await this.page.content();
  }
  
  url(): string {
    return this.page.url();
  }
  
  async close(): Promise<void> {
    this.pagesMap.delete(this.pageId);
    await this.page.close();
  }
  
  /**
   * Get the underlying Playwright page
   */
  getPlaywrightPage(): Page {
    return this.page;
  }
  
  /**
   * Execute JavaScript in the page context
   */
  async executeScript<T>(script: string): Promise<T> {
    return await this.page.evaluate(script);
  }
  
  /**
   * Get all links on the page
   */
  async getLinks(): Promise<string[]> {
    return await this.page.evaluate(() => {
      const links: string[] = [];
      document.querySelectorAll('a[href]').forEach(a => {
        const href = a.getAttribute('href');
        if (href) links.push(href);
      });
      return links;
    });
  }
  
  /**
   * Get all forms on the page
   */
  async getForms(): Promise<FormData[]> {
    return await this.page.evaluate(() => {
      const forms: FormData[] = [];
      document.querySelectorAll('form').forEach(form => {
        const inputs: InputData[] = [];
        form.querySelectorAll('input, textarea, select').forEach(input => {
          const el = input as HTMLInputElement;
          inputs.push({
            name: el.name || '',
            type: el.type || 'text',
            value: el.value || '',
            required: el.required || false,
          });
        });
        forms.push({
          action: form.action || '',
          method: form.method || 'GET',
          inputs,
        });
      });
      return forms;
    });
  }
  
  /**
   * Intercept network requests
   */
  async interceptRequests(handler: (request: RequestInfo) => void): Promise<void> {
    this.page.on('request', request => {
      handler({
        url: request.url(),
        method: request.method(),
        headers: request.headers(),
        postData: request.postData() || undefined,
      });
    });
  }
  
  /**
   * Intercept network responses
   */
  async interceptResponses(handler: (response: ResponseInfo) => void): Promise<void> {
    this.page.on('response', async response => {
      let body = '';
      try {
        body = await response.text();
      } catch {
        // Response body may not be available
      }
      
      handler({
        url: response.url(),
        status: response.status(),
        headers: response.headers(),
        body,
      });
    });
  }
}

// ============================================================================
// Types
// ============================================================================

interface FormData {
  action: string;
  method: string;
  inputs: InputData[];
}

interface InputData {
  name: string;
  type: string;
  value: string;
  required: boolean;
}

interface RequestInfo {
  url: string;
  method: string;
  headers: Record<string, string>;
  postData?: string;
}

interface ResponseInfo {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
}

export default BrowserManager;
