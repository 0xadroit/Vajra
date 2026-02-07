/**
 * Vajra - AI-Powered Security Scanner
 * Logger Utility
 */

import winston from 'winston';
import * as path from 'path';
import * as fs from 'fs';
import { Logger, LogLevel } from '../types/index.js';

// ============================================================================
// Logger Factory
// ============================================================================

/**
 * Create a logger instance
 */
export function createLogger(outputDir: string, scanId: string): Logger {
  // Ensure log directory exists
  const logDir = path.join(outputDir, 'logs');
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }
  
  const logFile = path.join(logDir, `vajra-${scanId}.log`);
  
  const winstonLogger = winston.createLogger({
    level: 'debug',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    ),
    defaultMeta: { scanId },
    transports: [
      // File transport for all logs
      new winston.transports.File({
        filename: logFile,
        maxsize: 10 * 1024 * 1024, // 10MB
        maxFiles: 5,
      }),
      // Error file transport
      new winston.transports.File({
        filename: path.join(logDir, `vajra-${scanId}-error.log`),
        level: 'error',
      }),
    ],
  });
  
  // Add console transport in development
  if (process.env['NODE_ENV'] !== 'production') {
    winstonLogger.add(
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        ),
        level: 'info',
      })
    );
  }
  
  return {
    debug: (message: string, meta?: Record<string, unknown>) => {
      winstonLogger.debug(message, meta);
    },
    info: (message: string, meta?: Record<string, unknown>) => {
      winstonLogger.info(message, meta);
    },
    warn: (message: string, meta?: Record<string, unknown>) => {
      winstonLogger.warn(message, meta);
    },
    error: (message: string, meta?: Record<string, unknown>) => {
      winstonLogger.error(message, meta);
    },
    verbose: (message: string, meta?: Record<string, unknown>) => {
      winstonLogger.verbose(message, meta);
    },
  };
}

/**
 * Create a silent logger (for testing)
 */
export function createSilentLogger(): Logger {
  return {
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {},
    verbose: () => {},
  };
}

/**
 * Create a console-only logger
 */
export function createConsoleLogger(level: LogLevel = 'info'): Logger {
  const winstonLogger = winston.createLogger({
    level,
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.timestamp({ format: 'HH:mm:ss' }),
      winston.format.printf(({ level, message, timestamp, ...meta }) => {
        const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
        return `${timestamp} ${level}: ${message}${metaStr}`;
      })
    ),
    transports: [new winston.transports.Console()],
  });
  
  return {
    debug: (message: string, meta?: Record<string, unknown>) => {
      winstonLogger.debug(message, meta);
    },
    info: (message: string, meta?: Record<string, unknown>) => {
      winstonLogger.info(message, meta);
    },
    warn: (message: string, meta?: Record<string, unknown>) => {
      winstonLogger.warn(message, meta);
    },
    error: (message: string, meta?: Record<string, unknown>) => {
      winstonLogger.error(message, meta);
    },
    verbose: (message: string, meta?: Record<string, unknown>) => {
      winstonLogger.verbose(message, meta);
    },
  };
}

export default createLogger;
