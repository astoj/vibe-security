/**
 * Rate Limiting Utility for Next.js
 * 
 * This module provides rate limiting functionality to protect
 * API routes from abuse, brute force attacks, and DoS.
 */

import { LRUCache } from 'lru-cache';

/**
 * Create a rate limiter with the specified configuration
 * @param {Object} options - Rate limiter options
 * @param {number} options.interval - Time window in milliseconds
 * @param {number} options.maxRequests - Maximum requests allowed in the time window
 * @param {number} options.uniqueTokenPerInterval - Maximum number of unique tokens to track
 * @returns {Object} Rate limiter instance
 */
export function rateLimit(options = {}) {
  const {
    interval = 60 * 1000, // 1 minute in milliseconds
    maxRequests = 10,      // Maximum 10 requests per minute
    uniqueTokenPerInterval = 500, // Maximum 500 unique tokens (users)
  } = options;
  
  // Create LRU cache to store rate limiting data
  const tokenCache = new LRUCache({
    max: uniqueTokenPerInterval,
    ttl: interval,
  });
  
  return {
    /**
     * Check if a token has exceeded the rate limit
     * @param {number} limit - Custom limit for this check (optional)
     * @param {string} token - Unique identifier (e.g., IP, API key, user ID)
     * @returns {Promise<Object>} Result with success, limit, remaining, and reset information
     * @throws {Error} If rate limit is exceeded
     */
    check: async (limit, token) => {
      const maxRequestsForToken = limit || maxRequests;
      
      // Get current count from cache
      const tokenCount = (tokenCache.get(token) || 0) + 1;
      
      // Calculate time to reset
      const currentTime = Date.now();
      const ttl = tokenCache.getTtl(token) || (currentTime + interval);
      const reset = Math.ceil((ttl - currentTime) / 1000); // in seconds
      
      // Store updated count
      tokenCache.set(token, tokenCount);
      
      // Rate limit information
      const rateLimitInfo = {
        limit: maxRequestsForToken,
        remaining: Math.max(0, maxRequestsForToken - tokenCount),
        reset,
      };
      
      // Check if rate limit exceeded
      if (tokenCount > maxRequestsForToken) {
        const error = new Error('Rate limit exceeded');
        error.status = 429;
        error.rateLimit = rateLimitInfo;
        throw error;
      }
      
      return {
        success: true,
        ...rateLimitInfo,
      };
    },
    
    /**
     * Create a middleware function for Next.js API routes
     * @param {Object} options - Middleware options
     * @param {function} options.keyGenerator - Function to generate token from request
     * @param {number} options.limit - Custom limit for this middleware (optional)
     * @param {boolean} options.headers - Whether to include rate limit headers in response
     * @returns {function} Middleware function
     */
    middleware: (options = {}) => {
      const {
        keyGenerator = (req) => req.headers['x-forwarded-for'] || req.ip || 'anonymous',
        limit = maxRequests,
        headers = true,
      } = options;
      
      return async (req, res, next) => {
        try {
          // Generate token for the request
          const token = await Promise.resolve(
            typeof keyGenerator === 'function' ? keyGenerator(req) : keyGenerator
          );
          
          // Check rate limit
          const result = await this.check(limit, token);
          
          // Set rate limit headers if enabled
          if (headers) {
            res.setHeader('X-RateLimit-Limit', result.limit);
            res.setHeader('X-RateLimit-Remaining', result.remaining);
            res.setHeader('X-RateLimit-Reset', result.reset);
          }
          
          // Continue to the next middleware/handler
          if (typeof next === 'function') {
            next();
          }
        } catch (error) {
          // Handle rate limit exceeded
          if (error.status === 429) {
            // Set rate limit headers if enabled
            if (headers && error.rateLimit) {
              res.setHeader('X-RateLimit-Limit', error.rateLimit.limit);
              res.setHeader('X-RateLimit-Remaining', 0);
              res.setHeader('X-RateLimit-Reset', error.rateLimit.reset);
              res.setHeader('Retry-After', error.rateLimit.reset);
            }
            
            // Send 429 Too Many Requests response
            res.status(429).json({
              error: 'Too Many Requests',
              message: 'Rate limit exceeded. Please try again later.',
              retryAfter: error.rateLimit?.reset || 60,
            });
          } else {
            // Handle other errors
            console.error('Rate limit error:', error);
            res.status(500).json({
              error: 'Internal Server Error',
              message: 'An unexpected error occurred',
            });
          }
        }
      };
    },
    
    /**
     * Higher-order function to wrap an API route handler with rate limiting
     * @param {function} handler - API route handler function
     * @param {Object} options - Rate limit options
     * @returns {function} Wrapped handler function with rate limiting
     */
    withRateLimit: (handler, options = {}) => {
      return async (req, res) => {
        try {
          // Default token generator uses IP address
          const {
            keyGenerator = (req) => req.headers['x-forwarded-for'] || req.ip || 'anonymous',
            limit = maxRequests,
            headers = true,
          } = options;
          
          // Generate token
          const token = await Promise.resolve(
            typeof keyGenerator === 'function' ? keyGenerator(req) : keyGenerator
          );
          
          // Check rate limit
          const result = await this.check(limit, token);
          
          // Set rate limit headers if enabled
          if (headers) {
            res.setHeader('X-RateLimit-Limit', result.limit);
            res.setHeader('X-RateLimit-Remaining', result.remaining);
            res.setHeader('X-RateLimit-Reset', result.reset);
          }
          
          // Call the original handler
          return handler(req, res);
        } catch (error) {
          // Handle rate limit exceeded
          if (error.status === 429) {
            // Set rate limit headers if enabled
            if (headers && error.rateLimit) {
              res.setHeader('X-RateLimit-Limit', error.rateLimit.limit);
              res.setHeader('X-RateLimit-Remaining', 0);
              res.setHeader('X-RateLimit-Reset', error.rateLimit.reset);
              res.setHeader('Retry-After', error.rateLimit.reset);
            }
            
            // Send 429 Too Many Requests response
            return res.status(429).json({
              error: 'Too Many Requests',
              message: 'Rate limit exceeded. Please try again later.',
              retryAfter: error.rateLimit?.reset || 60,
            });
          }
          
          // Handle other errors
          console.error('Rate limit error:', error);
          return res.status(500).json({
            error: 'Internal Server Error',
            message: 'An unexpected error occurred',
          });
        }
      };
    },
    
    /**
     * Get current rate limit status for a token
     * @param {string} token - Unique identifier (e.g., IP, API key, user ID)
     * @param {number} limit - Custom limit for this check (optional)
     * @returns {Object} Rate limit information
     */
    getStatus: (token, limit = maxRequests) => {
      const tokenCount = tokenCache.get(token) || 0;
      const currentTime = Date.now();
      const ttl = tokenCache.getTtl(token) || (currentTime + interval);
      const reset = Math.ceil((ttl - currentTime) / 1000); // in seconds
      
      return {
        limit,
        remaining: Math.max(0, limit - tokenCount),
        reset,
        exceeded: tokenCount >= limit,
      };
    },
    
    /**
     * Reset rate limit for a specific token
     * @param {string} token - Unique identifier to reset
     * @returns {boolean} True if token was in cache and reset
     */
    reset: (token) => {
      const exists = tokenCache.has(token);
      tokenCache.delete(token);
      return exists;
    },
    
    /**
     * Get instance of the token cache for advanced usage
     * @returns {LRUCache} Token cache instance
     */
    getCache: () => tokenCache,
  };
}

// Create default rate limiter instances for common use cases
export const globalLimiter = rateLimit({
  interval: 60 * 1000, // 1 minute
  maxRequests: 60,      // 60 requests per minute (reasonable for general API)
});

export const authLimiter = rateLimit({
  interval: 60 * 1000, // 1 minute
  maxRequests: 5,       // 5 login attempts per minute
});

export const sensitiveApiLimiter = rateLimit({
  interval: 60 * 1000, // 1 minute
  maxRequests: 10,      // 10 requests per minute for sensitive operations
});

// Example usage:

/*
// In app/api/login/route.js
import { authLimiter } from '@/utils/rate-limit';

export async function POST(request) {
  try {
    // Get client IP (or user identifier)
    const forwarded = request.headers.get('x-forwarded-for');
    const ip = forwarded ? forwarded.split(',')[0] : 'anonymous';
    
    // Check rate limit (5 attempts per minute)
    await authLimiter.check(5, ip);
    
    // Process login request
    const body = await request.json();
    // Authenticate user...
    
    return Response.json({ success: true });
  } catch (error) {
    if (error.status === 429) {
      // Too many login attempts
      return Response.json(
        { 
          error: 'Too many login attempts', 
          message: 'Please try again later',
          retryAfter: error.rateLimit?.reset || 60 
        },
        { 
          status: 429,
          headers: {
            'Retry-After': error.rateLimit?.reset || 60,
          }
        }
      );
    }
    
    // Handle other errors
    return Response.json(
      { error: 'Authentication failed' },
      { status: 401 }
    );
  }
}

// In app/api/users/route.js with options
import { rateLimit } from '@/utils/rate-limit';

// Create specialized limiter with token based on user ID
const userApiLimiter = rateLimit({
  interval: 60 * 1000, // 1 minute
  maxRequests: 20,      // 20 requests per minute
});

// Handler with rate limiting
export async function GET(request) {
  try {
    const session = await getServerSession();
    
    if (!session?.user) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    // Rate limit by user ID instead of IP
    await userApiLimiter.check(20, session.user.id);
    
    // Get users from database
    const users = await db.users.findMany();
    
    return Response.json({ users });
  } catch (error) {
    if (error.status === 429) {
      return Response.json(
        { error: 'Rate limit exceeded' },
        { status: 429 }
      );
    }
    
    return Response.json(
      { error: 'Failed to fetch users' },
      { status: 500 }
    );
  }
}
*/
