/**
 * Secure HTTP headers configuration
 * 
 * This file configures security headers for Next.js using the
 * next.config.js headers property.
 */

// Define Content Security Policy directives
const ContentSecurityPolicy = {
  'default-src': ["'self'"],
  'script-src': ["'self'", "'unsafe-inline'", "https://analytics.example.com"],
  'style-src': ["'self'", "'unsafe-inline'"],
  'img-src': ["'self'", "data:", "https://*.example.com"],
  'font-src': ["'self'", "https://fonts.gstatic.com"],
  'connect-src': ["'self'", "https://api.example.com"],
  'frame-src': ["'self'"],
  'object-src': ["'none'"],
  'base-uri': ["'self'"],
  'form-action': ["'self'"],
  'frame-ancestors': ["'self'"],
  'worker-src': ["'self'", "blob:"],
  'manifest-src': ["'self'"],
  'media-src': ["'self'"],
};

// Convert CSP object to string
const cspString = Object.entries(ContentSecurityPolicy)
  .map(([key, values]) => `${key} ${values.join(' ')}`)
  .join('; ');

// Define secure headers
const secureHeaders = [
  {
    key: 'Content-Security-Policy',
    value: cspString,
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  },
  {
    key: 'X-XSS-Protection',
    value: '1; mode=block',
  },
  {
    key: 'X-Frame-Options',
    value: 'SAMEORIGIN',
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin',
  },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
  },
  {
    key: 'X-DNS-Prefetch-Control',
    value: 'on',
  },
];

// Export header configuration for next.config.js
export const secureHeadersConfig = {
  // Apply to all routes
  source: '/(.*)',
  headers: secureHeaders,
};

// Usage in next.config.js:
/*
const { secureHeadersConfig } = require('./config/secure-headers');

module.exports = {
  async headers() {
    return [
      secureHeadersConfig,
      // Add other route-specific headers if needed
    ];
  },
};
*/

// You can also create environment-specific headers:
export const getEnvironmentHeaders = (environment) => {
  if (environment === 'development') {
    // Looser CSP for development
    return {
      ...secureHeadersConfig,
      headers: secureHeadersConfig.headers.map(header => {
        if (header.key === 'Content-Security-Policy') {
          return {
            key: 'Content-Security-Policy',
            value: cspString.replace("'self'", "'self' 'unsafe-eval'")
          };
        }
        return header;
      })
    };
  }
  
  // Use strict headers for production
  return secureHeadersConfig;
};
