/**
 * CSRF Protection for Next.js
 * 
 * This module provides Cross-Site Request Forgery (CSRF) protection utilities
 * using the iron-session and next-csrf libraries.
 */

import { withIronSessionApiRoute, withIronSessionSsr } from 'iron-session/next';
import { getToken, csrf } from 'next-csrf';

// Configuration for iron-session (used for storing CSRF token)
const sessionOptions = {
  password: process.env.SESSION_SECRET || 'complex-password-at-least-32-characters-long',
  cookieName: 'next-csrf-session',
  cookieOptions: {
    // Set secure: true in production
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    // Set domain in production
    ...(process.env.NODE_ENV === 'production' ? { domain: '.example.com' } : {}),
  },
};

// Configure CSRF protection
export const csrfConfig = {
  // Generate a unique token value
  getToken,
  // Cookie settings for CSRF token
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
  },
  // Additional options
  tokenKey: 'csrf-token', // The form input field name
  cookieName: 'next-csrf', // The cookie name
  expiresIn: 3600, // 1 hour in seconds
  salt: 'unique-salt-string', // A unique string to secure your tokens
};

// Initialize CSRF middleware
const csrfMiddleware = csrf(csrfConfig);

/**
 * Protect an API route with CSRF
 * @param {Function} handler - Next.js API route handler
 * @returns {Function} Protected API route handler
 */
export function withCsrfApiRoute(handler) {
  // First apply Iron Session to have session available
  const withSession = withIronSessionApiRoute(handler, sessionOptions);
  
  // Then wrap with CSRF protection
  return async (req, res) => {
    try {
      // Apply CSRF protection
      await csrfMiddleware(req, res);
      // If CSRF validation passes, call the handler
      return await withSession(req, res);
    } catch (error) {
      // If CSRF validation fails, return 403 Forbidden
      if (error.code === 'CSRF_TOKEN_INVALID') {
        return res.status(403).json({
          error: 'Invalid CSRF token',
          message: 'CSRF validation failed. Please try again.',
        });
      }
      
      // For other errors, pass to the original handler or return 500
      console.error('CSRF error:', error);
      return res.status(500).json({
        error: 'Internal server error',
        message: 'An unexpected error occurred',
      });
    }
  };
}

/**
 * Protect a server-side rendered page with CSRF
 * @param {Function} handler - Next.js getServerSideProps function 
 * @returns {Function} Protected getServerSideProps function with CSRF token
 */
export function withCsrfSsr(handler) {
  // First apply Iron Session to have session available
  const withSession = withIronSessionSsr(handler, sessionOptions);
  
  // Then generate and add CSRF token
  return async (context) => {
    try {
      // Generate CSRF token (will be set as cookie automatically)
      const csrfToken = await getToken(context.req, context.res);
      
      // Get server-side props
      const result = await withSession(context);
      
      // Inject CSRF token into props
      return {
        ...result,
        props: {
          ...result.props,
          csrfToken,
        },
      };
    } catch (error) {
      console.error('CSRF SSR error:', error);
      
      // Return error page or redirect to error page
      return {
        redirect: {
          destination: '/error',
          permanent: false,
        },
      };
    }
  };
}

/**
 * Hook to extract CSRF token from meta tag in client component
 * @returns {string|null} CSRF token
 */
export function useCsrfToken() {
  if (typeof window === 'undefined') {
    return null;
  }
  
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  return csrfMeta ? csrfMeta.getAttribute('content') : null;
}

/**
 * Component to inject CSRF token into forms
 */
export function CsrfToken({ token }) {
  if (!token) {
    return null;
  }
  
  return (
    <input 
      type="hidden" 
      name={csrfConfig.tokenKey} 
      value={token} 
    />
  );
}

/**
 * Create a fetch function with CSRF token automatically included
 * @param {string} csrfToken - CSRF token from server
 * @returns {Function} Enhanced fetch function
 */
export function createCsrfFetch(csrfToken) {
  return async (url, options = {}) => {
    const headers = {
      ...options.headers,
      // Add CSRF token to header
      'X-CSRF-Token': csrfToken,
    };
    
    // For form submissions, ensure CSRF token is included in body
    if (
      options.body instanceof FormData &&
      !options.body.has(csrfConfig.tokenKey)
    ) {
      options.body.append(csrfConfig.tokenKey, csrfToken);
    }
    
    // For JSON requests, include token in body if it's an object
    if (
      options.headers?.['Content-Type'] === 'application/json' &&
      typeof options.body === 'string'
    ) {
      try {
        const bodyObj = JSON.parse(options.body);
        if (typeof bodyObj === 'object' && bodyObj !== null) {
          options.body = JSON.stringify({
            ...bodyObj,
            [csrfConfig.tokenKey]: csrfToken,
          });
        }
      } catch (e) {
        // If not valid JSON, leave body as is
      }
    }
    
    return fetch(url, {
      ...options,
      headers,
    });
  };
}

// Example usage:

/*
// In app/api/contact-form/route.js
import { withCsrfApiRoute } from '@/utils/csrf-protection';

async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  
  // Process form submission (CSRF already validated)
  const { name, email, message } = req.body;
  
  // Save to database, send email, etc.
  
  return res.status(200).json({ success: true });
}

export default withCsrfApiRoute(handler);

// In app/page.js or any server component
import { withCsrfSsr, CsrfToken } from '@/utils/csrf-protection';

function ContactPage({ csrfToken }) {
  return (
    <form action="/api/contact-form" method="post">
      <CsrfToken token={csrfToken} />
      <input type="text" name="name" placeholder="Your name" />
      <input type="email" name="email" placeholder="Your email" />
      <textarea name="message" placeholder="Your message"></textarea>
      <button type="submit">Send</button>
    </form>
  );
}

export const getServerSideProps = withCsrfSsr(async (context) => {
  return {
    props: {
      // Additional props can be included here
    },
  };
});

// In a client component
import { useCsrfToken, createCsrfFetch } from '@/utils/csrf-protection';

function ContactForm() {
  const csrfToken = useCsrfToken();
  const csrfFetch = createCsrfFetch(csrfToken);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    
    try {
      const response = await csrfFetch('/api/contact-form', {
        method: 'POST',
        body: formData,
      });
      
      if (response.ok) {
        // Success!
      } else {
        // Handle error
      }
    } catch (error) {
      console.error('Form submission error:', error);
    }
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input type="hidden" name="csrf-token" value={csrfToken} />
      {/* Form fields */}
    </form>
  );
}
*/
