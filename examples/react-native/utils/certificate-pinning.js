/**
 * Certificate Pinning Implementation for React Native
 * 
 * This module provides SSL/TLS certificate pinning to prevent
 * man-in-the-middle attacks by verifying server certificates
 * against a set of known, trusted certificates.
 */

import { Platform } from 'react-native';
import { fetch as sslPinningFetch } from 'react-native-ssl-pinning';
import NetInfo from '@react-native-community/netinfo';

// Configuration for pinned certificates
const PINNED_DOMAINS = {
  'api.example.com': {
    includeSubdomains: true,
    // SHA-256 hashes of the certificate's public key
    // In a real app, you should extract these from your API's certificates
    certs: [
      'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', // Primary certificate hash
      'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=', // Backup certificate hash
    ],
  },
  'auth.example.com': {
    includeSubdomains: false,
    certs: [
      'sha256/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
    ],
  },
};

// Default request timeout in milliseconds
const DEFAULT_TIMEOUT = 30000;

/**
 * Make a network request with certificate pinning
 * 
 * @param {string} url - The URL to fetch
 * @param {Object} options - Request options (method, headers, body)
 * @param {number} timeout - Request timeout in milliseconds
 * @returns {Promise<Object>} - Response data
 */
export const secureFetch = async (url, options = {}, timeout = DEFAULT_TIMEOUT) => {
  try {
    // Check network connectivity before making request
    const networkState = await NetInfo.fetch();
    if (!networkState.isConnected) {
      throw new Error('No internet connection');
    }
    
    // Extract domain from URL for certificate pinning
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    // Check if this domain requires certificate pinning
    const pinnedDomain = findPinnedDomain(domain);
    
    if (!pinnedDomain) {
      console.warn(`Certificate pinning not configured for ${domain}`);
      // Fall back to regular fetch
      const response = await fetch(url, {
        ...options,
        timeout,
      });
      return await processResponse(response);
    }
    
    // Configure options for SSL pinning
    const pinningOptions = {
      method: options.method || 'GET',
      timeoutInterval: timeout,
      headers: options.headers || {},
      body: options.body,
      // SSL Pinning options
      sslPinning: {
        certs: pinnedDomain.certs,
      },
      ...Platform.select({
        android: {
          trustkit: {
            includeSubdomains: pinnedDomain.includeSubdomains,
          },
        },
      }),
    };
    
    // Make request with certificate pinning
    const response = await sslPinningFetch(url, pinningOptions);
    
    return response;
  } catch (error) {
    // Handle certificate validation failures specifically
    if (error.message && (
        error.message.includes('certificate') || 
        error.message.includes('SSL') || 
        error.message.includes('pinning')
    )) {
      console.error('Certificate pinning error - possible security breach:', error);
      throw new Error('Security error: Server certificate validation failed');
    }
    
    // Handle other errors
    console.error('Secure fetch error:', error);
    throw error;
  }
};

/**
 * Find the pinning configuration for a domain
 * @private
 */
const findPinnedDomain = (domain) => {
  // Direct match
  if (PINNED_DOMAINS[domain]) {
    return PINNED_DOMAINS[domain];
  }
  
  // Check for subdomain matches
  for (const [pinnedDomain, config] of Object.entries(PINNED_DOMAINS)) {
    if (config.includeSubdomains && domain.endsWith(`.${pinnedDomain}`)) {
      return config;
    }
  }
  
  return null;
};

/**
 * Process the fetch response
 * @private
 */
const processResponse = async (response) => {
  // Parse response based on content type
  const contentType = response.headers.get('content-type') || '';
  
  if (contentType.includes('application/json')) {
    return await response.json();
  } else if (contentType.includes('text/')) {
    return await response.text();
  } else {
    // Binary data
    return await response.blob();
  }
};

/**
 * Create secure API client with certificate pinning
 * 
 * @param {string} baseURL - Base URL for API requests
 * @param {Object} defaultOptions - Default options for all requests
 * @returns {Object} - API client object
 */
export const createSecureApiClient = (baseURL, defaultOptions = {}) => {
  const client = {
    /**
     * Make a GET request
     * @param {string} path - API path
     * @param {Object} options - Request options
     * @returns {Promise<Object>} - Response data
     */
    get: async (path, options = {}) => {
      const url = `${baseURL}${path}`;
      return secureFetch(url, {
        method: 'GET',
        ...defaultOptions,
        ...options,
        headers: {
          ...defaultOptions.headers,
          ...options.headers,
        },
      });
    },
    
    /**
     * Make a POST request
     * @param {string} path - API path
     * @param {Object} data - Request body data
     * @param {Object} options - Request options
     * @returns {Promise<Object>} - Response data
     */
    post: async (path, data, options = {}) => {
      const url = `${baseURL}${path}`;
      return secureFetch(url, {
        method: 'POST',
        ...defaultOptions,
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...defaultOptions.headers,
          ...options.headers,
        },
        body: JSON.stringify(data),
      });
    },
    
    /**
     * Make a PUT request
     * @param {string} path - API path
     * @param {Object} data - Request body data
     * @param {Object} options - Request options
     * @returns {Promise<Object>} - Response data
     */
    put: async (path, data, options = {}) => {
      const url = `${baseURL}${path}`;
      return secureFetch(url, {
        method: 'PUT',
        ...defaultOptions,
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...defaultOptions.headers,
          ...options.headers,
        },
        body: JSON.stringify(data),
      });
    },
    
    /**
     * Make a DELETE request
     * @param {string} path - API path
     * @param {Object} options - Request options
     * @returns {Promise<Object>} - Response data
     */
    delete: async (path, options = {}) => {
      const url = `${baseURL}${path}`;
      return secureFetch(url, {
        method: 'DELETE',
        ...defaultOptions,
        ...options,
        headers: {
          ...defaultOptions.headers,
          ...options.headers,
        },
      });
    },
  };
  
  return client;
};

// Example usage:
/*
// Create a secure API client
const apiClient = createSecureApiClient('https://api.example.com', {
  headers: {
    'Accept': 'application/json',
    'X-API-Version': '1.0',
  },
  timeout: 10000, // 10 seconds
});

// Use the client
try {
  const userData = await apiClient.get('/users/profile');
  console.log('User data:', userData);
  
  const response = await apiClient.post('/users/settings', {
    theme: 'dark',
    notifications: true,
  });
  console.log('Settings updated:', response);
} catch (error) {
  console.error('API request failed:', error);
}
*/
