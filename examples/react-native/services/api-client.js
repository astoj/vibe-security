/**
 * Secure API Client for React Native
 * 
 * This module provides a secure API client with:
 * - Request/response interceptors
 * - Token authentication
 * - Token refresh
 * - Request queueing
 * - Certificate pinning
 * - Error handling
 * - Offline detection
 */

import { Platform } from 'react-native';
import axios from 'axios';
import NetInfo from '@react-native-community/netinfo';
import { secureFetch } from '../utils/certificate-pinning';
import { getInternetCredentials, setInternetCredentials } from 'react-native-keychain';

// API configuration
const API_CONFIG = {
  baseURL: 'https://api.example.com',
  timeout: 30000,
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
  },
};

// Request queue for handling offline scenarios
let requestQueue = [];
let isRefreshingToken = false;
let tokenRefreshPromise = null;
let refreshSubscribers = [];

/**
 * Subscribe to token refresh
 * @param {Function} callback - Function to call when token is refreshed
 */
function subscribeTokenRefresh(callback) {
  refreshSubscribers.push(callback);
}

/**
 * Notify all subscribers that token has been refreshed
 * @param {string} token - New access token
 */
function onTokenRefreshed(token) {
  refreshSubscribers.forEach(callback => callback(token));
  refreshSubscribers = [];
}

/**
 * Create a secure API client instance
 * @param {Object} authProvider - Authentication provider with token management
 * @returns {Object} API client instance
 */
export const createApiClient = (authProvider) => {
  // Create Axios instance
  const apiClient = axios.create(API_CONFIG);
  
  // Request interceptor
  apiClient.interceptors.request.use(
    async (config) => {
      try {
        // Check for network connectivity
        const networkState = await NetInfo.fetch();
        if (!networkState.isConnected) {
          // Queue request for later if offline
          return new Promise((resolve, reject) => {
            requestQueue.push({
              config,
              resolve,
              reject,
            });
          });
        }
        
        // Add authentication token if available
        const token = await authProvider.getAccessToken();
        
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        
        // Prevent storing sensitive API responses in the device's cache
        config.headers['Cache-Control'] = 'no-store';
        
        // Add device info for analytics and security monitoring
        config.headers['X-Device-Type'] = Platform.OS;
        config.headers['X-Device-OS'] = Platform.Version;
        config.headers['X-App-Version'] = process.env.APP_VERSION || '1.0.0';
        
        return config;
      } catch (error) {
        console.error('API request interceptor error:', error);
        return Promise.reject(error);
      }
    },
    (error) => {
      return Promise.reject(error);
    }
  );
  
  // Response interceptor
  apiClient.interceptors.response.use(
    (response) => {
      // Extract security headers if present
      const securityHeaders = {
        requiresUpdate: response.headers['x-requires-update'],
        securityAlert: response.headers['x-security-alert'],
      };
      
      // Handle required app updates
      if (securityHeaders.requiresUpdate === 'true') {
        // Notify user about required update
        // This could trigger an app update flow
        console.warn('App update required for security reasons');
      }
      
      // Handle security alerts
      if (securityHeaders.securityAlert) {
        console.warn('Security alert:', securityHeaders.securityAlert);
        // Log security alert for monitoring
      }
      
      return response;
    },
    async (error) => {
      const originalRequest = error.config;
      
      // Handle offline scenarios
      if (error.message === 'Network Error') {
        const networkState = await NetInfo.fetch();
        if (!networkState.isConnected) {
          // Queue the failed request
          return new Promise((resolve, reject) => {
            requestQueue.push({
              config: originalRequest,
              resolve,
              reject,
            });
          });
        }
      }
      
      // Handle token expiration (401 Unauthorized)
      if (
        error.response?.status === 401 &&
        !originalRequest._retry &&
        authProvider
      ) {
        // If token refresh is not already in progress
        if (!isRefreshingToken) {
          isRefreshingToken = true;
          tokenRefreshPromise = authProvider.refreshToken()
            .then((success) => {
              isRefreshingToken = false;
              if (success) {
                return authProvider.getAccessToken();
              }
              throw new Error('Token refresh failed');
            })
            .then((newToken) => {
              onTokenRefreshed(newToken);
              return newToken;
            })
            .catch((err) => {
              refreshSubscribers = [];
              // Force logout on refresh failure
              authProvider.logout();
              throw err;
            });
        }
        
        // Wait for the token refresh to complete
        return new Promise((resolve, reject) => {
          subscribeTokenRefresh((newToken) => {
            // Replace the expired token
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            originalRequest._retry = true;
            resolve(apiClient(originalRequest));
          });
          
          tokenRefreshPromise.catch(reject);
        });
      }
      
      // Handle server errors with useful messages
      if (error.response) {
        // The request was made and the server responded with a non-2xx status code
        const statusCode = error.response.status;
        const data = error.response.data;
        
        switch (statusCode) {
          case 400:
            console.warn('Bad Request:', data);
            break;
          case 403:
            console.warn('Forbidden:', data);
            break;
          case 404:
            console.warn('Not Found:', data);
            break;
          case 429:
            console.warn('Too Many Requests:', data);
            // Handle rate limiting with exponential backoff
            const retryAfter = error.response.headers['retry-after'] || 5;
            return new Promise((resolve) => {
              setTimeout(() => {
                resolve(apiClient(originalRequest));
              }, retryAfter * 1000);
            });
          case 500:
          case 502:
          case 503:
          case 504:
            console.error('Server Error:', statusCode, data);
            break;
        }
      } else if (error.request) {
        // The request was made but no response was received
        console.error('No response received:', error.request);
      } else {
        // Something happened in setting up the request
        console.error('Request error:', error.message);
      }
      
      return Promise.reject(error);
    }
  );
  
  // Network change listener for processing offline queue
  NetInfo.addEventListener((state) => {
    if (state.isConnected && requestQueue.length > 0) {
      // Process queued requests when back online
      const queue = [...requestQueue];
      requestQueue = [];
      
      queue.forEach(async ({ config, resolve, reject }) => {
        try {
          // Add fresh token to request
          const token = await authProvider.getAccessToken();
          if (token) {
            config.headers.Authorization = `Bearer ${token}`;
          }
          
          // Retry the request
          const response = await apiClient(config);
          resolve(response);
        } catch (error) {
          reject(error);
        }
      });
    }
  });
  
  /**
   * Make a secure request with certificate pinning
   * @param {string} url - Request URL
   * @param {Object} options - Request options
   * @returns {Promise<Object>} Response data
   */
  const securePinnedRequest = async (url, options = {}) => {
    try {
      // Get authentication token
      const token = await authProvider.getAccessToken();
      
      // Build complete URL
      const fullUrl = url.startsWith('http')
        ? url
        : `${API_CONFIG.baseURL}${url}`;
      
      // Add authorization header
      const headers = {
        ...API_CONFIG.headers,
        ...options.headers,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      };
      
      // Make request with certificate pinning
      return await secureFetch(fullUrl, {
        ...options,
        headers,
      });
    } catch (error) {
      console.error('Secure request error:', error);
      throw error;
    }
  };
  
  // Return the API client with secure methods
  return {
    // Standard Axios client (without certificate pinning)
    client: apiClient,
    
    // Get request with certificate pinning
    async get(url, options = {}) {
      return securePinnedRequest(url, {
        method: 'GET',
        ...options,
      });
    },
    
    // Post request with certificate pinning
    async post(url, data, options = {}) {
      return securePinnedRequest(url, {
        method: 'POST',
        body: JSON.stringify(data),
        ...options,
      });
    },
    
    // Put request with certificate pinning
    async put(url, data, options = {}) {
      return securePinnedRequest(url, {
        method: 'PUT',
        body: JSON.stringify(data),
        ...options,
      });
    },
    
    // Delete request with certificate pinning
    async delete(url, options = {}) {
      return securePinnedRequest(url, {
        method: 'DELETE',
        ...options,
      });
    },
    
    // Upload file with progress tracking
    async upload(url, fileUri, fileName, fileType, onProgress, formData = {}) {
      try {
        const token = await authProvider.getAccessToken();
        
        // Create form data for file upload
        const data = new FormData();
        data.append('file', {
          uri: fileUri,
          name: fileName,
          type: fileType,
        });
        
        // Add additional form data
        Object.keys(formData).forEach(key => {
          data.append(key, formData[key]);
        });
        
        // Upload file
        return apiClient.post(url, data, {
          headers: {
            'Content-Type': 'multipart/form-data',
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          onUploadProgress: progressEvent => {
            const percentCompleted = Math.round(
              (progressEvent.loaded * 100) / progressEvent.total
            );
            if (onProgress) {
              onProgress(percentCompleted);
            }
          },
        });
      } catch (error) {
        console.error('Upload error:', error);
        throw error;
      }
    },
    
    // Clear request queue (useful when logging out)
    clearQueue() {
      const queueLength = requestQueue.length;
      requestQueue = [];
      return queueLength;
    },
    
    // Cancel all pending requests
    cancelRequests() {
      apiClient.interceptors.request.use(request => {
        request.cancelToken = new axios.CancelToken(cancel => {
          cancel('Operation canceled by user');
        });
        return request;
      });
    },
  };
};

/**
 * Create a secure API client with a mock auth provider for testing
 * @returns {Object} Testing API client
 */
export const createTestApiClient = () => {
  // Mock auth provider for testing
  const mockAuthProvider = {
    getAccessToken: async () => 'test-token',
    refreshToken: async () => true,
    logout: () => {},
  };
  
  return createApiClient(mockAuthProvider);
};

// Instantiate API client with appropriate configuration based on environment
export const secureApiClient = process.env.NODE_ENV === 'test'
  ? createTestApiClient()
  : null; // This will be initialized with the real auth provider when ready

// Example usage:
/*
// In your app initialization, after setting up auth provider:
import { createApiClient } from './api-client';
import { authProvider } from './auth-provider';

export const apiClient = createApiClient(authProvider);

// Then use it in your components:
try {
  const response = await apiClient.get('/user/profile');
  console.log('User profile:', response.data);
  
  // Upload profile picture
  const imageResponse = await apiClient.upload(
    '/user/avatar',
    'file:///path/to/image.jpg',
    'avatar.jpg',
    'image/jpeg',
    (progress) => console.log(`Upload progress: ${progress}%`)
  );
  
  console.log('Upload complete:', imageResponse.data);
} catch (error) {
  console.error('API error:', error);
}
*/
