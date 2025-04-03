/**
 * Secure Authentication Provider for React Native
 * 
 * This component provides a secure authentication context
 * for React Native applications with token management,
 * auto-refresh, and secure storage.
 */

import React, { createContext, useState, useContext, useEffect } from 'react';
import { Platform } from 'react-native';
import * as Keychain from 'react-native-keychain';
import { z } from 'zod';
import { secureApiClient } from '../services/api-client';
import { checkBiometricAvailability } from '../utils/biometric-auth';

// Define validation schema for authentication
const loginSchema = z.object({
  email: z.string().email('Please enter a valid email'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

// Authentication context
const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [biometricsAvailable, setBiometricsAvailable] = useState(false);
  
  // Check for biometric capabilities on mount
  useEffect(() => {
    const checkBiometrics = async () => {
      const available = await checkBiometricAvailability();
      setBiometricsAvailable(available);
    };
    
    checkBiometrics();
  }, []);
  
  // Check for existing session on mount
  useEffect(() => {
    const loadUserSession = async () => {
      try {
        setLoading(true);
        const session = await getStoredSession();
        
        if (session) {
          // Validate token expiration
          const { expiration, refreshToken } = session;
          
          if (new Date(expiration) > new Date()) {
            // Token still valid, restore session
            setUser(session.user);
          } else if (refreshToken) {
            // Token expired, attempt refresh
            await refreshSession(refreshToken);
          }
        }
      } catch (err) {
        console.error('Failed to restore session:', err);
        await clearSession();
      } finally {
        setLoading(false);
      }
    };
    
    loadUserSession();
  }, []);
  
  // Login function
  const login = async (email, password, useBiometrics = false) => {
    try {
      setLoading(true);
      setError(null);
      
      // Validate input
      loginSchema.parse({ email, password });
      
      // Send authentication request
      const response = await secureApiClient.post('/auth/login', {
        email,
        password,
        device_name: Platform.OS === 'ios' ? 'iOS Device' : 'Android Device',
      });
      
      const { user, access_token, refresh_token, expiration } = response.data;
      
      // Store session securely
      await storeSession({
        user,
        accessToken: access_token,
        refreshToken: refresh_token,
        expiration,
      }, useBiometrics);
      
      // Set authenticated user
      setUser(user);
      
      return true;
    } catch (err) {
      // Handle specific errors
      if (err instanceof z.ZodError) {
        setError('Invalid email or password format');
      } else if (err.response?.status === 401) {
        setError('Invalid credentials');
      } else if (err.response?.status === 429) {
        setError('Too many login attempts. Please try again later.');
      } else {
        setError('Authentication failed. Please try again.');
        console.error('Login error:', err);
      }
      
      return false;
    } finally {
      setLoading(false);
    }
  };
  
  // Biometric authentication
  const loginWithBiometrics = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Get credentials from secure storage
      const credentials = await Keychain.getGenericPassword({
        service: 'biometric_login',
      });
      
      if (!credentials) {
        setError('No saved credentials found');
        return false;
      }
      
      // Parse stored credentials
      const { username, password } = credentials;
      const { email, refreshToken } = JSON.parse(password);
      
      if (refreshToken) {
        // Use refresh token to get a new session
        return await refreshSession(refreshToken);
      } else if (email) {
        // Show biometric prompt in real implementation
        // For this example, we'll simulate success
        setUser(JSON.parse(username));
        return true;
      }
      
      return false;
    } catch (err) {
      console.error('Biometric login error:', err);
      setError('Biometric authentication failed');
      return false;
    } finally {
      setLoading(false);
    }
  };
  
  // Logout function
  const logout = async () => {
    try {
      setLoading(true);
      
      // Get current session
      const session = await getStoredSession();
      
      if (session?.accessToken) {
        // Notify backend about logout (invalidate token)
        try {
          await secureApiClient.post('/auth/logout', {}, {
            headers: {
              Authorization: `Bearer ${session.accessToken}`,
            },
          });
        } catch (err) {
          console.warn('Logout API call failed:', err);
          // Continue with local logout even if API call fails
        }
      }
      
      // Clear local session
      await clearSession();
      
      setUser(null);
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      setLoading(false);
    }
  };
  
  // Refresh authentication token
  const refreshSession = async (refreshToken) => {
    try {
      // Call refresh token endpoint
      const response = await secureApiClient.post('/auth/refresh', {
        refresh_token: refreshToken,
      });
      
      const { user, access_token, refresh_token, expiration } = response.data;
      
      // Store new session
      await storeSession({
        user,
        accessToken: access_token, 
        refreshToken: refresh_token,
        expiration,
      });
      
      // Update state
      setUser(user);
      
      return true;
    } catch (err) {
      console.error('Token refresh failed:', err);
      await clearSession();
      setUser(null);
      return false;
    }
  };
  
  // Store session securely
  const storeSession = async (sessionData, enableBiometrics = false) => {
    try {
      // Store auth token securely
      await Keychain.setGenericPassword(
        'auth_session',
        JSON.stringify(sessionData),
        {
          service: 'auth_session',
          accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED,
        }
      );
      
      // Optionally store for biometric login
      if (enableBiometrics && biometricsAvailable) {
        await Keychain.setGenericPassword(
          JSON.stringify(sessionData.user),
          JSON.stringify({
            email: sessionData.user.email,
            refreshToken: sessionData.refreshToken,
          }),
          {
            service: 'biometric_login',
            accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
            accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_ANY,
          }
        );
      }
    } catch (err) {
      console.error('Failed to store session:', err);
      throw err;
    }
  };
  
  // Get session from secure storage
  const getStoredSession = async () => {
    try {
      const credentials = await Keychain.getGenericPassword({
        service: 'auth_session',
      });
      
      if (!credentials) {
        return null;
      }
      
      return JSON.parse(credentials.password);
    } catch (err) {
      console.error('Failed to get session:', err);
      return null;
    }
  };
  
  // Clear stored session data
  const clearSession = async () => {
    try {
      await Keychain.resetGenericPassword({ service: 'auth_session' });
      // Don't clear biometric credentials to allow re-login
    } catch (err) {
      console.error('Failed to clear session:', err);
    }
  };
  
  // Get current access token
  const getAccessToken = async () => {
    try {
      const session = await getStoredSession();
      
      if (!session) {
        return null;
      }
      
      const { accessToken, expiration, refreshToken } = session;
      
      // Check if token is expired or will expire soon (5 min buffer)
      const expirationDate = new Date(expiration);
      const now = new Date();
      const expirationBuffer = new Date(now.getTime() + 5 * 60 * 1000); // 5 minutes
      
      if (expirationDate <= expirationBuffer) {
        // Token expired or expiring soon, try to refresh
        const refreshed = await refreshSession(refreshToken);
        if (refreshed) {
          const newSession = await getStoredSession();
          return newSession.accessToken;
        }
        return null;
      }
      
      return accessToken;
    } catch (err) {
      console.error('Get access token error:', err);
      return null;
    }
  };
  
  // Register a new user
  const register = async (userData) => {
    try {
      setLoading(true);
      setError(null);
      
      // Validate registration data (expanded validation would be in a real app)
      const registerSchema = z.object({
        name: z.string().min(2, 'Name must be at least 2 characters'),
        email: z.string().email('Please enter a valid email'),
        password: z.string().min(8, 'Password must be at least 8 characters'),
      });
      
      registerSchema.parse(userData);
      
      // Send registration request
      const response = await secureApiClient.post('/auth/register', userData);
      
      // Auto-login if registration is successful
      if (response.data.success) {
        return await login(userData.email, userData.password);
      }
      
      return false;
    } catch (err) {
      if (err instanceof z.ZodError) {
        setError(err.errors[0].message);
      } else if (err.response?.status === 409) {
        setError('Email already exists');
      } else {
        setError('Registration failed. Please try again.');
        console.error('Registration error:', err);
      }
      
      return false;
    } finally {
      setLoading(false);
    }
  };
  
  // Provide authentication context to all child components
  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        error,
        biometricsAvailable,
        isAuthenticated: !!user,
        login,
        loginWithBiometrics,
        logout,
        register,
        getAccessToken,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

// Hook for easy context usage
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
