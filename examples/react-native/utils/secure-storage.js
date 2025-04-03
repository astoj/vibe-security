/**
 * Secure Storage Utilities for React Native
 * 
 * This module provides utilities for securely storing sensitive data
 * in React Native applications using a combination of AsyncStorage
 * and Keychain/Keystore.
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Keychain from 'react-native-keychain';
import { Platform } from 'react-native';

// Security levels for different types of data
export const SECURITY_LEVEL = {
  // General app preferences, non-sensitive
  STANDARD: 'standard',
  
  // Personal information, requires security but not highest level
  SENSITIVE: 'sensitive',
  
  // Highly confidential data (financial, health, authentication)
  CRITICAL: 'critical',
};

/**
 * Store a value securely based on security level
 * @param {string} key - Storage key
 * @param {any} value - Value to store (will be JSON stringified)
 * @param {string} securityLevel - One of SECURITY_LEVEL values
 * @returns {Promise<boolean>} Success status
 */
export const secureStore = async (key, value, securityLevel = SECURITY_LEVEL.STANDARD) => {
  try {
    switch (securityLevel) {
      case SECURITY_LEVEL.CRITICAL:
        // For highest security, store in keychain/keystore
        return await _storeInKeychain(key, value);
        
      case SECURITY_LEVEL.SENSITIVE:
        // For sensitive data, store encrypted value in AsyncStorage
        // with encryption key in keychain
        return await _storeEncrypted(key, value);
        
      case SECURITY_LEVEL.STANDARD:
      default:
        // For standard data, use AsyncStorage
        await AsyncStorage.setItem(key, JSON.stringify(value));
        return true;
    }
  } catch (error) {
    console.error(`Error storing ${key}:`, error);
    return false;
  }
};

/**
 * Retrieve a value based on security level
 * @param {string} key - Storage key
 * @param {string} securityLevel - One of SECURITY_LEVEL values
 * @returns {Promise<any>} Retrieved value or null if not found
 */
export const secureRetrieve = async (key, securityLevel = SECURITY_LEVEL.STANDARD) => {
  try {
    switch (securityLevel) {
      case SECURITY_LEVEL.CRITICAL:
        return await _retrieveFromKeychain(key);
        
      case SECURITY_LEVEL.SENSITIVE:
        return await _retrieveEncrypted(key);
        
      case SECURITY_LEVEL.STANDARD:
      default:
        const value = await AsyncStorage.getItem(key);
        return value ? JSON.parse(value) : null;
    }
  } catch (error) {
    console.error(`Error retrieving ${key}:`, error);
    return null;
  }
};

/**
 * Remove a value based on security level
 * @param {string} key - Storage key
 * @param {string} securityLevel - One of SECURITY_LEVEL values
 * @returns {Promise<boolean>} Success status
 */
export const secureRemove = async (key, securityLevel = SECURITY_LEVEL.STANDARD) => {
  try {
    switch (securityLevel) {
      case SECURITY_LEVEL.CRITICAL:
        await Keychain.resetGenericPassword({ service: key });
        return true;
        
      case SECURITY_LEVEL.SENSITIVE:
        await Keychain.resetGenericPassword({ service: `${key}_encryption_key` });
        await AsyncStorage.removeItem(key);
        return true;
        
      case SECURITY_LEVEL.STANDARD:
      default:
        await AsyncStorage.removeItem(key);
        return true;
    }
  } catch (error) {
    console.error(`Error removing ${key}:`, error);
    return false;
  }
};

/**
 * Store critical data directly in Keychain/Keystore
 * @private
 */
const _storeInKeychain = async (key, value) => {
  // Define the security options based on platform
  const securityOptions = {
    service: key,
    ...(Platform.OS === 'ios' ? {
      accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED,
    } : {
      // Android-specific options
      securityLevel: Keychain.SECURITY_LEVEL.ANY,
    }),
  };
  
  // Store in Keychain/Keystore
  await Keychain.setGenericPassword(
    key, // username field is used as identifier
    typeof value === 'string' ? value : JSON.stringify(value),
    securityOptions
  );
  
  return true;
};

/**
 * Retrieve critical data from Keychain/Keystore
 * @private
 */
const _retrieveFromKeychain = async (key) => {
  const credentials = await Keychain.getGenericPassword({ service: key });
  
  if (!credentials) {
    return null;
  }
  
  const { password } = credentials;
  
  try {
    // Try to parse as JSON if possible
    return JSON.parse(password);
  } catch {
    // Return as string if not JSON
    return password;
  }
};

/**
 * Store sensitive data with encryption
 * @private
 */
const _storeEncrypted = async (key, value) => {
  // Generate a random encryption key
  const encryptionKey = Math.random().toString(36).substring(2, 15) + 
                        Math.random().toString(36).substring(2, 15);
  
  // Store the encryption key in the secure keychain
  await Keychain.setGenericPassword(key, encryptionKey, {
    service: `${key}_encryption_key`,
    ...(Platform.OS === 'ios' ? {
      accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED,
    } : {}),
  });
  
  // Simple XOR encryption (Note: in a real app, use a stronger encryption library)
  const encryptedValue = _encryptXOR(JSON.stringify(value), encryptionKey);
  
  // Store encrypted value in AsyncStorage
  await AsyncStorage.setItem(key, encryptedValue);
  
  return true;
};

/**
 * Retrieve and decrypt sensitive data
 * @private
 */
const _retrieveEncrypted = async (key) => {
  // Get the encryption key from Keychain
  const credentials = await Keychain.getGenericPassword({
    service: `${key}_encryption_key`,
  });
  
  if (!credentials) {
    return null;
  }
  
  const encryptionKey = credentials.password;
  
  // Get the encrypted value from AsyncStorage
  const encryptedValue = await AsyncStorage.getItem(key);
  
  if (!encryptedValue) {
    return null;
  }
  
  // Decrypt the value
  const decryptedStr = _decryptXOR(encryptedValue, encryptionKey);
  
  try {
    // Parse the decrypted JSON string
    return JSON.parse(decryptedStr);
  } catch (error) {
    console.error('Error parsing decrypted value:', error);
    return null;
  }
};

/**
 * Simple XOR encryption/decryption
 * NOTE: This is for demonstration only. In a real app, use a library like
 * react-native-aes-crypto for proper encryption.
 * @private
 */
const _encryptXOR = (text, key) => {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return Buffer.from(result).toString('base64');
};

/**
 * Simple XOR decryption
 * @private
 */
const _decryptXOR = (encryptedBase64, key) => {
  const encryptedText = Buffer.from(encryptedBase64, 'base64').toString();
  let result = '';
  for (let i = 0; i < encryptedText.length; i++) {
    result += String.fromCharCode(encryptedText.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return result;
};

// Example usage:
/*
// Store user preferences (non-sensitive)
await secureStore('userPreferences', { 
  theme: 'dark', 
  notifications: true 
}, SECURITY_LEVEL.STANDARD);

// Store personal information (sensitive)
await secureStore('personalInfo', { 
  name: 'John Doe', 
  address: '123 Main St',
  phoneNumber: '555-123-4567'
}, SECURITY_LEVEL.SENSITIVE);

// Store authentication data (critical)
await secureStore('authToken', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...', SECURITY_LEVEL.CRITICAL);
*/
