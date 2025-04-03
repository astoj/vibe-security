/**
 * Biometric Authentication for React Native
 * 
 * This module provides utilities for using biometric authentication
 * (fingerprint, face recognition) in React Native applications.
 */

import ReactNativeBiometrics, { BiometryTypes } from 'react-native-biometrics';
import * as Keychain from 'react-native-keychain';
import { Platform } from 'react-native';

// Initialize biometrics module
const biometrics = new ReactNativeBiometrics({
  allowDeviceCredentials: true,
});

/**
 * Check if biometric authentication is available on the device
 * @returns {Promise<boolean>} True if biometrics are available
 */
export const checkBiometricAvailability = async () => {
  try {
    const { available, biometryType } = await biometrics.isSensorAvailable();
    
    return available && (
      biometryType === BiometryTypes.TouchID ||
      biometryType === BiometryTypes.FaceID ||
      biometryType === BiometryTypes.Biometrics
    );
  } catch (error) {
    console.error('Error checking biometric availability:', error);
    return false;
  }
};

/**
 * Get the type of biometric authentication available
 * @returns {Promise<string|null>} The biometry type or null if not available
 */
export const getBiometricType = async () => {
  try {
    const { available, biometryType } = await biometrics.isSensorAvailable();
    
    if (!available) {
      return null;
    }
    
    switch (biometryType) {
      case BiometryTypes.TouchID:
        return 'fingerprint';
      case BiometryTypes.FaceID:
        return 'face';
      case BiometryTypes.Biometrics:
        return 'biometric';
      default:
        return null;
    }
  } catch (error) {
    console.error('Error getting biometric type:', error);
    return null;
  }
};

/**
 * Generate and store biometric keys
 * @returns {Promise<boolean>} True if key pair was generated successfully
 */
export const generateBiometricKeys = async () => {
  try {
    const { publicKey } = await biometrics.createKeys('Unlock app using biometrics');
    
    // Store the public key for future verification
    if (publicKey) {
      await Keychain.setGenericPassword(
        'biometric_public_key',
        publicKey,
        {
          service: 'biometric_keys',
          accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        }
      );
      return true;
    }
    
    return false;
  } catch (error) {
    console.error('Error generating biometric keys:', error);
    return false;
  }
};

/**
 * Check if biometric keys exist
 * @returns {Promise<boolean>} True if keys exist
 */
export const hasBiometricKeys = async () => {
  try {
    const { keysExists } = await biometrics.biometricKeysExist();
    return keysExists;
  } catch (error) {
    console.error('Error checking biometric keys:', error);
    return false;
  }
};

/**
 * Delete existing biometric keys
 * @returns {Promise<boolean>} True if keys were deleted successfully
 */
export const deleteBiometricKeys = async () => {
  try {
    await biometrics.deleteKeys();
    await Keychain.resetGenericPassword({ service: 'biometric_keys' });
    return true;
  } catch (error) {
    console.error('Error deleting biometric keys:', error);
    return false;
  }
};

/**
 * Prompt user for biometric authentication
 * @param {string} promptMessage - Message to display to the user
 * @returns {Promise<boolean>} True if authentication was successful
 */
export const authenticateWithBiometrics = async (promptMessage = 'Authenticate to continue') => {
  try {
    const { success } = await biometrics.simplePrompt({
      promptMessage,
      cancelButtonText: 'Cancel',
      fallbackPromptMessage: 'Use PIN instead',
    });
    
    return success;
  } catch (error) {
    console.error('Biometric authentication error:', error);
    return false;
  }
};

/**
 * Sign data with biometric authentication
 * @param {string} payload - Data to sign
 * @param {string} promptMessage - Message to display to the user
 * @returns {Promise<{success: boolean, signature?: string}>} Result with signature if successful
 */
export const signWithBiometrics = async (payload, promptMessage = 'Sign with your biometrics') => {
  try {
    // Check if biometric keys exist
    const { keysExists } = await biometrics.biometricKeysExist();
    
    if (!keysExists) {
      // Generate keys if they don't exist
      const keysGenerated = await generateBiometricKeys();
      if (!keysGenerated) {
        return { success: false };
      }
    }
    
    // Sign the payload
    const { success, signature } = await biometrics.createSignature({
      promptMessage,
      payload,
      cancelButtonText: 'Cancel',
    });
    
    if (success && signature) {
      return { success: true, signature };
    }
    
    return { success: false };
  } catch (error) {
    console.error('Error signing with biometrics:', error);
    return { success: false };
  }
};

/**
 * Verify a signature created with biometrics
 * @param {string} signature - The signature to verify
 * @param {string} payload - The original payload that was signed
 * @returns {Promise<boolean>} True if signature is valid
 */
export const verifySignature = async (signature, payload) => {
  try {
    // Get the stored public key
    const credentials = await Keychain.getGenericPassword({
      service: 'biometric_keys',
    });
    
    if (!credentials) {
      return false;
    }
    
    const publicKey = credentials.password;
    
    // Verify the signature
    const { success } = await biometrics.verifySignature({
      signature,
      payload,
      publicKey,
    });
    
    return success;
  } catch (error) {
    console.error('Error verifying signature:', error);
    return false;
  }
};

/**
 * Secure data with biometric authentication
 * @param {string} key - Storage key
 * @param {any} data - Data to secure
 * @param {string} promptMessage - Message to display to user
 * @returns {Promise<boolean>} True if data was secured successfully
 */
export const secureBiometricData = async (key, data, promptMessage = 'Authenticate to secure data') => {
  try {
    // Prompt user for biometric authentication
    const authenticated = await authenticateWithBiometrics(promptMessage);
    
    if (!authenticated) {
      return false;
    }
    
    // Store data in keychain with biometric protection
    const accessControl = Platform.select({
      ios: Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE,
      android: Keychain.ACCESS_CONTROL.BIOMETRIC_STRONG,
    });
    
    await Keychain.setGenericPassword(
      key,
      JSON.stringify(data),
      {
        service: `biometric_${key}`,
        accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        accessControl,
      }
    );
    
    return true;
  } catch (error) {
    console.error('Error securing data with biometrics:', error);
    return false;
  }
};

/**
 * Retrieve data secured with biometric authentication
 * @param {string} key - Storage key
 * @param {string} promptMessage - Message to display to user
 * @returns {Promise<any|null>} The retrieved data or null if authentication failed
 */
export const retrieveBiometricData = async (key, promptMessage = 'Authenticate to access data') => {
  try {
    // Prompt user for biometric authentication
    const authenticated = await authenticateWithBiometrics(promptMessage);
    
    if (!authenticated) {
      return null;
    }
    
    // Retrieve data from keychain
    const credentials = await Keychain.getGenericPassword({
      service: `biometric_${key}`,
    });
    
    if (!credentials) {
      return null;
    }
    
    try {
      return JSON.parse(credentials.password);
    } catch {
      return credentials.password;
    }
  } catch (error) {
    console.error('Error retrieving data with biometrics:', error);
    return null;
  }
};

// Example usage:
/*
// Check if biometrics are available
const biometricsAvailable = await checkBiometricAvailability();
if (biometricsAvailable) {
  // Get biometric type
  const biometricType = await getBiometricType();
  console.log(`Device supports ${biometricType} authentication`);
  
  // Store sensitive data with biometric protection
  const userData = {
    userId: 'user123',
    apiKey: 'secret-api-key',
  };
  
  const secured = await secureBiometricData(
    'user_credentials',
    userData,
    'Authenticate to save your credentials'
  );
  
  if (secured) {
    console.log('Credentials secured with biometrics');
  }
  
  // Later, retrieve the data
  const retrievedData = await retrieveBiometricData(
    'user_credentials',
    'Authenticate to access your account'
  );
  
  if (retrievedData) {
    console.log('Retrieved user data:', retrievedData);
  }
}
*/
