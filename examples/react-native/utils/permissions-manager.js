/**
 * Permissions Manager for React Native
 * 
 * This module provides utilities for securely managing
 * device permissions following least privilege principles.
 */

import { Platform, Alert, Linking } from 'react-native';
import { request, check, RESULTS, PERMISSIONS, openSettings } from 'react-native-permissions';
import AsyncStorage from '@react-native-async-storage/async-storage';

// Permission types with platform-specific configuration
const PERMISSION_TYPES = {
  // Camera permission
  CAMERA: {
    ios: PERMISSIONS.IOS.CAMERA,
    android: PERMISSIONS.ANDROID.CAMERA,
    title: 'Camera Permission',
    message: 'This app needs access to your camera to take photos.',
    critical: false, // Whether the app can function without this permission
  },
  
  // Photo library permissions
  PHOTO_LIBRARY: {
    ios: PERMISSIONS.IOS.PHOTO_LIBRARY,
    android: PERMISSIONS.ANDROID.READ_EXTERNAL_STORAGE,
    title: 'Photo Library Permission',
    message: 'This app needs access to your photos to upload images.',
    critical: false,
  },
  
  // Microphone permissions
  MICROPHONE: {
    ios: PERMISSIONS.IOS.MICROPHONE,
    android: PERMISSIONS.ANDROID.RECORD_AUDIO,
    title: 'Microphone Permission',
    message: 'This app needs access to your microphone for voice notes.',
    critical: false,
  },
  
  // Location permissions
  LOCATION: {
    ios: PERMISSIONS.IOS.LOCATION_WHEN_IN_USE,
    android: PERMISSIONS.ANDROID.ACCESS_FINE_LOCATION,
    title: 'Location Permission',
    message: 'This app needs access to your location to show nearby services.',
    critical: false,
  },
  
  // Contacts permissions
  CONTACTS: {
    ios: PERMISSIONS.IOS.CONTACTS,
    android: PERMISSIONS.ANDROID.READ_CONTACTS,
    title: 'Contacts Permission',
    message: 'This app needs access to your contacts to find friends.',
    critical: false,
  },
  
  // Notifications permissions (iOS only)
  NOTIFICATIONS: {
    ios: PERMISSIONS.IOS.NOTIFICATIONS,
    android: null, // Android handles notifications differently
    title: 'Notifications Permission',
    message: 'This app needs to send you notifications for important updates.',
    critical: true,
  },
};

// AsyncStorage key for permission request history
const PERMISSION_HISTORY_KEY = 'permission_request_history';

/**
 * Get platform-specific permission for the given type
 * @param {string} type - Permission type from PERMISSION_TYPES
 * @returns {string|null} Platform-specific permission string
 */
const getPermissionByPlatform = (type) => {
  const permission = PERMISSION_TYPES[type];
  
  if (!permission) {
    console.warn(`Unknown permission type: ${type}`);
    return null;
  }
  
  const platformPermission = Platform.select({
    ios: permission.ios,
    android: permission.android,
  });
  
  // Some permissions might not be available on certain platforms
  if (!platformPermission) {
    console.warn(`Permission ${type} not available on ${Platform.OS}`);
    return null;
  }
  
  return platformPermission;
};

/**
 * Save permission request history
 * @param {string} permissionType - Type of permission
 * @param {string} result - Result of permission request
 * @param {Date} timestamp - When the permission was requested
 */
const savePermissionHistory = async (permissionType, result, timestamp = new Date()) => {
  try {
    // Get existing history
    const historyJson = await AsyncStorage.getItem(PERMISSION_HISTORY_KEY);
    const history = historyJson ? JSON.parse(historyJson) : {};
    
    // Update history for this permission
    if (!history[permissionType]) {
      history[permissionType] = [];
    }
    
    // Add new request to history
    history[permissionType].push({
      result,
      timestamp: timestamp.toISOString(),
    });
    
    // Keep only last 5 requests to prevent excessive storage
    if (history[permissionType].length > 5) {
      history[permissionType] = history[permissionType].slice(-5);
    }
    
    // Save updated history
    await AsyncStorage.setItem(PERMISSION_HISTORY_KEY, JSON.stringify(history));
  } catch (error) {
    console.error('Failed to save permission history:', error);
  }
};

/**
 * Get permission request history
 * @param {string} permissionType - Type of permission (optional, all if not specified)
 * @returns {Object|Array} Permission request history
 */
const getPermissionHistory = async (permissionType = null) => {
  try {
    const historyJson = await AsyncStorage.getItem(PERMISSION_HISTORY_KEY);
    const history = historyJson ? JSON.parse(historyJson) : {};
    
    if (permissionType) {
      return history[permissionType] || [];
    }
    
    return history;
  } catch (error) {
    console.error('Failed to get permission history:', error);
    return permissionType ? [] : {};
  }
};

/**
 * Check if permission was requested too many times
 * @param {string} permissionType - Type of permission
 * @returns {boolean} True if permission was requested too many times
 */
const isTooManyRequests = async (permissionType) => {
  const history = await getPermissionHistory(permissionType);
  
  // If permission was requested and denied 3+ times, it's too many
  const denials = history.filter(item => 
    item.result === RESULTS.DENIED || item.result === RESULTS.BLOCKED
  );
  
  return denials.length >= 3;
};

/**
 * Show permission rationale dialog
 * @param {Object} permission - Permission configuration
 * @returns {Promise<boolean>} True if user wants to proceed
 */
const showPermissionRationale = (permission) => {
  return new Promise((resolve) => {
    Alert.alert(
      permission.title,
      permission.message,
      [
        {
          text: 'Not Now',
          style: 'cancel',
          onPress: () => resolve(false),
        },
        {
          text: 'Continue',
          onPress: () => resolve(true),
        },
      ],
      { cancelable: false }
    );
  });
};

/**
 * Show settings dialog when permission is blocked
 * @param {Object} permission - Permission configuration
 * @returns {Promise<boolean>} True if user went to settings
 */
const showSettingsDialog = (permission) => {
  return new Promise((resolve) => {
    Alert.alert(
      'Permission Required',
      `${permission.message} Please enable it in settings.`,
      [
        {
          text: 'Not Now',
          style: 'cancel',
          onPress: () => resolve(false),
        },
        {
          text: 'Open Settings',
          onPress: async () => {
            await openSettings();
            resolve(true);
          },
        },
      ],
      { cancelable: false }
    );
  });
};

/**
 * Request permission with proper user flow
 * @param {string} permissionType - Type of permission to request
 * @param {boolean} skipRationale - Skip rationale dialog (optional)
 * @returns {Promise<boolean>} True if permission is granted
 */
export const requestPermission = async (permissionType, skipRationale = false) => {
  try {
    const permissionConfig = PERMISSION_TYPES[permissionType];
    if (!permissionConfig) {
      console.error(`Unknown permission type: ${permissionType}`);
      return false;
    }
    
    const platformPermission = getPermissionByPlatform(permissionType);
    if (!platformPermission) {
      // Permission not applicable on this platform
      return false;
    }
    
    // Check current permission status
    const status = await check(platformPermission);
    
    // Record this check in history
    await savePermissionHistory(permissionType, status);
    
    switch (status) {
      case RESULTS.GRANTED:
        // Already granted
        return true;
        
      case RESULTS.DENIED:
        // Check if we've asked too many times
        const tooManyRequests = await isTooManyRequests(permissionType);
        
        if (tooManyRequests) {
          // If we've asked too many times, show settings dialog
          const wentToSettings = await showSettingsDialog(permissionConfig);
          return wentToSettings;
        }
        
        // Show rationale if not skipped
        if (!skipRationale) {
          const shouldProceed = await showPermissionRationale(permissionConfig);
          if (!shouldProceed) {
            return false;
          }
        }
        
        // Request permission
        const result = await request(platformPermission);
        await savePermissionHistory(permissionType, result);
        
        return result === RESULTS.GRANTED;
        
      case RESULTS.BLOCKED:
      case RESULTS.UNAVAILABLE:
        // Permission is blocked or unavailable, show settings dialog
        const critical = permissionConfig.critical;
        
        if (critical) {
          // For critical permissions, always show settings dialog
          const wentToSettings = await showSettingsDialog(permissionConfig);
          return wentToSettings;
        } else {
          // For non-critical permissions, only show settings dialog if requested
          const wentToSettings = await showSettingsDialog(permissionConfig);
          return wentToSettings;
        }
        
      default:
        return false;
    }
  } catch (error) {
    console.error('Permission request error:', error);
    return false;
  }
};

/**
 * Check multiple permissions at once
 * @param {Array<string>} permissionTypes - Array of permission types
 * @returns {Promise<Object>} Object with permission status for each type
 */
export const checkMultiplePermissions = async (permissionTypes) => {
  try {
    const permissionsToCheck = permissionTypes.reduce((acc, type) => {
      const platformPermission = getPermissionByPlatform(type);
      if (platformPermission) {
        acc[type] = platformPermission;
      }
      return acc;
    }, {});
    
    // Check all permissions
    const results = {};
    
    for (const [type, permission] of Object.entries(permissionsToCheck)) {
      try {
        const status = await check(permission);
        results[type] = status;
      } catch (error) {
        console.warn(`Error checking permission ${type}:`, error);
        results[type] = RESULTS.UNAVAILABLE;
      }
    }
    
    return results;
  } catch (error) {
    console.error('Check multiple permissions error:', error);
    return {};
  }
};

/**
 * Request multiple permissions sequentially
 * @param {Array<string>} permissionTypes - Array of permission types
 * @returns {Promise<Object>} Object with results for each permission
 */
export const requestMultiplePermissions = async (permissionTypes) => {
  const results = {};
  
  for (const type of permissionTypes) {
    results[type] = await requestPermission(type);
  }
  
  return results;
};

/**
 * Clear permission request history
 * @param {string} permissionType - Type of permission (optional, all if not specified)
 */
export const clearPermissionHistory = async (permissionType = null) => {
  try {
    if (permissionType) {
      // Clear history for specific permission
      const historyJson = await AsyncStorage.getItem(PERMISSION_HISTORY_KEY);
      const history = historyJson ? JSON.parse(historyJson) : {};
      
      if (history[permissionType]) {
        delete history[permissionType];
        await AsyncStorage.setItem(PERMISSION_HISTORY_KEY, JSON.stringify(history));
      }
    } else {
      // Clear all permission history
      await AsyncStorage.removeItem(PERMISSION_HISTORY_KEY);
    }
  } catch (error) {
    console.error('Failed to clear permission history:', error);
  }
};

/**
 * Get permission status
 * @param {string} permissionType - Type of permission
 * @returns {Promise<string>} Permission status
 */
export const getPermissionStatus = async (permissionType) => {
  try {
    const platformPermission = getPermissionByPlatform(permissionType);
    
    if (!platformPermission) {
      return RESULTS.UNAVAILABLE;
    }
    
    return await check(platformPermission);
  } catch (error) {
    console.error('Get permission status error:', error);
    return RESULTS.UNAVAILABLE;
  }
};

/**
 * Check if all required permissions are granted
 * @param {Array<string>} requiredPermissions - Array of required permission types
 * @returns {Promise<boolean>} True if all required permissions are granted
 */
export const hasRequiredPermissions = async (requiredPermissions) => {
  const statuses = await checkMultiplePermissions(requiredPermissions);
  
  return Object.values(statuses).every(status => status === RESULTS.GRANTED);
};

/**
 * Create a React Hook for managing permissions
 * @param {Array<string>} initialPermissions - Initial permission types to check
 * @returns {Object} Permission hook with status and request methods
 */
export const usePermissions = (initialPermissions = []) => {
  const [permissions, setPermissions] = React.useState({});
  const [loading, setLoading] = React.useState(true);
  
  // Load initial permissions
  React.useEffect(() => {
    const loadPermissions = async () => {
      if (initialPermissions.length > 0) {
        setLoading(true);
        const statuses = await checkMultiplePermissions(initialPermissions);
        setPermissions(statuses);
        setLoading(false);
      } else {
        setLoading(false);
      }
    };
    
    loadPermissions();
  }, []);
  
  // Request permission and update state
  const request = async (permissionType) => {
    const granted = await requestPermission(permissionType);
    
    setPermissions(prev => ({
      ...prev,
      [permissionType]: granted ? RESULTS.GRANTED : RESULTS.DENIED,
    }));
    
    return granted;
  };
  
  // Request multiple permissions
  const requestMultiple = async (permissionTypes) => {
    const results = await requestMultiplePermissions(permissionTypes);
    
    const updatedStatuses = {};
    for (const [type, granted] of Object.entries(results)) {
      updatedStatuses[type] = granted ? RESULTS.GRANTED : RESULTS.DENIED;
    }
    
    setPermissions(prev => ({
      ...prev,
      ...updatedStatuses,
    }));
    
    return results;
  };
  
  // Check if permission is granted
  const isGranted = (permissionType) => {
    return permissions[permissionType] === RESULTS.GRANTED;
  };
  
  return {
    permissions,
    loading,
    request,
    requestMultiple,
    isGranted,
    refresh: async () => {
      setLoading(true);
      const statuses = await checkMultiplePermissions(
        Object.keys(permissions).length > 0
          ? Object.keys(permissions)
          : initialPermissions
      );
      setPermissions(statuses);
      setLoading(false);
    },
  };
};

// Export permission types and results for convenience
export const PermissionTypes = Object.keys(PERMISSION_TYPES);
export const PermissionResults = RESULTS;

// Example usage:
/*
// Function component with permissions hook
function CameraScreen() {
  const { permissions, loading, request, isGranted } = usePermissions(['CAMERA']);
  
  const takePicture = async () => {
    if (!isGranted('CAMERA')) {
      const granted = await request('CAMERA');
      if (!granted) {
        Alert.alert('Permission required', 'Camera access is needed for this feature');
        return;
      }
    }
    
    // Access camera functionality
    // ...
  };
  
  return (
    <View style={styles.container}>
      <Button title="Take Picture" onPress={takePicture} />
    </View>
  );
}

// Function to check multiple permissions before a feature
async function checkRequiredPermissions() {
  const requiredPermissions = ['CAMERA', 'MICROPHONE'];
  
  // Check if we have all permissions
  const hasPermissions = await hasRequiredPermissions(requiredPermissions);
  
  if (hasPermissions) {
    // All permissions granted, proceed with feature
    startVideoRecording();
  } else {
    // Request missing permissions
    const results = await requestMultiplePermissions(requiredPermissions);
    
    // Check if all were granted
    const allGranted = Object.values(results).every(result => result === true);
    
    if (allGranted) {
      startVideoRecording();
    } else {
      Alert.alert(
        'Permissions Required',
        'Camera and microphone access are needed for video recording'
      );
    }
  }
}
*/
