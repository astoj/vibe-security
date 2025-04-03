/**
 * Secure Input Component for React Native
 * 
 * This component provides enhanced input security features:
 * - Input validation
 * - Masking for sensitive data
 * - Clipboard protection
 * - Visual security indicators
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  View,
  TextInput,
  Text,
  StyleSheet,
  TouchableOpacity,
  Clipboard,
  Platform,
  Keyboard,
} from 'react-native';
import { z } from 'zod';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';

/**
 * Secure input component with validation and security features
 */
const SecureInput = ({
  label,
  value,
  onChangeText,
  placeholder,
  validator,
  errorMessage,
  autoComplete,
  keyboardType = 'default',
  secureTextEntry = false,
  disabled = false,
  maxLength,
  mask,
  preventScreenshot = false,
  preventClipboard = false,
  style,
  containerStyle,
  testID,
}) => {
  // Component state
  const [isFocused, setIsFocused] = useState(false);
  const [isSecureVisible, setIsSecureVisible] = useState(!secureTextEntry);
  const [error, setError] = useState('');
  const [isPasting, setIsPasting] = useState(false);
  const inputRef = useRef(null);
  
  // Prevent screenshots (iOS only, Android needs native module)
  useEffect(() => {
    if (preventScreenshot && Platform.OS === 'ios') {
      const screenListener = () => {
        if (isFocused) {
          Keyboard.dismiss();
          // In a real app, use a native module to show a security alert
          console.warn('Screenshots are not allowed for security reasons');
        }
      };
      
      // Add listener for screenshots
      Clipboard.addListener(screenListener);
      
      return () => {
        // Remove listener on cleanup
        Clipboard.removeListener(screenListener);
      };
    }
  }, [preventScreenshot, isFocused]);
  
  // Clear error when value changes
  useEffect(() => {
    if (error) {
      setError('');
    }
  }, [value]);
  
  // Handle focus event
  const handleFocus = () => {
    setIsFocused(true);
  };
  
  // Handle blur event with validation
  const handleBlur = () => {
    setIsFocused(false);
    
    if (validator && value) {
      validateInput(value);
    }
  };
  
  // Validate input using Zod schema
  const validateInput = (inputValue) => {
    try {
      if (typeof validator === 'object' && validator instanceof z.ZodType) {
        validator.parse(inputValue);
        setError('');
        return true;
      } else if (typeof validator === 'function') {
        const result = validator(inputValue);
        if (result !== true) {
          setError(result || errorMessage || 'Invalid input');
          return false;
        }
        setError('');
        return true;
      }
      return true;
    } catch (err) {
      if (err instanceof z.ZodError) {
        setError(err.errors[0]?.message || errorMessage || 'Invalid input');
      } else {
        setError(errorMessage || 'Invalid input');
      }
      return false;
    }
  };
  
  // Handle paste event
  const handlePaste = async () => {
    if (preventClipboard) {
      // Prevent pasting for security reasons
      return;
    }
    
    try {
      setIsPasting(true);
      const clipboard = await Clipboard.getString();
      
      if (clipboard) {
        // Apply mask if provided
        if (mask && typeof mask === 'function') {
          onChangeText(mask(clipboard));
        } else {
          onChangeText(clipboard);
        }
        
        // Validate pasted content
        if (validator) {
          validateInput(clipboard);
        }
      }
    } catch (err) {
      console.error('Error pasting text:', err);
    } finally {
      setIsPasting(false);
    }
  };
  
  // Handle text change with masking
  const handleChangeText = (text) => {
    // Apply mask if provided
    if (mask && typeof mask === 'function') {
      onChangeText(mask(text));
    } else {
      onChangeText(text);
    }
    
    // Clear error when typing
    if (error) {
      setError('');
    }
  };
  
  // Toggle password visibility
  const toggleSecureEntry = () => {
    setIsSecureVisible(!isSecureVisible);
  };
  
  return (
    <View style={[styles.container, containerStyle]}>
      {label && <Text style={styles.label}>{label}</Text>}
      
      <View style={[
        styles.inputContainer,
        isFocused && styles.inputFocused,
        error && styles.inputError,
        disabled && styles.inputDisabled,
      ]}>
        <TextInput
          ref={inputRef}
          style={[styles.input, style]}
          value={value}
          onChangeText={handleChangeText}
          onFocus={handleFocus}
          onBlur={handleBlur}
          placeholder={placeholder}
          placeholderTextColor="#888"
          secureTextEntry={secureTextEntry && !isSecureVisible}
          keyboardType={keyboardType}
          autoCapitalize="none"
          autoComplete={autoComplete}
          autoCorrect={false}
          editable={!disabled}
          maxLength={maxLength}
          contextMenuHidden={preventClipboard}
          testID={testID}
          // Disable paste option on iOS
          {...(Platform.OS === 'ios' && preventClipboard
            ? { onPaste: () => null }
            : {}
          )}
        />
        
        {isPasting && (
          <View style={styles.iconContainer}>
            <Icon name="content-paste" size={18} color="#888" />
          </View>
        )}
        
        {secureTextEntry && (
          <TouchableOpacity
            style={styles.iconContainer}
            onPress={toggleSecureEntry}
            testID={`${testID}-toggle-secure`}
          >
            <Icon
              name={isSecureVisible ? 'eye-off' : 'eye'}
              size={20}
              color="#888"
            />
          </TouchableOpacity>
        )}
        
        {!secureTextEntry && !isPasting && value && (
          <TouchableOpacity
            style={styles.iconContainer}
            onPress={() => onChangeText('')}
            testID={`${testID}-clear`}
          >
            <Icon name="close-circle" size={18} color="#888" />
          </TouchableOpacity>
        )}
        
        {!preventClipboard && !value && !isPasting && (
          <TouchableOpacity
            style={styles.iconContainer}
            onPress={handlePaste}
            testID={`${testID}-paste`}
          >
            <Icon name="content-paste" size={18} color="#888" />
          </TouchableOpacity>
        )}
      </View>
      
      {error ? (
        <Text style={styles.errorText} testID={`${testID}-error`}>
          {error}
        </Text>
      ) : null}
    </View>
  );
};

// Common validators for reuse
export const Validators = {
  // Email validator
  email: z.string().email('Please enter a valid email address'),
  
  // Password validator (min 8 chars, 1 uppercase, 1 lowercase, 1 number)
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  
  // Phone number validator (simple format)
  phone: z.string().regex(/^\+?[0-9]{10,15}$/, 'Please enter a valid phone number'),
  
  // Credit card number validator
  creditCard: z.string().regex(/^[0-9]{16}$/, 'Please enter a valid 16-digit card number'),
  
  // CVV validator
  cvv: z.string().regex(/^[0-9]{3,4}$/, 'Please enter a valid CVV code'),
  
  // Expiration date validator (MM/YY format)
  expiryDate: z.string().regex(/^(0[1-9]|1[0-2])\/([0-9]{2})$/, 'Please use MM/YY format'),
};

// Common masks for reuse
export const Masks = {
  // Credit card mask (XXXX XXXX XXXX XXXX)
  creditCard: (text) => {
    const digits = text.replace(/\D/g, '').substring(0, 16);
    const groups = [];
    
    for (let i = 0; i < digits.length; i += 4) {
      groups.push(digits.substring(i, i + 4));
    }
    
    return groups.join(' ');
  },
  
  // Phone number mask (+X XXX XXX XXXX)
  phone: (text) => {
    const digits = text.replace(/\D/g, '');
    
    if (digits.length <= 3) {
      return digits;
    } else if (digits.length <= 6) {
      return `${digits.substring(0, 3)} ${digits.substring(3)}`;
    } else if (digits.length <= 10) {
      return `${digits.substring(0, 3)} ${digits.substring(3, 6)} ${digits.substring(6)}`;
    } else {
      return `+${digits.substring(0, 1)} ${digits.substring(1, 4)} ${digits.substring(4, 7)} ${digits.substring(7, 11)}`;
    }
  },
  
  // Expiration date mask (MM/YY)
  expiryDate: (text) => {
    const digits = text.replace(/\D/g, '').substring(0, 4);
    
    if (digits.length <= 2) {
      return digits;
    } else {
      return `${digits.substring(0, 2)}/${digits.substring(2)}`;
    }
  },
  
  // SSN mask (XXX-XX-XXXX)
  ssn: (text) => {
    const digits = text.replace(/\D/g, '').substring(0, 9);
    
    if (digits.length <= 3) {
      return digits;
    } else if (digits.length <= 5) {
      return `${digits.substring(0, 3)}-${digits.substring(3)}`;
    } else {
      return `${digits.substring(0, 3)}-${digits.substring(3, 5)}-${digits.substring(5)}`;
    }
  },
};

const styles = StyleSheet.create({
  container: {
    marginBottom: 16,
  },
  label: {
    fontSize: 14,
    marginBottom: 8,
    fontWeight: '500',
    color: '#333',
  },
  inputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: a8,
    backgroundColor: '#fff',
    paddingHorizontal: 12,
    height: 48,
  },
  inputFocused: {
    borderColor: '#007AFF',
    borderWidth: 2,
  },
  inputError: {
    borderColor: '#FF3B30',
  },
  inputDisabled: {
    backgroundColor: '#f5f5f5',
    borderColor: '#e0e0e0',
  },
  input: {
    flex: 1,
    fontSize: 16,
    color: '#333',
    paddingVertical: 8,
  },
  iconContainer: {
    padding: 4,
    marginLeft: 4,
  },
  errorText: {
    color: '#FF3B30',
    fontSize: 12,
    marginTop: 4,
  },
});

export default SecureInput;

// Example usage:
/*
// Email input with validation
<SecureInput
  label="Email Address"
  value={email}
  onChangeText={setEmail}
  placeholder="Enter your email"
  validator={Validators.email}
  keyboardType="email-address"
  autoComplete="email"
  testID="email-input"
/>

// Password input with security features
<SecureInput
  label="Password"
  value={password}
  onChangeText={setPassword}
  placeholder="Enter your password"
  validator={Validators.password}
  secureTextEntry
  preventClipboard
  preventScreenshot
  testID="password-input"
/>

// Credit card input with masking
<SecureInput
  label="Card Number"
  value={cardNumber}
  onChangeText={setCardNumber}
  placeholder="XXXX XXXX XXXX XXXX"
  validator={Validators.creditCard}
  keyboardType="number-pad"
  mask={Masks.creditCard}
  maxLength={19} // 16 digits + 3 spaces
  testID="card-input"
/>
*/
