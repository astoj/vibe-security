# React Native Security Examples

This directory contains security implementation examples for React Native applications. These examples demonstrate how to implement the security recommendations from the Vibe Security checklist in a React Native context.

## Contents

1. **Authentication** - Secure authentication implementation
2. **Secure Storage** - Encrypting and storing sensitive data
3. **Certificate Pinning** - Preventing MITM attacks
4. **Biometric Authentication** - Using device biometrics
5. **Input Validation** - Validating and sanitizing user input
6. **Secure API Requests** - Making secure network requests
7. **App Permissions** - Managing application permissions

## Requirements

These examples are designed for React Native 0.71+ and have been tested on both iOS and Android platforms. They use standard React Native libraries and some common security-focused packages.

## Setup

To use these examples in your React Native project:

1. Install required dependencies:

```bash
npm install @react-native-async-storage/async-storage react-native-keychain @react-native-community/netinfo react-native-ssl-pinning zod react-native-biometrics
```

2. Link native modules if needed:

```bash
npx pod-install  # For iOS
```

3. Copy the relevant files to your project
4. Adjust configuration to match your project structure
5. Implement the security patterns in your application logic

## Additional Resources

- [React Native Security Documentation](https://reactnative.dev/docs/security)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
