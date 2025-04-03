# Next.js Security Examples

This directory contains security implementation examples for Next.js applications. These examples demonstrate how to implement the security recommendations from the Vibe Security checklist in a Next.js context.

## Contents

1. **Authentication** - Implementing secure authentication with NextAuth.js
2. **Middleware Protection** - Protecting routes and API endpoints
3. **Secure Headers** - Configuring secure HTTP headers
4. **Input Validation** - Validating and sanitizing user input
5. **API Security** - Securing API routes
6. **Environment Variables** - Handling sensitive configuration
7. **CSRF Protection** - Cross-Site Request Forgery prevention

## Requirements

These examples are designed for Next.js 14+ and assume you're using the App Router. With minor adjustments, they can be adapted for the Pages Router as well.

## Setup

To use these examples in your Next.js project:

1. Install required dependencies:

```bash
npm install next-auth zod iron-session @hapi/iron next-csrf jose
```

2. Copy the relevant files to your project
3. Adjust configuration to match your project structure
4. Implement the security patterns in your application logic

## Additional Resources

- [Next.js Security Documentation](https://nextjs.org/docs/advanced-features/security-headers)
- [NextAuth.js Documentation](https://next-auth.js.org/getting-started/introduction)
- [OWASP Top Ten for Web](https://owasp.org/www-project-top-ten/)
