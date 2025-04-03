/**
 * Input validation utilities for Next.js applications
 * 
 * This file provides input validation and sanitization utilities
 * using Zod for schema validation and DOMPurify for HTML sanitization.
 */

import { z } from 'zod';
import DOMPurify from 'isomorphic-dompurify';

// Common validation schemas
export const schemas = {
  // User registration schema
  registration: z.object({
    username: z.string()
      .min(3, 'Username must be at least 3 characters')
      .max(50, 'Username cannot exceed 50 characters')
      .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores and hyphens'),
    email: z.string()
      .email('Invalid email address'),
    password: z.string()
      .min(8, 'Password must be at least 8 characters')
      .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
      .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
      .regex(/[0-9]/, 'Password must contain at least one number')
      .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
    confirmPassword: z.string(),
  }).refine(data => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  }),

  // Profile update schema
  profileUpdate: z.object({
    displayName: z.string()
      .min(2, 'Display name must be at least 2 characters')
      .max(100, 'Display name cannot exceed 100 characters')
      .optional(),
    bio: z.string()
      .max(500, 'Bio cannot exceed 500 characters')
      .optional(),
    website: z.string()
      .url('Website must be a valid URL')
      .optional()
      .or(z.literal('')),
  }),

  // Content creation schema
  content: z.object({
    title: z.string()
      .min(5, 'Title must be at least 5 characters')
      .max(200, 'Title cannot exceed 200 characters'),
    content: z.string()
      .min(10, 'Content must be at least 10 characters')
      .max(50000, 'Content cannot exceed 50,000 characters'),
    tags: z.array(z.string().max(30, 'Tags cannot exceed 30 characters'))
      .max(10, 'Cannot have more than 10 tags'),
    isPublished: z.boolean().default(false),
  }),

  // API query parameters
  queryParams: z.object({
    page: z.coerce.number()
      .int('Page must be an integer')
      .positive('Page must be positive')
      .default(1),
    limit: z.coerce.number()
      .int('Limit must be an integer')
      .positive('Limit must be positive')
      .max(100, 'Limit cannot exceed 100')
      .default(20),
    sortBy: z.enum(['createdAt', 'updatedAt', 'title', 'popular'])
      .default('createdAt'),
    order: z.enum(['asc', 'desc']).default('desc'),
    search: z.string().max(100).optional(),
  }),
};

/**
 * Validate and sanitize user input against a schema
 * @param {object} data - The data to validate
 * @param {z.ZodSchema} schema - The Zod schema to validate against
 * @returns {object} - Validation result with data, success, and errors
 */
export function validateInput(data, schema) {
  try {
    // Parse and validate the data
    const validatedData = schema.parse(data);
    return { data: validatedData, success: true, errors: null };
  } catch (error) {
    if (error instanceof z.ZodError) {
      // Format Zod errors for easier consumption
      const formattedErrors = error.errors.reduce((acc, err) => {
        const path = err.path.join('.');
        acc[path] = err.message;
        return acc;
      }, {});
      
      return { 
        data: null,
        success: false,
        errors: formattedErrors
      };
    }
    
    // Handle unexpected errors
    console.error('Validation error:', error);
    return {
      data: null,
      success: false,
      errors: { _form: 'Validation failed. Please check your input.' }
    };
  }
}

/**
 * Sanitize HTML content to prevent XSS attacks
 * @param {string} html - The HTML content to sanitize
 * @param {object} options - Custom DOMPurify options
 * @returns {string} - Sanitized HTML
 */
export function sanitizeHtml(html, options = {}) {
  // Default configuration - very restrictive
  const defaultOptions = {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li', 'br', 'span'],
    ALLOWED_ATTR: ['href', 'title', 'target', 'rel', 'class'],
    ALLOW_DATA_ATTR: false,
    ADD_ATTR: ['target'],
    FORBID_TAGS: ['script', 'style', 'iframe', 'form', 'object', 'embed', 'input', 'button'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover'],
  };
  
  // Ensure links open in new tab and have noopener/noreferrer
  const hookOptions = {
    afterSanitizeAttributes: function(node) {
      if (node.nodeName.toLowerCase() === 'a') {
        node.setAttribute('target', '_blank');
        node.setAttribute('rel', 'noopener noreferrer');
      }
    }
  };
  
  // Combine options
  const mergedOptions = {
    ...defaultOptions,
    ...options,
    ...hookOptions
  };
  
  // Return sanitized HTML
  return DOMPurify.sanitize(html, mergedOptions);
}

/**
 * Middleware for validating API request data
 * @param {z.ZodSchema} schema - The Zod schema to validate against
 * @param {'body' | 'query' | 'params'} source - The request property to validate
 */
export function validateRequest(schema, source = 'body') {
  return async (req, res, next) => {
    try {
      const result = validateInput(req[source], schema);
      
      if (!result.success) {
        return res.status(400).json({
          success: false,
          errors: result.errors
        });
      }
      
      // Replace the original data with validated data
      req[source] = result.data;
      next();
    } catch (error) {
      console.error('Request validation error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error during validation'
      });
    }
  };
}

// Usage example in API route:
/*
import { schemas, validateInput } from '@/utils/input-validation';

export async function POST(req) {
  try {
    const body = await req.json();
    const result = validateInput(body, schemas.registration);
    
    if (!result.success) {
      return Response.json(
        { success: false, errors: result.errors },
        { status: 400 }
      );
    }
    
    // Process validated data
    const { username, email, password } = result.data;
    // ...
    
    return Response.json({ success: true });
  } catch (error) {
    console.error('API error:', error);
    return Response.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
*/
