/**
 * Secure API Route Example
 * 
 * This demonstrates a secure implementation of a Next.js API route with:
 * - Input validation
 * - Authentication and authorization
 * - Rate limiting
 * - Error handling
 * - Secure response formatting
 */

import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { rateLimit } from '@/utils/rate-limit';
import { authOptions } from '@/auth/auth-config';
import { validateInput, schemas } from '@/utils/input-validation';
import { z } from 'zod';

// Configure rate limiting
const limiter = rateLimit({
  interval: 60 * 1000, // 1 minute
  uniqueTokenPerInterval: 500,
});

// Custom schema for this API
const userQuerySchema = schemas.queryParams.extend({
  role: z.enum(['admin', 'user', 'guest']).optional(),
  status: z.enum(['active', 'inactive']).optional(),
});

export async function GET(request) {
  try {
    // Rate limiting
    try {
      await limiter.check(10, 'users_api'); // 10 requests per minute
    } catch {
      return NextResponse.json(
        { error: 'Too many requests. Please try again later.' },
        { status: 429 }
      );
    }
    
    // Authentication check
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      );
    }
    
    // Authorization check - only admins can list all users
    if (session.user.role !== 'admin') {
      return NextResponse.json(
        { error: 'Insufficient permissions' },
        { status: 403 }
      );
    }
    
    // Parse and validate query parameters
    const { searchParams } = new URL(request.url);
    const queryParams = Object.fromEntries(searchParams.entries());
    const validation = validateInput(queryParams, userQuerySchema);
    
    if (!validation.success) {
      return NextResponse.json(
        { error: 'Invalid query parameters', details: validation.errors },
        { status: 400 }
      );
    }
    
    const { page, limit, sortBy, order, search, role, status } = validation.data;
    
    // Real implementation would query the database
    // This is just a simulation for the example
    const users = await fetchUsers({ page, limit, sortBy, order, search, role, status });
    
    // Return success response with pagination headers
    const response = NextResponse.json({
      success: true,
      data: users.data,
      pagination: {
        page,
        limit,
        total: users.total,
        pages: Math.ceil(users.total / limit),
      },
    });
    
    // Set security headers
    response.headers.set('Cache-Control', 'private, max-age=0, no-cache, no-store');
    response.headers.set('Pragma', 'no-cache');
    
    return response;
  } catch (error) {
    console.error('Error in users API:', error);
    
    // Determine the appropriate status code
    let statusCode = 500;
    let errorMessage = 'Internal server error';
    
    if (error instanceof z.ZodError) {
      statusCode = 400;
      errorMessage = 'Validation error';
    }
    
    // Return a generic error message (don't leak implementation details)
    return NextResponse.json(
      { error: errorMessage },
      { status: statusCode }
    );
  }
}

export async function POST(request) {
  try {
    // Rate limiting
    try {
      await limiter.check(5, 'create_user'); // 5 requests per minute
    } catch {
      return NextResponse.json(
        { error: 'Too many requests. Please try again later.' },
        { status: 429 }
      );
    }
    
    // Authentication check
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      );
    }
    
    // Authorization check - only admins can create users
    if (session.user.role !== 'admin') {
      return NextResponse.json(
        { error: 'Insufficient permissions' },
        { status: 403 }
      );
    }
    
    // Parse and validate request body
    const body = await request.json();
    
    // Define a schema for creating users
    const createUserSchema = z.object({
      username: z.string().min(3).max(50),
      email: z.string().email(),
      role: z.enum(['admin', 'user', 'guest']).default('user'),
      isActive: z.boolean().default(true),
    });
    
    const validation = validateInput(body, createUserSchema);
    
    if (!validation.success) {
      return NextResponse.json(
        { error: 'Invalid user data', details: validation.errors },
        { status: 400 }
      );
    }
    
    // Validated data
    const userData = validation.data;
    
    // Real implementation would create the user in the database
    // This is just a simulation for the example
    const newUser = await createUser(userData);
    
    // Return success response
    return NextResponse.json({
      success: true,
      data: newUser,
    }, { status: 201 });
  } catch (error) {
    console.error('Error creating user:', error);
    
    // Determine the appropriate status code
    let statusCode = 500;
    let errorMessage = 'Internal server error';
    
    if (error instanceof z.ZodError) {
      statusCode = 400;
      errorMessage = 'Validation error';
    } else if (error.code === 'P2002') {
      // Prisma unique constraint error
      statusCode = 409;
      errorMessage = 'User with this email already exists';
    }
    
    // Return a generic error message (don't leak implementation details)
    return NextResponse.json(
      { error: errorMessage },
      { status: statusCode }
    );
  }
}

// Simulated database functions
async function fetchUsers({ page, limit, sortBy, order, search, role, status }) {
  // In a real app, this would query your database
  // This is just a simulation
  
  // Simulate some delay for a database query
  await new Promise(resolve => setTimeout(resolve, 100));
  
  // Mock data
  const mockUsers = [
    { id: '1', username: 'admin', email: 'admin@example.com', role: 'admin', status: 'active' },
    { id: '2', username: 'user1', email: 'user1@example.com', role: 'user', status: 'active' },
    { id: '3', username: 'user2', email: 'user2@example.com', role: 'user', status: 'inactive' },
  ];
  
  // Filter based on query parameters
  let filteredUsers = [...mockUsers];
  
  if (search) {
    const searchLower = search.toLowerCase();
    filteredUsers = filteredUsers.filter(user => 
      user.username.toLowerCase().includes(searchLower) || 
      user.email.toLowerCase().includes(searchLower)
    );
  }
  
  if (role) {
    filteredUsers = filteredUsers.filter(user => user.role === role);
  }
  
  if (status) {
    filteredUsers = filteredUsers.filter(user => user.status === status);
  }
  
  // Calculate pagination
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + limit;
  
  // Return paginated results
  return {
    data: filteredUsers.slice(startIndex, endIndex),
    total: filteredUsers.length,
  };
}

async function createUser(userData) {
  // In a real app, this would create a user in your database
  // This is just a simulation
  
  // Simulate some delay for a database operation
  await new Promise(resolve => setTimeout(resolve, 100));
  
  // Return a mock created user
  return {
    id: Math.random().toString(36).substring(2, 15),
    ...userData,
    createdAt: new Date().toISOString(),
  };
}
