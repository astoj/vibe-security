/**
 * Authorization middleware for Next.js
 * 
 * This middleware:
 * 1. Protects routes based on authentication status
 * 2. Implements role-based access control
 * 3. Sets secure headers for all responses
 */

import { NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';

// Define protected routes and required roles
const protectedRoutes = [
  {
    path: '/dashboard',
    requiredRole: 'user',
  },
  {
    path: '/admin',
    requiredRole: 'admin',
  },
  {
    path: '/api/admin',
    requiredRole: 'admin',
  },
];

// Set secure headers for all responses
const secureHeaders = {
  'X-DNS-Prefetch-Control': 'on',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-XSS-Protection': '1; mode=block',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': `
    default-src 'self';
    script-src 'self' 'unsafe-inline' 'unsafe-eval';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data:;
    font-src 'self';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'self';
    block-all-mixed-content;
    upgrade-insecure-requests;
  `.replace(/\s+/g, ' ').trim(),
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

export async function middleware(request) {
  // Clone the response to add headers
  const response = NextResponse.next();
  
  // Apply secure headers to all responses
  Object.entries(secureHeaders).forEach(([key, value]) => {
    response.headers.set(key, value);
  });
  
  // Get the pathname from the URL
  const { pathname } = request.nextUrl;
  
  // Skip auth check for non-protected routes
  const isProtectedRoute = protectedRoutes.some(
    (route) => pathname === route.path || pathname.startsWith(`${route.path}/`)
  );
  
  if (!isProtectedRoute) {
    return response;
  }
  
  try {
    // Get the token using the NextAuth.js JWT callback
    const token = await getToken({
      req: request,
      secret: process.env.NEXTAUTH_SECRET,
    });
    
    // No token = not authenticated
    if (!token) {
      // Redirect to login page with return URL
      const url = new URL('/auth/login', request.url);
      url.searchParams.set('returnUrl', pathname);
      return NextResponse.redirect(url);
    }
    
    // Check role-based access for the specific route
    const routeConfig = protectedRoutes.find(
      (route) => pathname === route.path || pathname.startsWith(`${route.path}/`)
    );
    
    if (routeConfig && routeConfig.requiredRole) {
      const userRole = token.role;
      
      // Role hierarchy for access control
      const roleHierarchy = {
        admin: ['admin', 'user', 'guest'],
        user: ['user', 'guest'],
        guest: ['guest'],
      };
      
      // Check if user's role has access to the required role
      const hasAccess = userRole && roleHierarchy[userRole]?.includes(routeConfig.requiredRole);
      
      if (!hasAccess) {
        // Return 403 Forbidden for API routes
        if (pathname.startsWith('/api/')) {
          return new NextResponse(
            JSON.stringify({ error: 'Insufficient permissions' }),
            { status: 403, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        // Redirect to unauthorized page for non-API routes
        return NextResponse.redirect(new URL('/unauthorized', request.url));
      }
    }
    
    // User is authenticated and authorized
    return response;
  } catch (error) {
    console.error('Middleware error:', error);
    
    // Handle errors gracefully
    if (pathname.startsWith('/api/')) {
      return new NextResponse(
        JSON.stringify({ error: 'Authentication error' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      );
    }
    
    // Redirect to error page for non-API routes
    return NextResponse.redirect(new URL('/auth/error', request.url));
  }
}

// Configure which routes use this middleware
export const config = {
  matcher: [
    '/dashboard/:path*', 
    '/admin/:path*',
    '/api/:path*', 
    '/((?!_next/static|_next/image|favicon.ico|public/|auth/).*)',
  ],
};
