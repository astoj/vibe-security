/**
 * NextAuth.js configuration with security best practices
 * 
 * This example configures NextAuth.js with secure defaults and
 * implements recommended security practices.
 */

import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { compare } from "bcryptjs";
import { z } from "zod";

// Input validation schema for login credentials
const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(8, "Password must be at least 8 characters"),
});

// Simulate a database call to retrieve a user
// In a real app, this would query your database
async function getUserByEmail(email) {
  // This is a simulation! Replace with actual database query
  // NEVER store plain text passwords in a real application
  const users = [
    {
      id: "1",
      email: "user@example.com",
      // In reality, this would be a hashed password
      passwordHash: "$2a$12$K6vGhA.yU3Tyq0Kq9ifs7.YpMckg3vN1AKVk.gr9KcBYz9wRUFQUi", // "securePassword123"
      name: "Test User",
      role: "user",
    },
  ];
  
  return users.find(user => user.email === email);
}

export const authOptions = {
  providers: [
    CredentialsProvider({
      id: "credentials",
      name: "Email and Password",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        try {
          // Validate input format using Zod
          const result = loginSchema.safeParse(credentials);
          if (!result.success) {
            return null;
          }
          
          const { email, password } = result.data;
          
          // Get user from database
          const user = await getUserByEmail(email);
          if (!user) {
            // Don't reveal that the user doesn't exist
            console.log("Authentication failed: User not found");
            return null;
          }
          
          // Verify password with bcrypt
          const isPasswordValid = await compare(password, user.passwordHash);
          if (!isPasswordValid) {
            // Don't reveal that the password is incorrect
            console.log("Authentication failed: Invalid password");
            return null;
          }
          
          // Never include sensitive information in the session
          return {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
          };
        } catch (error) {
          console.error("Error in authorize function:", error);
          return null;
        }
      },
    }),
  ],
  
  // Configure secure sessions
  session: {
    strategy: "jwt",
    maxAge: 30 * 60, // 30 minutes
  },
  
  // Custom JWT encoding/decoding
  jwt: {
    maxAge: 30 * 60, // 30 minutes
  },
  
  // Include user role in token and session
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.role = user.role;
      }
      return token;
    },
    async session({ session, token }) {
      if (token && session.user) {
        session.user.id = token.sub;
        session.user.role = token.role;
      }
      return session;
    },
  },
  
  // Security settings
  pages: {
    signIn: "/auth/login", // Custom login page
    error: "/auth/error", // Custom error page
  },
  
  // Enable debug in development only
  debug: process.env.NODE_ENV === "development",
  
  // Cookie security settings
  cookies: {
    sessionToken: {
      name: `__Secure-next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: process.env.NODE_ENV === "production",
      },
    },
  },
};

export const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };

// In app/api/auth/[...nextauth]/route.js:
// import { handler } from '@/auth/auth-config';
// export { handler as GET, handler as POST };
