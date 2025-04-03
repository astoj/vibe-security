# Next.js Secure Environment Configuration
# ----------------------------------------
# IMPORTANT: Rename this file to .env.local and NEVER commit it to version control
# Add .env.local to your .gitignore file

# Authentication (NextAuth.js)
# ----------------------------------------
# Generate a strong secret with: openssl rand -base64 32
NEXTAUTH_SECRET=your-generated-secret-key-here-never-share-this
NEXTAUTH_URL=http://localhost:3000

# Database (replace with your actual database URL)
# ----------------------------------------
# Format: postgresql://USER:PASSWORD@HOST:PORT/DATABASE
DATABASE_URL=postgresql://user:password@localhost:5432/myapp

# External APIs and Services
# ----------------------------------------
# Email service API key
EMAIL_SERVICE_API_KEY=your-api-key-never-share-this

# Payment processing API key (development only)
PAYMENT_API_KEY=your-payment-api-key-never-share-this

# Feature flags
# ----------------------------------------
NEXT_PUBLIC_ENABLE_ANALYTICS=false
NEXT_PUBLIC_MAINTENANCE_MODE=false

# Node environment (development/production)
# ----------------------------------------
NODE_ENV=development

# Security settings
# ----------------------------------------
# Set the number of bcrypt hash rounds (12+ recommended for production)
PASSWORD_HASH_ROUNDS=12

# API rate limits (requests per minute)
RATE_LIMIT_API=60
RATE_LIMIT_AUTH=10

# Session configuration
# ----------------------------------------
# Session duration in seconds (30 minutes)
SESSION_MAX_AGE=1800

# IMPORTANT NOTES:
# ----------------------------------------
# 1. Never store sensitive information in environment variables prefixed with NEXT_PUBLIC_
#    These variables are embedded in the client-side JavaScript bundle.
# 
# 2. Use different environment files for different environments:
#    - .env.development.local
#    - .env.production.local
#    - .env.test.local
#
# 3. For production secrets, consider using a vault service rather than environment variables.
#
# 4. Regularly rotate your secrets and API keys.
