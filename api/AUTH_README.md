# 🔐 NestJS Authentication System

Complete authentication system with refresh tokens, session tracking, and Google OAuth integration.

## 🚀 Features

- ✅ **User Registration & Login** with email/password
- ✅ **JWT Access Tokens** (15 minutes expiration)
- ✅ **Refresh Tokens** (30 days expiration)
- ✅ **Session Management** with device tracking
- ✅ **Google OAuth 2.0** integration
- ✅ **Password Hashing** with bcrypt
- ✅ **Request Validation** with class-validator
- ✅ **Route Protection** with guards and decorators
- ✅ **User Profile Management**
- ✅ **Session Revocation** (logout from specific devices)

## 📦 Database Schema

### Users Table
```sql
- id (serial, primary key)
- name (varchar)
- email (varchar, unique)
- password (varchar, optional for OAuth users)
- google_id (varchar, unique)
- avatar (varchar)
- is_email_verified (boolean)
- provider ('local' | 'google')
- created_at, updated_at (timestamps)
```

### Sessions Table
```sql
- id (serial, primary key)
- user_id (foreign key)
- session_token (varchar, unique)
- user_agent (text)
- ip_address (varchar)
- is_active (boolean)
- expires_at (timestamp)
- created_at, last_accessed_at (timestamps)
```

### Refresh Tokens Table
```sql
- id (serial, primary key)
- user_id (foreign key)
- token (varchar, unique)
- expires_at (timestamp)
- is_revoked (boolean)
- created_at (timestamp)
```

## 🔧 Setup Instructions

### 1. Environment Variables
Update your `.env` file:
```env
# Database
DATABASE_URL="postgresql://postgres:[PASSWORD]@db.[PROJECT].supabase.co:5432/postgres"

# JWT Configuration
JWT_SECRET="your-super-secret-jwt-key-change-this-in-production"

# Google OAuth Configuration
GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"
GOOGLE_CALLBACK_URL="http://localhost:3000/auth/google/callback"

# Application
PORT=3000
NODE_ENV=development
```

### 2. Google OAuth Setup
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URIs:
   - `http://localhost:3000/auth/google/callback` (development)
   - `https://yourdomain.com/auth/google/callback` (production)

### 3. Run Database Migration
```bash
npm run db:generate  # Generate migration files
npm run db:migrate   # Run migrations
# OR
npm run db:push      # Push schema directly (development)
```

### 4. Start the Application
```bash
npm run start:dev
```

## 📚 API Endpoints

### Authentication Routes (`/auth`)

#### Register
```http
POST /auth/register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123"
}
```

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "password123"
}
```

#### Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

#### Logout
```http
POST /auth/logout
Authorization: Bearer your-access-token
```

#### Get Profile
```http
GET /auth/me
Authorization: Bearer your-access-token
```

#### Get Sessions
```http
GET /auth/sessions
Authorization: Bearer your-access-token
```

#### Revoke Session
```http
DELETE /auth/sessions/:sessionId
Authorization: Bearer your-access-token
```

### Google OAuth Routes

#### Initiate Google Auth
```http
GET /auth/google
```

#### Google Callback (handled automatically)
```http
GET /auth/google/callback
```

### User Routes (`/users`)

#### Get All Users
```http
GET /users
Authorization: Bearer your-access-token
```

#### Get My Profile
```http
GET /users/me
Authorization: Bearer your-access-token
```

#### Update My Profile
```http
PUT /users/me
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "name": "Updated Name"
}
```

## 🔒 Authentication Response Format

```json
{
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "avatar": "https://...",
    "provider": "local",
    "isEmailVerified": false
  },
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
  "expiresIn": 900
}
```

## 🛡️ Using Authentication in Your Code

### Protect Routes
```typescript
import { UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';

@Controller('protected')
@UseGuards(JwtAuthGuard)
export class ProtectedController {
  // All routes in this controller require authentication
}
```

### Make Routes Public
```typescript
import { Public } from './auth/decorators/public.decorator';

@Controller('public')
export class PublicController {
  @Public()
  @Get('info')
  getPublicInfo() {
    return { message: 'This is public' };
  }
}
```

### Get Current User
```typescript
import { CurrentUser } from './auth/decorators/current-user.decorator';
import { User } from './db/schema';

@Controller('profile')
export class ProfileController {
  @Get()
  getProfile(@CurrentUser() user: User) {
    return user;
  }
}
```

## 🔐 Security Features

### Password Security
- Passwords are hashed using bcrypt with salt rounds of 12
- Minimum password length of 6 characters (configurable)

### JWT Security
- Short-lived access tokens (15 minutes)
- Secure refresh token rotation
- Session-based token validation

### Session Management
- Device tracking with User-Agent and IP address
- Session expiration (7 days, configurable)
- Ability to revoke specific sessions
- Automatic cleanup of expired sessions

### OAuth Security
- Secure Google OAuth 2.0 flow
- Email verification through OAuth provider
- Account linking for existing users

## 🚀 Testing the Authentication

### Using cURL

**Register:**
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"John Doe","email":"john@example.com","password":"password123"}'
```

**Login:**
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com","password":"password123"}'
```

**Access Protected Route:**
```bash
curl -X GET http://localhost:3000/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Using Frontend (JavaScript)

```javascript
// Register
const response = await fetch('http://localhost:3000/auth/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'John Doe',
    email: 'john@example.com',
    password: 'password123'
  })
});

const { user, accessToken, refreshToken } = await response.json();

// Store tokens
localStorage.setItem('accessToken', accessToken);
localStorage.setItem('refreshToken', refreshToken);

// Use access token for authenticated requests
const protectedResponse = await fetch('http://localhost:3000/auth/me', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});
```

## 🔄 Token Refresh Flow

```javascript
async function refreshAccessToken() {
  const refreshToken = localStorage.getItem('refreshToken');
  
  const response = await fetch('http://localhost:3000/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken })
  });
  
  if (response.ok) {
    const { accessToken, refreshToken: newRefreshToken } = await response.json();
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', newRefreshToken);
    return accessToken;
  } else {
    // Refresh token expired, redirect to login
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    window.location.href = '/login';
  }
}
```

## 🎯 Production Considerations

1. **Environment Variables**: Use strong, unique secrets in production
2. **HTTPS**: Always use HTTPS in production
3. **CORS**: Configure CORS properly for your frontend domain
4. **Rate Limiting**: Implement rate limiting for auth endpoints
5. **Monitoring**: Monitor failed login attempts and suspicious activity
6. **Backup**: Regular database backups
7. **Updates**: Keep dependencies updated for security patches

## 🔍 Troubleshooting

### Common Issues

1. **"Invalid or expired token"**
   - Check if JWT_SECRET matches between token generation and validation
   - Verify token hasn't expired
   - Ensure proper Bearer token format

2. **Google OAuth not working**
   - Verify Google OAuth credentials in .env
   - Check redirect URI configuration
   - Ensure Google+ API is enabled

3. **Database connection issues**
   - Verify DATABASE_URL is correct
   - Check if migrations have been run
   - Ensure database server is accessible

Your authentication system is now ready for production use! 🎉 