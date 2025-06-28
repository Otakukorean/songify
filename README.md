# 🎵 Songify

A comprehensive music streaming application built with modern full-stack technologies, delivering seamless experiences across web and mobile platforms.

## 🚀 Overview

Songify is a multi-platform music streaming application that allows users to discover, stream, and manage their favorite songs. Built with a robust backend API, responsive web interface, and native mobile experience.

## 🛠️ Tech Stack

### Backend API
- **NestJS** - Scalable Node.js server-side framework
- **PostgreSQL** - Robust relational database
- **Drizzle ORM** - Type-safe database toolkit
- **JWT Authentication** - Secure user authentication
- **Google OAuth 2.0** - Social login integration
- **Swagger/OpenAPI** - API documentation

### Web Frontend
- **Next.js** - React framework for production
- **React** - Modern UI library
- **TypeScript** - Type-safe JavaScript

### Mobile App
- **React Native** - Cross-platform mobile development
- **Expo** - Universal React Native platform
- **TypeScript** - Type-safe development

## 📁 Project Structure

```
songify/
├── api/                    # NestJS Backend API
│   ├── src/
│   │   ├── auth/          # Authentication system
│   │   ├── users/         # User management
│   │   ├── db/            # Database configuration
│   │   └── main.ts        # Application entry point
│   ├── drizzle/           # Database migrations
│   └── package.json
├── web/                   # Next.js Web Application (Coming Soon)
├── mobile/               # React Native Expo App (Coming Soon)
└── README.md
```

## ✨ Features

### 🔐 Authentication & User Management
- User registration and login
- JWT access and refresh tokens
- Google OAuth 2.0 integration
- Session management with device tracking
- Role-based access control (User, Moderator, Admin)
- Password security with bcrypt hashing

### 🎶 Core Features (Planned)
- Music streaming and playback
- Playlist creation and management
- Song search and discovery
- User profiles and preferences
- Social features (following, sharing)
- Audio quality settings
- Offline playback capability

### 📊 Admin Features
- User management dashboard
- Content moderation tools
- Analytics and reporting
- System monitoring

## 🚀 Getting Started

### Prerequisites
- Node.js (v18+ recommended)
- PostgreSQL database
- npm or yarn package manager

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd songify
   ```

2. **Install API dependencies**
   ```bash
   cd api
   npm install
   ```

3. **Environment Configuration**
   Create a `.env` file in the `api` directory:
   ```env
   # Database
   DATABASE_URL="postgresql://username:password@localhost:5432/songify"
   
   # JWT
   JWT_SECRET="your-super-secret-jwt-key"
   JWT_REFRESH_SECRET="your-super-secret-refresh-key"
   
   # Google OAuth
   GOOGLE_CLIENT_ID="your-google-client-id"
   GOOGLE_CLIENT_SECRET="your-google-client-secret"
   
   # App
   PORT=3000
   NODE_ENV=development
   ```

4. **Database Setup**
   ```bash
   # Run database migrations
   npm run db:push
   
   # Generate database client
   npm run db:generate
   ```

5. **Start the development server**
   ```bash
   npm run start:dev
   ```

6. **Access the API**
   - API: http://localhost:3000
   - Swagger Documentation: http://localhost:3000/api/docs

### Frontend Setup (Coming Soon)
Instructions for setting up the Next.js web application will be added when the frontend is implemented.

### Mobile Setup (Coming Soon)
Instructions for setting up the React Native Expo mobile application will be added when the mobile app is implemented.

## 📚 API Documentation

The API is fully documented using Swagger/OpenAPI. Once the server is running, visit:
- **Interactive API Docs**: http://localhost:3000/api/docs
- **JSON Schema**: http://localhost:3000/api/docs-json

### Key API Endpoints

#### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - User logout
- `GET /auth/profile` - Get user profile
- `GET /auth/google` - Google OAuth login

#### Users
- `GET /users/profile` - Get current user profile
- `PATCH /users/profile` - Update user profile

## 🔒 Security Features

- **JWT Authentication** with access/refresh token rotation
- **Password Hashing** using bcrypt with salt rounds
- **Session Management** with device tracking
- **CORS Protection** for cross-origin requests
- **Rate Limiting** to prevent abuse
- **Input Validation** using class-validator
- **Role-Based Access Control** for protected resources

## 🌟 Roadmap

### Phase 1: Foundation ✅
- [x] Backend API with NestJS
- [x] Authentication system
- [x] Database setup with PostgreSQL
- [x] API documentation with Swagger
- [x] User management

### Phase 2: Core Features (In Progress)
- [ ] Music upload and storage system
- [ ] Audio streaming capabilities
- [ ] Search and discovery features
- [ ] Playlist management

### Phase 3: Frontend Development
- [ ] Next.js web application
- [ ] Responsive design
- [ ] Music player interface
- [ ] User dashboard

### Phase 4: Mobile Development
- [ ] React Native Expo app
- [ ] Native audio playback
- [ ] Offline capabilities
- [ ] Push notifications

### Phase 5: Advanced Features
- [ ] Social features
- [ ] Recommendation engine
- [ ] Real-time features
- [ ] Analytics dashboard

## 🤝 Contributing

We welcome contributions to Songify! Please read our contributing guidelines and submit pull requests for any improvements.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Team

Built with ❤️ by the Songify development team.

## 🔗 Links

- [API Documentation](http://localhost:3000/api/docs)
- [Project Repository](https://github.com/your-username/songify)
- [Issue Tracker](https://github.com/your-username/songify/issues)

---

**Happy Coding! 🎵** 