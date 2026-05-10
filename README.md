# Advanced Authentication System

A complete backend authentication system built with Node.js, Express, MongoDB, JWT, Passport.js, OAuth, OTP verification, and Nodemailer.

---

# Features

- User Signup & Login
- JWT Authentication
- Refresh Tokens
- Google OAuth Login
- GitHub OAuth Login
- Email Verification
- OTP Verification
- Resend OTP
- Forgot Password
- Reset Password
- Protected Routes
- Admin Middleware
- Rate Limiting
- Secure Cookies
- Password Hashing with bcrypt
- Nodemailer Email Integration

---

# Tech Stack

- Node.js
- Express.js
- MongoDB
- Mongoose
- JWT
- Passport.js
- Google OAuth 2.0
- GitHub OAuth
- bcrypt
- Nodemailer
- Zod
- express-rate-limit

---

# Installation

Clone the repository:

bash id="w2r8kx" git clone YOUR_GITHUB_REPOSITORY_LINK 

Move into the project folder:

bash id="d6n3pv" cd PROJECT_NAME 

Install dependencies:

bash id="f9m1qt" npm install 

---

# Environment Variables

Create a .env file in the root directory and add the following:

env id="u4y7bc" MONGO_URL=  JWT_SECRET= JWT_REFRESH_SECRET=  GOOGLE_CLIENT_ID= GOOGLE_CLIENT_SECRET=  GITHUB_CLIENT_ID= GITHUB_CLIENT_SECRET=  SESSION_SECRET=  PORT=  NODE_ENV=  EMAIL_USER= EMAIL_PASS= 

You can use .env.example as a reference.

---

# Run the Project

Start the server:

bash id="e3x7na" node index.js 

Or with nodemon:

bash id="c8v2zl" npx nodemon index.js 

---

# API Routes

## Authentication

- POST /signup
- POST /login
- POST /logout
- POST /refresh

## OAuth

- GET /auth/google
- GET /auth/github

## Email Verification

- GET /verify/:token

## OTP

- POST /send-otp
- POST /verify-otp
- POST /resend-otp

## Password Reset

- POST /forgot-password
- POST /reset-password/:token

## Protected Routes

- GET /profile
- GET /admin

---

# Security Features

- Password hashing using bcrypt
- JWT Access & Refresh Tokens
- HTTP-only cookies
- Rate limiting
- Email verification
- OTP expiration
- Secure password reset tokens

---

# Future Improvements

- Role-Based Access Control
- Two-Factor Authentication
- Email Templates
- Redis Session Storage
- Docker Support
- API Documentation with Swagger
- Frontend Integration

---

# Author

Khushi