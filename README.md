# Auth API Service

This is a REST API service for user authentication, including sign-up, sign-in, token authorization, token revocation, and token refresh functionality.

## Prerequisites

- Docker
- Docker Compose

## Curl commands

SignUP -- 
curl -X POST http://localhost:8080/signup \
-H "Content-Type: application/json" \
-d '{"email": "user@example.com", "password": "password123"}'

SignIN --
curl -X POST http://localhost:8080/signin \
-H "Content-Type: application/json" \
-d '{"email": "user@example.com", "password": "password123"}'

Refresh Token -- 
curl -X POST http://localhost:8080/refresh \
-H "Content-Type: application/json" \
-d '{"refresh_token": "your_refresh_token"}'

Logout--
curl -X POST http://localhost:8080/logout \
-H "Authorization: Bearer your_access_token"


Protected Route -- 
curl -X GET http://localhost:8080/protected \
-H "Authorization: Bearer your_access_token"