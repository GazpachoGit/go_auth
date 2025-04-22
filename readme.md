# go_auth

## Description

Web-authentication app (JWT token) written in Golang. User profiles are stored in Postgres. Token Blacklist is stored in Redis

## Run

```
docker-compose up -d
cd ./cmd
go run main.go
```

## api

- POST 0.0.0.0:8081/api/v1/register - register a new user
- POST 0.0.0.0:8081/api/v1/login - login with a token
- GET 0.0.0.0:8081/api/v1/profile - get user info(token required)
- POST 0.0.0.0:8081/api/v1/logout - put token to the blacklist
