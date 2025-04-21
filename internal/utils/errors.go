package utils

import "errors"

var (
	ERROR_EMAIL_REGISTERED    = errors.New("Email already registered")
	ERROR_INVALID_CREDENTIALS = errors.New("Invalid credentials")
	ERROR_TOKEN_EXPIRED       = errors.New("Logged out (token already expired)")
	ERROR_NO_JTI              = errors.New("Logged out (no JTI)")
	ERROR_TOKEN_BEEN_REVOKED  = errors.New("Token has been revoked")
	ERROR_FAILED_TO_LOGOUT    = errors.New("Failed to log out")
)
