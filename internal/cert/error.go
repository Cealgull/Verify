package cert

import "net/http"

type InternalError struct{}

type UnauthorizedError struct{}

type BadRequestError struct{}

func (e *InternalError) Code() int {
	return http.StatusInternalServerError
}

func (e *InternalError) Error() string {
	return "Cert: InternalError"
}

func (e *UnauthorizedError) Code() int {
	return http.StatusUnauthorized
}

func (e *UnauthorizedError) Error() string {
	return "Cert: Certificate Not Signed by the Verification Server"
}

func (e *BadRequestError) Code() int {
	return http.StatusBadRequest
}

func (e *BadRequestError) Error() string {
	return "Cert: Certificate Bad Request"
}
