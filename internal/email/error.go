package email

import "net/http"

type DuplicateError struct{}
type AccountError struct{}
type CodeError struct{}
type InternalError struct{}
type NotFoundError struct{}

func (e *DuplicateError) Code() int {
	return http.StatusBadRequest
}

func (e *DuplicateError) Error() string {
	return "Email: Duplicated Email. Please resend after 3 minutes."
}

func (e *AccountError) Code() int {
	return http.StatusBadRequest
}

func (e *AccountError) Error() string {
	return "Email: Invalid Account Format."
}

func (e *CodeError) Code() int {
	return http.StatusBadRequest
}

func (e *CodeError) Error() string {
	return "Email: Invalid Validation Code Format."
}

func (e *InternalError) Code() int {
	return http.StatusInternalServerError
}

func (e *InternalError) Error() string {
	return "Email: Internal Server Error."
}

func (e *NotFoundError) Code() int {
	return http.StatusNotFound
}

func (e *NotFoundError) Error() string {
	return "Email: Account is not found or the code is already invalid."
}
