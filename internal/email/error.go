package email

import (
	"net/http"

	"github.com/Cealgull/Verify/internal/proto"
)

type DuplicateEmailError struct{}
type AccountFormatError struct{}
type CodeFormatError struct{}
type CodeIncorrectError struct{}
type EmailInternalError struct{}
type AccountNotFoundError struct{}
type EmailDialingError struct{}

func (e *DuplicateEmailError) Error() string {
	return "Email: Email Duplicated, Please verify or wait for another three minutes."
}

func (e *DuplicateEmailError) Status() int {
	return http.StatusBadRequest
}

func (e *DuplicateEmailError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A0110",
		Message: e.Error(),
	}
}

func (e *AccountFormatError) Error() string {
	return "Email: Account Format Incorrect."
}

func (e *AccountFormatError) Status() int {
	return http.StatusBadRequest
}

func (e *AccountFormatError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A0421",
		Message: e.Error(),
	}
}

func (e *AccountNotFoundError) Error() string {
	return "Email: User hasn't requested a verfication code or the code has expired."
}

func (e *AccountNotFoundError) Status() int {
	return http.StatusNotFound
}

func (e *AccountNotFoundError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A0201",
		Message: e.Error(),
	}
}

func (e *CodeFormatError) Error() string {
	return "Email: Verification Code Format Incorrect."
}

func (e *CodeFormatError) Status() int {
	return http.StatusBadRequest
}

func (e *CodeFormatError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A0422",
		Message: e.Error(),
	}
}

func (e *CodeIncorrectError) Error() string {
	return "Email: Verfication Code Incorrect."
}

func (e *CodeIncorrectError) Status() int {
	return http.StatusBadRequest
}

func (e *CodeIncorrectError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A0422",
		Message: e.Error(),
	}
}

func (e *EmailInternalError) Error() string {
	return "Email: Internal Server Error."
}

func (e *EmailInternalError) Status() int {
	return http.StatusInternalServerError
}

func (e *EmailInternalError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "E1001",
		Message: e.Error(),
	}
}

func (e *EmailDialingError) Error() string {
	return "Email: Dialing Service Report that email is not valid."
}

func (e *EmailDialingError) Status() int {
	return http.StatusInternalServerError
}

func (e *EmailDialingError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "E1002",
		Message: e.Error(),
	}
}
