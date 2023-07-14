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

func (e *DuplicateEmailError) Status() int {
	return http.StatusBadRequest
}

func (e *DuplicateEmailError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A0110",
		Message: "Email: Email Duplicated, Please verify or wait for another three minutes.",
	}
}

func (e *AccountFormatError) Status() int {
	return http.StatusBadRequest
}

func (e *AccountFormatError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A0421",
		Message: "Email: Account Format Incorrect.",
	}
}

func (e *AccountNotFoundError) Status() int {
	return http.StatusNotFound
}

func (e *AccountNotFoundError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A0201",
		Message: "Email: User hasn't requested a verfication code or the code has expired.",
	}
}

func (e *CodeFormatError) Status() int {
	return http.StatusBadRequest
}

func (e *CodeFormatError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A0422",
		Message: "Email: Verification Code Format Incorrect.",
	}
}

func (e *CodeIncorrectError) Status() int {
	return http.StatusBadRequest
}

func (e *CodeIncorrectError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A0422",
		Message: "Email: Verfication Code Incorrect.",
	}
}

func (e *EmailInternalError) Status() int {
	return http.StatusInternalServerError
}

func (e *EmailInternalError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "E1001",
		Message: "Email: Internal Server Error.",
	}
}

func (e *EmailDialingError) Status() int {
	return http.StatusInternalServerError
}

func (e *EmailDialingError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "E1002",
		Message: "Email: Dialing Service Report that email is not valid.",
	}
}
