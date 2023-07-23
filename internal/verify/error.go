package verify

import (
	"net/http"

	"github.com/Cealgull/Verify/internal/proto"
)

type SignatureMissingError struct{}
type GenericBindingError struct{}
type VerifySuccess struct{}

func (e *SignatureMissingError) Status() int {
	return http.StatusBadRequest
}

func (e *SignatureMissingError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "S0010",
		Message: e.Error(),
	}
}

func (e *SignatureMissingError) Error() string {
	return "Signature Missing in Header."
}

func (e *GenericBindingError) Status() int {
	return http.StatusBadRequest
}

func (e *GenericBindingError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "B0001",
		Message: e.Error(),
	}
}

func (e *GenericBindingError) Error() string {
	return "Request: Bad Request. Missing some request headers."
}

func (e *VerifySuccess) Status() int {
	return http.StatusOK
}

func (e *VerifySuccess) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "N0001",
		Message: e.Error(),
	}
}

func (e *VerifySuccess) Error() string {
	return "OK"
}
