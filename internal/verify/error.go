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
		Message: "Signature Missing in Header",
	}
}

func (e *GenericBindingError) Status() int {
	return http.StatusBadRequest
}

func (e *GenericBindingError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "B0001",
		Message: "Request: Bad Request",
	}
}

func (e *VerifySuccess) Status() int {
	return http.StatusOK
}

func (e *VerifySuccess) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "N0001",
		Message: "OK",
	}
}
