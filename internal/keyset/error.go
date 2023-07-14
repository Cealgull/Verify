package keyset

import (
	"net/http"

	"github.com/Cealgull/Verify/internal/proto"
)

type SignatureDecodeError struct{}
type SignatureVerificationError struct{}

func (e *SignatureVerificationError) Status() int {
	return http.StatusUnauthorized
}

func (e *SignatureVerificationError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A9999",
		Message: "Signature: Message Verification Failure.",
	}
}

func (e *SignatureDecodeError) Status() int {
	return http.StatusBadRequest
}

func (e *SignatureDecodeError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A9998",
		Message: "Signature: Signature Decode Error",
	}
}
