package cert

import (
	"net/http"

	"github.com/Cealgull/Verify/internal/proto"
)

type CertDecodeError struct{}
type CertFormatError struct{}
type CertUnauthorizedError struct{}
type CertInternalError struct{}
type PubDecodeError struct{}
type PubFormatError struct{}
type BadRequestError struct{}
type FileInternalError struct{}
type FileFormatError struct{}
type FileDecodeError struct{}

func (e *PubFormatError) Status() int {
	return http.StatusBadRequest
}

func (e *PubFormatError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "P1001",
		Message: "PK: Public Key Decode Error.",
	}
}
func (e *PubDecodeError) Status() int {
	return http.StatusBadRequest
}

func (e *PubDecodeError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "P1002",
		Message: "PK: Public Key Format Not Matched With ed25519.",
	}
}

func (e *CertInternalError) Status() int {
	return http.StatusInternalServerError
}

func (e *CertInternalError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "C1001",
		Message: "Cert: Internal Server Error",
	}
}

func (e *CertDecodeError) Status() int {
	return http.StatusBadRequest
}

func (e *CertDecodeError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "C1002",
		Message: "Cert: Certifiate Decode Error. Please verify your input.",
	}
}

func (e *CertFormatError) Status() int {
	return http.StatusBadRequest
}

func (e *CertFormatError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "C1003",
		Message: "Cert: Certifiate Format Error. Please verify your input.",
	}
}

func (e *CertUnauthorizedError) Status() int {
	return http.StatusUnauthorized
}

func (e *CertUnauthorizedError) Message() *proto.ResponseMessage {
	return &proto.ResponseMessage{
		Code:    "A0240",
		Message: "Cert: Unauthorized Certificate. Not Signed by Verify.",
	}
}

func (e *FileInternalError) Error() string {
	return "Filesystem: Internal Server Error."
}

func (e *FileDecodeError) Error() string {
	return "Filesystem: Pem File Decode Error."
}

func (e *FileFormatError) Error() string {
	return "Filesystem: Pem Type Decode Error."
}
