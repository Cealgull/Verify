package proto

type ResponseMessage struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type VerifyError interface {
	Message() *ResponseMessage
	Status() int
}
