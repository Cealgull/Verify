package proto

type VerifyError interface {
	error
	Code() int
}
