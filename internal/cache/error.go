package cache

type KeyError struct{}

func (e *KeyError) Error() string {
	return "Cache: Key Not Found"
}

type InternalError struct{}

func (e *InternalError) Error() string {
	return "Cache: Internal Connection Error"
}
