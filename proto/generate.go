package proto

//go:generate buf lint
//go:generate buf format -w
//go:generate buf generate
//go:generate mv ./kit/errors/v1/error_reason.gen_errors.go ../errors/
