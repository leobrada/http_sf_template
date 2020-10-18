package service_function

import (
  "net/http"
)

type ServiceFunction interface {
  ApplyFunction(w http.ResponseWriter, req *http.Request) (forward bool)
}

// Very simplistic example
type ServiceFunctionDummy struct {
    name string
}

func NewServiceFunction() ServiceFunctionDummy {
    return ServiceFunctionDummy{name: "dummy"}
}

func (mw ServiceFunctionDummy) ApplyFunction(w http.ResponseWriter, req *http.Request) (forward bool) {
    forward = true
    return forward
}
