package service_function

import (
  "net/http"
)

type ServiceFunction interface {
  ApplyFunction(w http.ResponseWriter, req *http.Request) (forward bool)
}

/* Very simplistic example
type ServiceFunctionName struct {
    name string
    // TODO: dst_pdp string, // indicates where the pdp is located
}

func NewServiceFunction(name string) *ServiceFunctionName {
    return &ServiceFunctionName{name: name}
}

func (mw *ServiceFunctionName) ApplyFunction(w http.ResponseWriter, req *http.Request) bool {
    return true
}
*/
