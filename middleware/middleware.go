

type Middleware struct {
    dst_function string, // if empty mw is implementing the functionality
    // TODO: dst_pdp string, // indicates where the pdp is located
}

func NewMiddleware(_dst string) (*Middleware, error) {
    mw := new(Middleware)

    mw.dst = _dst
    // TODO: check if its reachable

    return mw, nil
}

/*
Router ==> (req, resp.writer) ==> Middlewarei(MFA) ==> (modified req) ==> Function(MFA)
                                                                            |
                                                                            |
Return error(ok or not ok) to router <==  Middleware <==  (http packet) <==
                                                |
                                                |
                Send response to client   <=====

Router ==> (req, resp.writer) ==> Middleware ==> retrieve userinfo from req; query pdp for userpw
                                                                    |
                                                                    |
                                                 ok or not ok    <==
*/

func (mw *Middleware) (req *http.Request) (error){
    
}

func (mw *Middleware) Evaluate(req *http.Request) (error){
    
}

func (mw *Middleware) ServeHTTP(req *http.Request) (error, bool){
    // TODO: implement
}
