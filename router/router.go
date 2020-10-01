package router

import (
    "net/url"
    "crypto/tls"
    "net/http"
    "net/http/httputil"
    "time"
    "fmt"
    "io/ioutil"
    "log"
    "crypto/x509"
    env "github.com/leobrada/http_sf/env"
)

type Router struct {
    tls_config *tls.Config
    frontend *http.Server

    // Middle that processes the packets before forwarded to the proxy
    // TODO: Middleware
    //mws []*middleware.Middleware

    // Proxy used to assign new proxies to whenever a new request must behandled
    proxy *httputil.ReverseProxy
}

func NewRouter() (*Router, error) {
    // Load SF Cert that is shown to other SFc and/or Services and/or PEP
    data_plane_sf_cert, err := tls.LoadX509KeyPair(env.DATA_PLANE_SF_CERT, env.DATA_PLANE_SF_PRIVKEY)

    // Load the CA's root certificate that i used to sign the certs shown to the SF by other SFs and/or Services
    // TODO: use loadCertPool() function from http_sf.go --> make new cert module for it that is providing x509 helper functions
    CA_root_crt, err := ioutil.ReadFile(env.DATA_PLANE_CA_ROOT_CERT)
    if err != nil {
        log.Print("ReadFile: ", err)
        return nil, err
    }

    nginx_crt, err := ioutil.ReadFile(env.DATA_PLANE_NGINX_CERT)
    if err != nil {
        log.Print("ReadFile: ", err)
        return nil, err
    }

    pep_crt, err := ioutil.ReadFile(env.DATA_PLANE_PEP_CERT)
    if err != nil {
        log.Print("ReadFile: ", err)
        return nil, err
    }

    ca_root_cert_pool := x509.NewCertPool()
    ca_root_cert_pool.AppendCertsFromPEM(CA_root_crt)
    ca_root_cert_pool.AppendCertsFromPEM(nginx_crt)
    ca_root_cert_pool.AppendCertsFromPEM(pep_crt)

    router := new(Router)

    router.tls_config = &tls.Config{
        Rand: nil,
        Time: nil,
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,
        SessionTicketsDisabled: true,
        Certificates: nil,
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: ca_root_cert_pool,
        GetCertificate: func(cli *tls.ClientHelloInfo) (*tls.Certificate, error) {
                            // TODO: Can SNI extension contain an IP addr?
                            return &data_plane_sf_cert, nil
                        },
    }

    router.frontend = &http.Server {
        Addr: env.ROUTER_LISTEN_ADDR,
        TLSConfig: router.tls_config,
        ReadTimeout: time.Second * 5,
        WriteTimeout: time.Second *5,
    }

    return router, nil
}

// Printing request details
// ONLY FOR TESTING
func (router *Router) printRequest(w http.ResponseWriter, req *http.Request) {
    fmt.Printf("Method: %s\n", req.Method)
    fmt.Printf("URL: %s\n", req.URL)
    fmt.Printf("Protocol Version: %d.%d\n", req.ProtoMajor, req.ProtoMinor)
    fmt.Println("===================HEADER FIELDS=======================")
    for key, value := range req.Header {
        fmt.Printf("%s: %v\n", key, value)
    }
    fmt.Println("==========================================")
    fmt.Printf("Body: %s\n", "TBD")
    fmt.Printf("Content Length: %d\n", req.ContentLength)
    fmt.Printf("Transfer Encoding: %v\n", req.TransferEncoding)
    fmt.Printf("Close: %v\n", req.Close)
    fmt.Printf("Host: %s\n", req.Host)
    fmt.Println("====================FORM======================")
    if err := req.ParseForm(); err == nil {
        for key, value := range req.Form {
            fmt.Printf("%s: %v\n", key, value)
        }
    }
    fmt.Println("==========================================")
    fmt.Println("====================POST FORM======================")
    for key, value := range req.PostForm {
        fmt.Printf("%s: %v\n", key, value)
    }
    fmt.Println("==========================================")
    fmt.Println("====================MULTIPART FORM======================")
    if err := req.ParseMultipartForm(100); err == nil {
        for key, value := range req.MultipartForm.Value {
            fmt.Printf("%s: %v\n", key, value)
        }
    }
    fmt.Println("==========================================")
    fmt.Println("===================TRAILER HEADER=======================")
    for key, value := range req.Trailer {
        fmt.Printf("%s: %v\n", key, value)
    }
    fmt.Println("==========================================")
    fmt.Printf("Remote Address: %s\n", req.RemoteAddr)
    fmt.Printf("Request URI: %s\n", req.RequestURI)
    fmt.Printf("TLS: %s\n", "TBD")
    fmt.Printf("Cancel: %s\n", "TBD")
    fmt.Printf("Reponse: %s\n", "TBD")
}
// END TESTING
func middlewareDummy(w http.ResponseWriter, req *http.Request) (bool){
    var username, password string
    form := `<html>
            <body>
            <form action="/" method="post">
            <label for="fname">Username:</label>
            <input type="text" id="username" name="username"><br><br>
            <label for="lname">Password:</label>
            <input type="password" id="password" name="password"><br><br>
            <input type="submit" value="Submit">
            </form>
            </body>
            </html>
            `

    _, err := req.Cookie("Username")
    if err != nil {
        if req.Method =="POST" {
            if err := req.ParseForm(); err != nil {
                fmt.Println("Parsing Error")
                w.WriteHeader(401)
                w.Header().Set("Content-Type", "text/html; charset=utf-8")
                fmt.Fprintf(w, form)
                return false
            }

            nmbr_of_postvalues := len(req.PostForm)
            if nmbr_of_postvalues != 2 {
                fmt.Println("Too many Post Form Values")
                w.WriteHeader(401)
                w.Header().Set("Content-Type", "text/html; charset=utf-8")
                fmt.Fprintf(w, form)
                return false
            }

            usernamel, exist := req.PostForm["username"]
            username = usernamel[0]
            if !exist || username != "alex" {
                fmt.Println("username not present or wrong")
                w.WriteHeader(401)
                w.Header().Set("Content-Type", "text/html; charset=utf-8")
                fmt.Fprintf(w, form)
                return false
            }

            passwordl, exist := req.PostForm["password"]
            password = passwordl[0]
            if !exist || password != "test" {
                fmt.Println("password not present or wrong")
                w.WriteHeader(401)
                w.Header().Set("Content-Type", "text/html; charset=utf-8")
                fmt.Fprintf(w, form)
                return false
            }

            cookie := http.Cookie{
                Name: "Username",
                Value: username,
                MaxAge: 10,
                Path: "/",
            }
            http.SetCookie(w, &cookie)
            http.Redirect(w, req, "https://service1.testbed.informatik.uni-ulm.de", 303)
            return true

        } else {
            fmt.Println("only post methods are accepted in this state")
            w.WriteHeader(401)
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            fmt.Fprintf(w, form)
            return false
        }
    }
    return true
}

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    fmt.Printf("Serving Request for %s\n", req.TLS.ServerName)
    // ONLY FOR TESTING
    // router.printRequest(w, req)
    // END TESTING

    // Check if its a POST request
    // Calling Middleware Dummy for Basic Authentication
    //if forward := middlewareDummy(w, req), forward == false {
    //    return
    //}
    //forward := middlewareDummy(w, req)
    //if !forward {
    //    return
    //}

    //router.printRequest(w, req)
    //proxy, ok := router.proxies[req.TLS.ServerName]
    //if !ok {
    //    w.WriteHeader(503)
    //    return
    //}
    //proxy.ServeHTTP(w, req)
    //10.5.0.53
    nginx_service_url, _ := url.Parse("https://10.5.0.53/")
    router.proxy = httputil.NewSingleHostReverseProxy(nginx_service_url)
    router.proxy.ServeHTTP(w, req)
}

func (router *Router) ListenAndServeTLS() error {
    return router.frontend.ListenAndServeTLS("","")
}

