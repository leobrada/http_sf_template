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
    
    "github.com/leobrada/http_sf/env"
    "github.com/leobrada/http_sf/serviceFunction"
)

type Router struct {
    tls_config *tls.Config
    frontend *http.Server

    // Proxy used to assign new proxies to whenever a new request must be handled
    proxy *httputil.ReverseProxy
}

func NewRouter() (*Router, error) {
    // Load the CA's root certificate that i used to sign the certs shown to the SF by other SFs and/or Services
    // TODO: use loadCertPool() function from http_sf.go --> make new cert module for it that is providing x509 helper functions

    ca_root_cert_pool, _ := LoadCertPool(
         env.DATA_PLANE_CA_ROOT_CERT,
    )
    // Load SF Cert that is shown to other SFc and/or Services and/or PEP
    data_plane_sf_cert, err := tls.LoadX509KeyPair(env.DATA_PLANE_SF_CERT, env.DATA_PLANE_SF_PRIVKEY)
    if err != nil {
        log.Print("ReadFile: ", err)
        return nil, err
    }
    
    router := new(Router)

    router.tls_config = &tls.Config{
        Rand: nil,
        Time: nil,
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,
        SessionTicketsDisabled: true,
        Certificates: []tls.Certificate{data_plane_sf_cert},
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: ca_root_cert_pool,
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

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    fmt.Printf("Serving Request for %s\n", req.TLS.ServerName)
       
    // ONLY FOR TESTING
    // router.printRequest(w, req)
    // END TESTING

    // Check if its a POST request
    // Calling Middleware Dummy for Basic Authentication
    //if forward := middlewareDummy(w, req), !forward {
    //    return
    //}
    
    // BasicAuthSF := serviceFunction.NewServiceFunction("BasicAuth")
    // forward := BasicAuthSF.ApplyFunction(serviceFunction.BasicAuth, w, req)
    // if !forward {
        // return
    // }
    
    OneTimePassAuthSF := serviceFunction.NewServiceFunction("OneTimePassAuth")
    forward := OneTimePassAuthSF.ApplyFunction(serviceFunction.OneTimePassAuth, w, req)
    if !forward {
        return
    }

    //router.printRequest(w, req)
    //proxy, ok := router.proxies[req.TLS.ServerName]
    //if !ok {
    //    w.WriteHeader(503)
    //    return
    //}
    //proxy.ServeHTTP(w, req)
    //10.5.0.53
    nginx_service_url, _ := url.Parse("https://10.80.12.2/")
    router.proxy = httputil.NewSingleHostReverseProxy(nginx_service_url)
    router.proxy.ServeHTTP(w, req)
}

func (router *Router) ListenAndServeTLS() error {
    return router.frontend.ListenAndServeTLS("","")
}

func LoadCertPool(cert_paths ...string) (cert_pool *x509.CertPool, err error)  {
    cert_pool = x509.NewCertPool()
    for _, cert_path := range cert_paths {
        cert_pem, err := ioutil.ReadFile(cert_path)
        if err != nil {
            log.Print("Read Cert PEM: ", err)
            return cert_pool, err
        }
        cert_pool.AppendCertsFromPEM(cert_pem)
    }
    return cert_pool, nil
}
