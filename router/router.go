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
    env "github.com/leobrada/http_sf_template/env"
    service_function "github.com/leobrada/http_sf_template/service_function"
)

type Router struct {
    tls_config *tls.Config
    frontend *http.Server

    sf service_function.ServiceFunction

    // Proxy variable used to assign new proxies to whenever a new request must behandled
    proxy *httputil.ReverseProxy
}

func NewRouter(_sf service_function.ServiceFunction) (*Router, error) {
    // Load SF Cert that is shown to other SFc and/or Services and/or PEP
    data_plane_sf_cert, err := tls.LoadX509KeyPair(env.DATA_PLANE_SF_CERT, env.DATA_PLANE_SF_PRIVKEY)

    // Load the CA's root certificate that i used to sign the certs shown to the SF by other SFs and/or Services
    accepted_certs, err := ioutil.ReadFile(env.DATA_PLANE_ACCEPTED_CERTS)
    if err != nil {
        log.Print("ReadFile: ", err)
        return nil, err
    }
    accepted_certs_pool := x509.NewCertPool()
    accepted_certs_pool.AppendCertsFromPEM(accepted_certs)

    router := new(Router)

    router.tls_config = &tls.Config{
        Rand: nil,
        Time: nil,
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,
        SessionTicketsDisabled: true,
        Certificates: nil,
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: accepted_certs_pool,
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

    router.sf = _sf

    return router, nil
}

// Printing request details
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

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    fmt.Printf("Serving Request for %s\n", req.TLS.ServerName)

    forward := router.sf.ApplyFunction(w, req)
    if !forward {
        return
    }

    dst := req.Header.Get("sf1")
    req.Header.Del("sf1")
    nginx_service_url, _ := url.Parse(dst)
    router.proxy = httputil.NewSingleHostReverseProxy(nginx_service_url)
    router.proxy.ServeHTTP(w, req)
}

func (router *Router) ListenAndServeTLS() error {
    return router.frontend.ListenAndServeTLS("","")
}
