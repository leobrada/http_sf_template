package router

import (
    "io/ioutil"
    "crypto/x509"
    "crypto/tls"
    "net/http"
    "net/http/httputil"
    "time"
    "fmt"
    "net/url"
    "log"
    
    env "github.com/leobrada/http_sf_template/env"
    service_function "github.com/leobrada/http_sf_template/service_function"
)

type Router struct {
    // SF tls config (server)
    tls_config *tls.Config
    frontend *http.Server
    
    // SF certificate and CA (when acts as a server)
    router_cert_when_acts_as_a_server    tls.Certificate 
    router_ca_pool_when_acts_as_a_server *x509.CertPool
    
    // SF certificate and CA (when acts as a client)
    router_cert_when_acts_as_a_client    tls.Certificate 
    router_ca_pool_when_acts_as_a_client *x509.CertPool
    
    // Service function to be called for every incoming HTTP request
    sf service_function.ServiceFunction
}

func NewRouter(_sf service_function.ServiceFunction) (*Router, error) {
    router := new(Router)
    router.sf = _sf
    
    router.initAllCertificates(&env.Config)
    
    router.tls_config = &tls.Config{
        Rand: nil,
        Time: nil,
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,
        SessionTicketsDisabled: true,
        Certificates: []tls.Certificate{router.router_cert_when_acts_as_a_server},
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: router.router_ca_pool_when_acts_as_a_server,
    }

    // Frontend Handlers
    mux := http.NewServeMux()
    mux.Handle("/", router)

    router.frontend = &http.Server {
        Addr: env.Config.Sf.Listen_addr,
        TLSConfig: router.tls_config,
        ReadTimeout: time.Second * 5,
        WriteTimeout: time.Second *5,
        Handler: mux,
    }
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

func (router *Router) SetUpSFC() bool {
    return true
}

func matchTLSConst(input uint16) string {
    switch input {
    // TLS VERSION
    case 0x0300:
        return "VersionSSL30"
    case 0x0301:
        return "VersionTLS10"
    case 0x0302:
        return "VersionTLS11"
    case 0x0303:
        return "VersionTLS12"
    case 0x0304:
        return "VersionTLS13"
    // TLS CIPHER SUITES
    case 0x0005:
        return "TLS_RSA_WITH_RC4_128_SHA"
    case 0x000a:
        return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    case 0x002f:
        return "TLS_RSA_WITH_AES_128_CBC_SHA"
    case 0x0035:
        return "TLS_RSA_WITH_AES_256_CBC_SHA"
    case 0x003c:
        return "TLS_RSA_WITH_AES_128_CBC_SHA256"
    case 0x009c:
        return "TLS_RSA_WITH_AES_128_GCM_SHA256"
    case 0x009d:
        return "TLS_RSA_WITH_AES_256_GCM_SHA384"
    case 0xc007:
        return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
    case 0xc009:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
    case 0xc00a:
        return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
    case 0x1301:
        return "TLS_AES_128_GCM_SHA256"
    case 0x1302:
        return "TLS_AES_256_GCM_SHA384"
    case 0x1303:
        return "TLS_CHACHA20_POLY1305_SHA256"
    case 0x5600:
        return "TLS_FALLBACK_SCSV"
    default:
        return "unsupported"
    }
}

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    forward := router.sf.ApplyFunction(w, req)
    if !forward {
        return
    }

    // ToDo: add extracting of the next hop address from the list of IPs
    
    dst := req.Header.Get("Sfp")
    req.Header.Del("Sfp")
    service_url, _ := url.Parse(dst)
    proxy := httputil.NewSingleHostReverseProxy(service_url)

    // When the PEP is acting as a client; this defines his behavior
    proxy.Transport = &http.Transport{
        TLSClientConfig: &tls.Config {
            Certificates: []tls.Certificate{router.router_cert_when_acts_as_a_client},
            InsecureSkipVerify: true,
            ClientAuth: tls.RequireAndVerifyClientCert,
            ClientCAs: router.router_ca_pool_when_acts_as_a_client,
        },
    }
    proxy.ServeHTTP(w, req)
}

func (router *Router) ListenAndServeTLS() error {
    return router.frontend.ListenAndServeTLS("","")
}

// Read all accepted certificates from the configuration
func loadCAPool(path string) (ca_cert_pool *x509.CertPool, ok bool) {
    ca_cert_pool = x509.NewCertPool()
    nginx_root_crt, err := ioutil.ReadFile(path)
    if err != nil {
        fmt.Printf("[Router.loadCAPool]: ReadFile: ", err)
        return ca_cert_pool, false
    }
    ca_cert_pool.AppendCertsFromPEM(nginx_root_crt)
    return ca_cert_pool, true
}

func (router *Router) initAllCertificates(conf *env.Config_t) {
    var err error
    var ok bool
    isErrorDetected := false

    // 1. Server section
    
    // 1.1: Load SF Cert that is shown when SF operates as a server
    router.router_cert_when_acts_as_a_server, err = tls.LoadX509KeyPair(
        env.Config.Sf.Server.Cert_shown_by_sf,
        env.Config.Sf.Server.Privkey_for_cert_shown_by_sf)
    if err!=nil {
        isErrorDetected = true
    }

    // 1.2: Load the CA's root certificate that was used to sign all incoming requests certificates
    router.router_ca_pool_when_acts_as_a_server, ok = loadCAPool(conf.Sf.Server.Certs_sf_accepts)
    if !ok {
        isErrorDetected = true
    }
    
    // 2. Client section
    
    // 2.1: Load SF Cert that is shown when SF operates as a client
    router.router_cert_when_acts_as_a_client, err = tls.LoadX509KeyPair(
        env.Config.Sf.Client.Cert_shown_by_sf,
        env.Config.Sf.Client.Privkey_for_cert_shown_by_sf)
    if err!=nil {
        isErrorDetected = true
    }

    // 2.2: Load the CA's root certificate that was used to sign certificates of the SF connection destination
    router.router_ca_pool_when_acts_as_a_client, ok = loadCAPool(conf.Sf.Client.Certs_sf_accepts)
    if !ok {
        isErrorDetected = true
    }
    
    if isErrorDetected {
        log.Fatal("[Router.initAllCertificates]: An error occurred during loading certificates. See details above.")
    }    
}
