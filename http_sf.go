package main

import (
    "io/ioutil"
    "crypto/x509"
    "crypto/tls"
    "log"
    "net/http"
    //"net/http/httputil"
    //"net/url"
    env "github.com/leobrada/http_sf/env"
    router "github.com/leobrada/http_sf/router"
)

// TODO: MUST BE UPDATED
func init() {
    var err error
    if err = env.InitEnv(); err != nil {
        log.Panicf("%v\n", err)
    }

    // Certificates used for communication with external hosts
    // TODO: make it dynamical not static
    // Used to authenticate to other communication parties
    if env.DATA_PLANE_SF_PRIVKEY, env.DATA_PLANE_SF_CERT, err = env.GetCertAndKeyByEnvName("DATA_PLANE_SF_PRIVKEY", "DATA_PLANE_SF_CERT"); err != nil {
        log.Panicf("%v\n", err)
    }

    if env.DATA_PLANE_PEP_CERT, err = env.GetDataCertByEnvName("DATA_PLANE_PEP_CERT"); err != nil {
        log.Panicf("%v\n", err)
    }

    if env.DATA_PLANE_CA_ROOT_CERT, err = env.GetDataCertByEnvName("DATA_PLANE_CA_ROOT_CERT"); err != nil {
        log.Panicf("%v\n", err)
    }

    if env.DATA_PLANE_NGINX_CERT, err = env.GetDataCertByEnvName("DATA_PLANE_NGINX_CERT"); err != nil {
        log.Panicf("%v\n", err)
    }

    env.LoadRouterListenAddr()
}

func loadCertPool(cert_paths ...string) (cert_pool *x509.CertPool, err error)  {
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

func main() {

    // HTTP PROXY
    // HTTP Default Transport 
    // TODO: MUST BE UPDATED
    certs_accepted_by_sf,_ := loadCertPool(env.DATA_PLANE_CA_ROOT_CERT, env.DATA_PLANE_NGINX_CERT, env.DATA_PLANE_PEP_CERT)
    sf_cert, err := tls.LoadX509KeyPair(env.DATA_PLANE_SF_CERT, env.DATA_PLANE_SF_PRIVKEY)

    // When the SF is acting as a client; this defines his behavior
    http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config {
        Certificates:       []tls.Certificate{sf_cert},
        InsecureSkipVerify: true,
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: certs_accepted_by_sf,
    }

    pep, err := router.NewRouter()
    if err != nil {
        log.Fatalln(err)
    }

    http.Handle("/", pep)

    err = pep.ListenAndServeTLS()
    if err != nil {
        log.Fatal("[Router]: ListenAndServeTLS", err)
    }
}
