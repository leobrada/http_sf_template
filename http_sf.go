package main

import (
    "crypto/tls"
    "log"
    "net/http"
    
    "github.com/leobrada/http_sf/env"
    "github.com/leobrada/http_sf/router"
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
    if env.DATA_PLANE_SF_CERT, env.DATA_PLANE_SF_PRIVKEY, err = env.GetCertAndKeyByEnvName("DATA_PLANE_SF_CERT", "DATA_PLANE_SF_PRIVKEY"); err != nil {
        log.Panicf("%v\n", err)
    }
    
    if env.PEP_CLIENT_KEY, env.PEP_CLIENT_CERT, err = env.GetCertAndKeyByEnvName("PEP_CLIENT_KEY", "PEP_CLIENT_CERT"); err != nil {
        log.Panicf("%v\n", err)
    }

    if env.DATA_PLANE_CA_ROOT_CERT, err = env.GetDataCertByEnvName("DATA_PLANE_CA_ROOT_CERT"); err != nil {
        log.Panicf("%v\n", err)
    }

    env.LoadRouterListenAddr()
}

func main() {
    certs_accepted_by_sf, _ := router.LoadCertPool(
         env.DATA_PLANE_CA_ROOT_CERT,
         )
         
    sf_cert, err := tls.LoadX509KeyPair(env.PEP_CLIENT_CERT, env.PEP_CLIENT_KEY)
    if err != nil {
        log.Panicf("%v\n", err)
    }
    
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
