package main

import (
    "crypto/tls"
    "log"
    "net/http"
    sec_utility "github.com/leobrada/golang_utility/security_utility"
    env "github.com/leobrada/http_sf_template/env"
    router "github.com/leobrada/http_sf_template/router"
)

func init() {
    var err error
    if err = env.InitEnv(); err != nil {
        log.Panicf("%v\n", err)
    }

    // TODO: write a helper function that can read in an arbitrary number of certificates 
    // Shown by the SF to other communication parties to authenticate itself. 
    if env.DATA_PLANE_SF_PRIVKEY, env.DATA_PLANE_SF_CERT, err = env.GetCertAndKeyByEnvName("DATA_PLANE_SF_PRIVKEY", "DATA_PLANE_SF_CERT"); err != nil {
        log.Panicf("%v\n", err)
    }

    // Certificates the SF acccepts or their signatures it accepts
    // Must concatenated in PEM format
    if env.DATA_PLANE_ACCEPTED_CERTS, err = env.GetCertByEnvName("DATA_PLANE_ACCEPTED_CERTS"); err != nil {
        log.Panicf("%v\n", err)
    }

    env.LoadRouterListenAddr()
}

func main() {

    // HTTP PROXY
    // HTTP Default Transport 
    certs_accepted_by_sf,_ := sec_utility.LoadCertPool(env.DATA_PLANE_ACCEPTED_CERTS)
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
