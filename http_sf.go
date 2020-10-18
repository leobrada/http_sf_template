package main

import (
    "io/ioutil"
    "crypto/tls"
    "log"
    "net/http"
    env "github.com/leobrada/http_sf_template/env"
    router "github.com/leobrada/http_sf_template/router"
    service_function "github.com/leobrada/http_sf_template/service_function"
)

func init() {
    var err error
    if err = env.InitEnv(); err != nil {
        log.Panicf("%v\n", err)
    }

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
    // Create all necessary parameters for the router
    // 1: Load SF Cert that is shown to other SFc and/or Services and/or PEP
    data_plane_sf_cert, err := tls.LoadX509KeyPair(env.DATA_PLANE_SF_CERT, env.DATA_PLANE_SF_PRIVKEY)
    if err != nil {
        log.Panicf("%v\n", err)
    }
    // 2: Load the CA's root certificate that i used to sign the certs shown to the SF by other SFs and/or Services
    accepted_certs_pem, err := ioutil.ReadFile(env.DATA_PLANE_ACCEPTED_CERTS)
    if err != nil {
        log.Panicf("%v\n", err)
    }
    // 3: Create Zero Trust Service Funtion
    sf_dummy := service_function.NewServiceFunction()
    router, err := router.NewRouter(data_plane_sf_cert, accepted_certs_pem, sf_dummy)
    if err != nil {
        log.Panicf("%v\n", err)
    }

    http.Handle("/", router)

    err = router.ListenAndServeTLS()
    if err != nil {
        log.Fatal("[Router]: ListenAndServeTLS", err)
    }
}
