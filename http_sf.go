package main

import (
    "crypto/tls"
    "log"
    "net/http"
    sec_utility "github.com/leobrada/golang_utility/security_utility"
    env "github.com/leobrada/http_sf_template/env"
    router "github.com/leobrada/http_sf_template/router"
)

// TODO: NEEDS AN UPDATED
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

// TODO: Put this method in an additional package
//func loadCertPool(cert_paths ...string) (cert_pool *x509.CertPool, err error)  {
//    cert_pool = x509.NewCertPool()
//    for _, cert_path := range cert_paths {
//        cert_pem, err := ioutil.ReadFile(cert_path)
//        if err != nil {
//            log.Print("Read Cert PEM: ", err)
//            return cert_pool, err
//        }
//        cert_pool.AppendCertsFromPEM(cert_pem)
//    }
//    return cert_pool, nil
//}

func main() {

    // HTTP PROXY
    // HTTP Default Transport 
    // TODO: MUST BE UPDATED
    certs_accepted_by_sf,_ := sec_utility.LoadCertPool(env.DATA_PLANE_CA_ROOT_CERT, env.DATA_PLANE_NGINX_CERT, env.DATA_PLANE_PEP_CERT)
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
