package main

import (
    "io/ioutil"
    "crypto/tls"
    "crypto/x509"
    "log"
    "net/http"
    env "github.com/leobrada/http_sf_template/env" 
    router "github.com/leobrada/http_sf_template/router"
    service_function "github.com/leobrada/http_sf_template/service_function"
)

func init() {
  // Read config file
  err := env.LoadConfig("conf.yml")
  if err != nil {
    log.Fatal(err)
  }
}

// Read all accepted certificates from the configuration
func loadCaPool(fn env.Function_t) (ca_cert_pool *x509.CertPool, err error) {
  ca_cert_pool = x509.NewCertPool()
  err = nil
  var caRoot []byte

  // Read accepted certificates of all servers
  for _, acceptedCert := range fn.Accepted {
    caRoot, err = ioutil.ReadFile(acceptedCert)
    if err != nil {
      return
    }
    // Append a certificate to the pool
    ca_cert_pool.AppendCertsFromPEM(caRoot)
  }
  return
}

func main() {
    // Create all necessary parameters for the router
    
    // 1: Load SF Cert that is shown to other SFc and/or Services and/or PEP
    data_plane_sf_cert, err := tls.LoadX509KeyPair(
                                      env.Config.Functions[0].Crt,
                                      env.Config.Functions[0].Key)
    if err != nil {
        log.Panicf("%v\n", err)
    }

    // 2: Load the CA's root certificate that i used to sign the certs shown to the SF by other SFs and/or Services
    accepted_cert_pool, err := loadCaPool(env.Config.Functions[0])
    if err != nil {
        log.Panicf("%v\n", err)
    }
    
    // 3: Create Zero Trust Service Funtion
    sf_dummy := service_function.NewServiceFunction()
    router, err := router.NewRouter(data_plane_sf_cert, accepted_cert_pool, sf_dummy)
    if err != nil {
        log.Panicf("%v\n", err)
    }

    http.Handle("/", router)

    err = router.ListenAndServeTLS()
    if err != nil {
        log.Fatal("[Router]: ListenAndServeTLS", err)
    }
}
