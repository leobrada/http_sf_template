package main

import (
    "log"
    "flag"
    "net/http"
    env "github.com/leobrada/http_sf_template/env" 
    router "github.com/leobrada/http_sf_template/router"
    service_function "github.com/leobrada/http_sf_template/service_function"
)

var (
    conf_file_path = flag.String("c", "./conf.yml", "Path to user defined yml config file")
)

func init() {
    flag.Parse()

    err := env.LoadConfig(*conf_file_path)
    if err != nil {
        log.Fatal(err)
    }
}

func main() {
    // Create Zero Trust Service Function
    sf_dummy := service_function.NewServiceFunction()

    router, err := router.NewRouter(sf_dummy)
    if err != nil {
        log.Panicf("%v\n", err)
    }

    http.Handle("/", router)

    err = router.ListenAndServeTLS()
    if err != nil {
        log.Fatal("[Router]: ListenAndServeTLS", err)
    }
}
