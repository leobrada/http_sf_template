package env

import (
    "github.com/subosito/gotenv"
    "os"
    "errors"
    "fmt"
)

var (
    // TODO: make it dynamic not hard coded
    DATA_PLANE_SF_PRIVKEY string
    DATA_PLANE_SF_CERT string
    DATA_PLANE_PEP_CERT string
    DATA_PLANE_CA_ROOT_CERT string
    DATA_PLANE_NGINX_CERT string

    ROUTER_LISTEN_ADDR string
)

func GetCertAndKeyByEnvName(key_path, cert_path string) (pkey, cert string, err error) {
    if pkey, err = LoadEnv(key_path); err != nil {
        return
    }
    if cert, err = LoadEnv(cert_path); err != nil {
        return
    }
    return
}

func GetDataCertByEnvName(cert_path string) (cert string, err error) {
    if cert, err = LoadEnv(cert_path); err != nil {
        return
    }
    return
}

func LoadRouterListenAddr() {
    ROUTER_LISTEN_ADDR = LoadEnvWithDefault("ROUTER_LISTEN_ADDR", ":443")
}

func LoadEnv(key string) (string, error) {
    value, ok := os.LookupEnv(key)
    if !ok {
        return "", errors.New(fmt.Sprintf("Error: Could not load %s", key))
    }
    return value, nil
}

func LoadEnvWithDefault(key, _default string) string {
    if value, ok := os.LookupEnv(key); ok {
        return value
    }
    return _default
}

func InitEnv() error {
    err := gotenv.Load();
    return err
}
