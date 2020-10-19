package env

import (
    "os"
    "gopkg.in/yaml.v2"
)

type Function_t struct {
  Dns           string  `yaml:"dns"`
  Ip            string  `yaml:"ip"`
  Crt           string  `yaml:"crt"`
  Key           string  `yaml:"key"`
  Accepted    []string  `yaml:"accepted"`
  Http_header   string  `yaml:"http_header"`
}

type Config_t struct {
  Functions []Function_t
  Listen_port  string  `yaml:"listen_port"`
}

var Config Config_t

// Parses a configuration yaml file into the global Config variable
func LoadConfig(configPath string) (err error) {
    // Open config file
    file, err := os.Open(configPath)
    if err != nil {
        return
    }
    defer file.Close()
    
    // Init new YAML decode
    d := yaml.NewDecoder(file)

    // Start YAML decoding from file
    err = d.Decode(&Config)
    return
}