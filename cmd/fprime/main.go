package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
)

// Config allows to create a package.
type Config struct {
	PkgName  string `json:"PkgName"`
	FullPath string `json:"FullPath"`
	PkgDoc   string `json:"PkgDoc"`
	Prime    string `json:"Prime"`
}

func (c *Config) load(fileName string) {
	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(buf, c)
	if err != nil {
		panic(err)
	}
}

func main() {
	var inFile, outFile string
	flag.StringVar(&inFile, "i", "", "name of the input json file")
	flag.StringVar(&outFile, "o", "", "name of the output go file")
	flag.Parse()
	if inFile == "" || outFile == "" {
		flag.Usage()
		return
	}

	var pk pkgBuilder
	pk.Cfg.load(inFile)
	pk.process()
	pk.render(outFile)
}
