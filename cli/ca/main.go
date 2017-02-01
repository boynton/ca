package main

import (
	"fmt"
	"io/ioutil"
	"strings"
	"os"

	"github.com/boynton/ca"
)

func usage() {
	fmt.Println("usage: ca init")
	fmt.Println("       ca create identity")
	fmt.Println("       ca read identity")
	fmt.Println("       ca update identity")
	fmt.Println("       ca delete identity")
	fmt.Println("       ca list")
	os.Exit(0)
}

func fatal(msg string, args ...interface{}) {
	s := fmt.Sprintf(msg, args...)
	fmt.Printf("*** %s\n", s)
	os.Exit(1)
}

func info(msg string, args ...interface{}) {
	s := fmt.Sprintf(msg, args...)
	fmt.Printf("[%s]\n", s)
}


func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		cmd := args[0]
		switch cmd {
		case "init":
			if len(args) == 1 {
				caInit()
			}
		case "create":
			if len(args) == 2 {
				caCreate(args[1])
			}
		case "read":
			if len(args) == 2 {
				caRead(args[1])
			}
		case "update":
			if len(args) == 2 {
				caUpdate(args[1])
			}
		case "delete":
			if len(args) == 2 {
				caDelete(args[1])
			}
		case "list":
			caList()
		}
	}
	usage()
}

func caInit() {
	err := ca.EnsureDir()
	conf, err := ca.ReadConfig()
	if err != nil {
		conf, err = ca.GenerateDefaultConfig()
		if err != nil {
			fatal("Cannot create default config: %v", err)
		}
		err = ca.Init(conf)
		if err != nil {
			fatal("Cannot initialize CA: %v", err)
		}
		fmt.Printf("Initialized CA in '%s': %s\n", ca.Dir(), conf)
	} else {
		fmt.Printf("CA already set up in '%s': %s\n", ca.Dir(), conf)
	}
	os.Exit(0)
}

func caList() {
	infos, err := ioutil.ReadDir(ca.Dir())
	if err != nil {
		fmt.Println(" - not initialized -")
	} else {
		for _, info := range infos {
			n := info.Name()
			if strings.HasSuffix(n, ".key") {
				identity := n[:len(n)-4]
				fmt.Println(identity)
			}
		}
	}
	os.Exit(0)
}

func caCreate(identity string) {
	conf, err := ca.ReadConfig()
	if err != nil {
		fatal("Cannot read config: %v", err)
	}
	err = ca.CreateCert(conf, identity, "", "", "")
	if err != nil {
		fatal("Cannot create cert for '%s': %v", identity, err)
	}
	fmt.Printf("created cert for '%s'\n", identity)
	os.Exit(0)
}

func caUpdate(identity string) {
	conf, err := ca.ReadConfig()
	if err != nil {
		fatal("Cannot read config: %v", err)
	}
	err = ca.UpdateCert(conf, identity, "", "", "")
	if err != nil {
		fatal("Cannot update cert for '%s': %v", identity, err)
	}
	fmt.Printf("updated cert for '%s'\n", identity)
	os.Exit(0)
}

func caDelete(identity string) {
	if identity == "ca" {
		fatal("Cannot delete CA's cert")
	}
	_, err := ca.GetCert(identity)
	if err != nil {
		fatal("No such identity: %s", identity)
	}
	conf, err := ca.ReadConfig()
	if err != nil {
		fatal("Cannot read config: %v", err)
	}
	err = ca.DeleteCert(conf, identity)
	if err != nil {
		fatal("Cannot delete cert for '%s': %v", identity, err)
	}
	fmt.Printf("deleted cert for '%s'\n", identity)
	os.Exit(0)
}

func caRead(identity string) {
	cert, err := ca.GetCert(identity)
	if err != nil {
		fatal("Cannot read cert: %v\n", err)
	}
	info := ca.GetCertInfo(cert)
	fmt.Printf("  Version: %s\n", info["version"])
	fmt.Printf("  Serial Number: %s\n", info["serial-number"])
	fmt.Printf("  Signature algorithm: %s\n", info["signature-algorithm"])
	fmt.Printf("  Issuer: %s\n", info["issuer"])
	fmt.Printf("  Not valid before %s\n", info["not-before"])
	fmt.Printf("  Not valid after %s\n", info["not-after"])
	fmt.Printf("  Subject: %s\n", info["subject"])
	fmt.Printf("  Subject public key algorithm: %s\n", info["subject-pub-key-algo"])
	fmt.Printf("  Key Usage: %s\n", info["usage"])
	if b, ok := info["ca"]; ok && b == "true" {
		fmt.Printf("  CA: true\n")
	}
	os.Exit(0)
}
