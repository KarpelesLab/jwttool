package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/KarpelesLab/hsm"
	"github.com/KarpelesLab/jwt"
)

func main() {
	if len(os.Args) <= 1 {
		fmt.Printf("Usage: %s command\n", os.Args[0])
		return
	}
	clusterName := os.Getenv("CLUSTER")
	if clusterName == "" {
		clusterName = "default"
	}

	h, err := hsm.New()
	if err != nil {
		log.Printf("failed to initialize HSM: %s", err)
		os.Exit(1)
	}

	ks, err := h.ListKeysByName("seidan:" + clusterName)
	if err != nil {
		log.Printf("failed to list HSM keys: %s", err)
		os.Exit(1)
	} else if len(ks) == 0 {
		// Generate?
		// NOTE: ecdsa, rsa only
		log.Printf("failed to list HSM keys: no keys. Please generate one.")
		os.Exit(1)
	}
	k := ks[0]

	log.Printf("found key: %s", k)

	switch strings.ToLower(os.Args[1]) {
	case "gen":
		// generate new signed jwt for a given host
		// params: name subject(the host's key in base64url format) expiration(in days, optional)
		if len(os.Args) <= 3 {
			fmt.Printf("Usage: %s gen name key [expiration]\n", os.Args[0])
			os.Exit(1)
		}
		name := os.Args[2]
		key := os.Args[3]
		exp := 0
		if len(os.Args) > 4 {
			exp, err = strconv.Atoi(os.Args[4])
			if err != nil {
				log.Printf("error: %s", err)
				os.Exit(1)
			}
		}

		// decode key
		keyBin, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil {
			log.Printf("error: %s", err)
			os.Exit(1)
		}

		// parse key
		_, err = x509.ParsePKIXPublicKey(keyBin)
		if err != nil {
			log.Printf("error: %s", err)
			os.Exit(1)
		}

		// generate jwt
		kid := k.Public()

		var jwtAlgo jwt.Algo
		switch kid.(type) {
		case *rsa.PublicKey:
			jwtAlgo = jwt.RS256
		case *ecdsa.PublicKey:
			jwtAlgo = jwt.ES256
		case ed25519.PublicKey:
			jwtAlgo = jwt.EdDSA
		default:
			log.Printf("unsupported key type %T", kid)
			os.Exit(1)
		}

		kidBin, err := x509.MarshalPKIXPublicKey(kid)
		if err != nil {
			log.Printf("error: %s", err)
			os.Exit(1)
		}

		token := jwt.New(jwtAlgo)
		token.Header().Set("kid", base64.RawURLEncoding.EncodeToString(kidBin))
		token.Payload().Set("iss", clusterName)
		token.Payload().Set("iat", time.Now().Unix())
		token.Payload().Set("sub", key)
		token.Payload().Set("nam", name)
		token.Payload().Set("aud", "directory.atonline.com")
		if exp > 0 {
			token.Payload().Set("exp", time.Now().Add(time.Duration(exp)*24*time.Hour).Unix())
		}
		res, err := token.Sign(k)
		if err != nil {
			log.Printf("error: %s", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", res)
		// success
		return
	default:
		log.Printf("no valid command provided")
	}
}
