package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

func init() {
	commandGenerate.AddCommand(commandGenerateAetherKey)
	commandGenerate.AddCommand(commandGenerateAetherKeyPair)
}

var commandGenerateAetherKey = &cobra.Command{
	Use:   "aether-key",
	Short: "Generate Aether master key",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		err := generateAetherKey(cmd.OutOrStdout())
		if err != nil {
			log.Fatal(err)
		}
	},
}

func generateAetherKey(out io.Writer) error {
	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return err
	}
	_, err = io.WriteString(out, base64.StdEncoding.EncodeToString(key[:])+"\n")
	return err
}

var commandGenerateAetherKeyPair = &cobra.Command{
	Use:   "aether-keypair",
	Short: "Generate Aether X25519 key pair",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		err := generateAetherKeyPair(cmd.OutOrStdout())
		if err != nil {
			log.Fatal(err)
		}
	},
}

func generateAetherKeyPair(out io.Writer) error {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	publicKey := privateKey.PublicKey()
	_, err = io.WriteString(
		out,
		"PrivateKey: "+base64.StdEncoding.EncodeToString(privateKey.Bytes())+"\n"+
			"PublicKey: "+base64.StdEncoding.EncodeToString(publicKey.Bytes())+"\n",
	)
	return err
}
