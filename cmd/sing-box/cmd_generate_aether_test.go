package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/schema"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type failingWriter struct {
	err error
}

func (w failingWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

func executeMainCommand(args ...string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	mainCommand.SetOut(&stdout)
	mainCommand.SetErr(&stderr)
	mainCommand.SetArgs(args)
	defer func() {
		mainCommand.SetOut(nil)
		mainCommand.SetErr(nil)
		mainCommand.SetArgs(nil)
	}()
	err := mainCommand.Execute()
	return stdout.String(), err
}

func parseKeyPairOutput(t *testing.T, output string) (*ecdh.PrivateKey, *ecdh.PublicKey) {
	t.Helper()
	require.Len(t, output, 113)
	require.True(t, strings.HasSuffix(output, "\n"))
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	require.Len(t, lines, 2)

	privB64, ok := strings.CutPrefix(lines[0], "PrivateKey: ")
	require.True(t, ok)
	require.Len(t, privB64, 44)
	require.True(t, strings.HasSuffix(privB64, "="))

	pubB64, ok := strings.CutPrefix(lines[1], "PublicKey: ")
	require.True(t, ok)
	require.Len(t, pubB64, 44)
	require.True(t, strings.HasSuffix(pubB64, "="))

	privBytes, err := base64.StdEncoding.DecodeString(privB64)
	require.NoError(t, err)
	require.Len(t, privBytes, 32)
	require.NotEqual(t, make([]byte, 32), privBytes)

	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	require.NoError(t, err)
	require.Len(t, pubBytes, 32)
	require.NotEqual(t, make([]byte, 32), pubBytes)

	privKey, err := ecdh.X25519().NewPrivateKey(privBytes)
	require.NoError(t, err)
	pubKey, err := ecdh.X25519().NewPublicKey(pubBytes)
	require.NoError(t, err)
	require.True(t, privKey.PublicKey().Equal(pubKey))
	return privKey, pubKey
}

func TestGenerateAetherKeyCLIAndUniqueness(t *testing.T) {
	output, err := executeMainCommand("generate", "aether-key")
	require.NoError(t, err)
	require.Len(t, output, 45)
	require.True(t, strings.HasSuffix(output, "\n"))

	encoded := strings.TrimSuffix(output, "\n")
	require.Len(t, encoded, 44)
	require.True(t, strings.HasSuffix(encoded, "="))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	require.Len(t, decoded, 32)
	require.NotEqual(t, make([]byte, 32), decoded)

	seen := make(map[[32]byte]struct{}, 32)
	for range 32 {
		var buf bytes.Buffer
		require.NoError(t, generateAetherKey(&buf))
		line := strings.TrimSuffix(buf.String(), "\n")
		require.Len(t, line, 44)
		raw, decodeErr := base64.StdEncoding.DecodeString(line)
		require.NoError(t, decodeErr)
		require.Len(t, raw, 32)
		var key [32]byte
		copy(key[:], raw)
		_, duplicate := seen[key]
		require.False(t, duplicate)
		seen[key] = struct{}{}
	}
}

func TestGenerateAetherKeyPairCLIAndECDH(t *testing.T) {
	output1, err := executeMainCommand("generate", "aether-keypair")
	require.NoError(t, err)
	priv1, pub1 := parseKeyPairOutput(t, output1)

	var buf2 bytes.Buffer
	require.NoError(t, generateAetherKeyPair(&buf2))
	priv2, pub2 := parseKeyPairOutput(t, buf2.String())
	require.False(t, priv1.Equal(priv2))

	shared1, err := priv1.ECDH(pub2)
	require.NoError(t, err)
	shared2, err := priv2.ECDH(pub1)
	require.NoError(t, err)
	require.Len(t, shared1, 32)
	require.Equal(t, shared1, shared2)
}

func TestGenerateAetherCommandsRejectExtraArgs(t *testing.T) {
	outKey, err := executeMainCommand("generate", "aether-key", "unexpected")
	require.Error(t, err)
	require.NotContains(t, outKey, "=")

	outPair, err := executeMainCommand("generate", "aether-keypair", "unexpected")
	require.Error(t, err)
	require.NotContains(t, outPair, "PrivateKey:")
}

func TestGenerateAetherWriterError(t *testing.T) {
	t.Parallel()
	writeErr := errors.New("broken pipe")
	require.ErrorIs(t, generateAetherKey(failingWriter{err: writeErr}), writeErr)
	require.ErrorIs(t, generateAetherKeyPair(failingWriter{err: writeErr}), writeErr)
}

func TestResolveSecretBehavior(t *testing.T) {
	t.Parallel()
	secret, err := option.ResolveSecret("", "")
	require.NoError(t, err)
	require.Empty(t, secret)

	secret, err = option.ResolveSecret("only-password-value", "")
	require.NoError(t, err)
	require.Equal(t, "only-password-value", secret)

	secret, err = option.ResolveSecret("", "only-key-value-123")
	require.NoError(t, err)
	require.Equal(t, "only-key-value-123", secret)

	secret, err = option.ResolveSecret("matching-secret-16", "matching-secret-16")
	require.NoError(t, err)
	require.Equal(t, "matching-secret-16", secret)

	_, err = option.ResolveSecret("secret-one-16chars", "secret-two-16chars")
	require.Error(t, err)
	require.ErrorContains(t, err, "conflicting password and key")
}

func TestAetherConfigCipherAndSecretValidation(t *testing.T) {
	baseCtx := include.Context(context.Background())
	checkConfig := func(rawConfig string) error {
		options, err := sjson.UnmarshalExtendedContext[option.Options](baseCtx, []byte(rawConfig))
		if err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(service.ExtendContext(baseCtx))
		defer cancel()
		instance, err := box.New(box.Options{
			Context: ctx,
			Options: options,
		})
		if err == nil {
			_ = instance.Close()
		}
		return err
	}

	for _, cipher := range []string{"", "auto", "aes-256-gcm", "chacha20-poly1305"} {
		cipherField := ""
		if cipher != "" {
			cipherField = `,"cipher":"` + cipher + `"`
		}
		cfg := `{"log":{"disabled":true},"inbounds":[{"type":"aether","tag":"in","listen":"127.0.0.1","listen_port":10443,"key":"0123456789abcdef0123456789abcdef","time_window":"30s","handshake_timeout":"6s","heartbeat_interval":"30s"}],"outbounds":[{"type":"aether","tag":"out","server":"127.0.0.1","server_port":10443,"key":"0123456789abcdef0123456789abcdef"` + cipherField + `,"heartbeat_interval":"30s"}]}`
		require.NoError(t, checkConfig(cfg), "cipher=%q should be accepted", cipher)
	}

	err := checkConfig(`{"log":{"disabled":true},"outbounds":[{"type":"aether","tag":"out","server":"127.0.0.1","server_port":10443,"key":"0123456789abcdef0123456789abcdef","cipher":"aes-128-gcm"}]}`)
	require.Error(t, err)
	require.ErrorContains(t, err, "unsupported aether cipher")

	err = checkConfig(`{"log":{"disabled":true},"outbounds":[{"type":"aether","tag":"out","server":"127.0.0.1","server_port":10443,"password":"0123456789abcdef0123456789abcdef","key":"fedcba9876543210fedcba9876543210"}]}`)
	require.Error(t, err)
	require.ErrorContains(t, err, "conflicting password and key")

	err = checkConfig(`{"log":{"disabled":true},"inbounds":[{"type":"aether","tag":"in","listen":"127.0.0.1","listen_port":10443,"users":[{"name":"u1","password":"0123456789abcdef0123456789abcdef","key":"fedcba9876543210fedcba9876543210"}]}]}`)
	require.Error(t, err)
	require.ErrorContains(t, err, "conflicting password and key")
}

func TestAetherSchemaReflection(t *testing.T) {
	content, err := schema.Generate(include.Context(context.Background()), reflect.TypeFor[option.Options]())
	require.NoError(t, err)

	var root struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(content, &root))
	require.Contains(t, root.Defs, "AetherUser")
	require.Contains(t, root.Defs, "Duration")
	require.Contains(t, root.Defs, "InboundMultiplexOptions")
	require.Contains(t, root.Defs, "OutboundMultiplexOptions")

	findAetherVariant := func(unionRaw json.RawMessage) map[string]any {
		var union struct {
			OneOf []map[string]any `json:"oneOf"`
		}
		require.NoError(t, json.Unmarshal(unionRaw, &union))
		for _, variant := range union.OneOf {
			props, _ := variant["properties"].(map[string]any)
			typeProp, _ := props["type"].(map[string]any)
			if typeProp["const"] == "aether" {
				return props
			}
		}
		t.Fatal("aether variant not found in schema union")
		return nil
	}

	inboundProps := findAetherVariant(root.Defs["Inbound"])
	require.Contains(t, inboundProps, "password")
	require.Contains(t, inboundProps, "key")
	require.Contains(t, inboundProps, "users")
	require.Contains(t, inboundProps, "private_key")
	require.Contains(t, inboundProps, "time_window")
	require.Contains(t, inboundProps, "handshake_timeout")
	require.Contains(t, inboundProps, "heartbeat_interval")
	require.Contains(t, inboundProps, "disable_shaping")
	require.Contains(t, inboundProps, "multiplex")
	require.NotContains(t, inboundProps, "time_limit_ms")
	require.NotContains(t, inboundProps, "heartbeat_interval_sec")

	outboundProps := findAetherVariant(root.Defs["Outbound"])
	require.Contains(t, outboundProps, "network")
	require.Contains(t, outboundProps, "password")
	require.Contains(t, outboundProps, "key")
	require.Contains(t, outboundProps, "public_key")
	require.Contains(t, outboundProps, "heartbeat_interval")
	require.Contains(t, outboundProps, "disable_shaping")
	require.Contains(t, outboundProps, "multiplex")
	require.Contains(t, outboundProps, "udp_over_tcp")
	require.NotContains(t, outboundProps, "heartbeat_interval_sec")

	cipherProp, ok := outboundProps["cipher"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, []any{"auto", "aes-256-gcm", "chacha20-poly1305"}, cipherProp["enum"])
}
