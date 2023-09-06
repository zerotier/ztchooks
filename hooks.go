// Copyright 2023 ZeroTier, Inc. All rights reserved.
// Use of this source code is governed by the Mozilla Public License Version 2.0
// license that can be found in the LICENSE file.

package ztchooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidSignatureHeader = errors.New("webhook has no signature header")
	ErrInvalidPreSharedKey    = errors.New("invalid pre shared key")
	ErrInvalidHeader          = errors.New("webhook has invalid header")
	ErrInvalidSignature       = errors.New("webhook has no valid signature")
	ErrTimestampExpired       = errors.New("timestamp has expired")
)

var (
	DefaultTolerance = 5 * time.Minute
)

type signedHeader struct {
	timestamp  time.Time
	signatures [][]byte
}

// GetHookType decodes the `HookBase` portion of the data to determine and return
// the `HookType`
func GetHookType(data []byte) (HookType, error) {
	var base HookBase
	if err := json.Unmarshal(data, &base); err != nil {
		return HOOK_TYPE_UNKNOWN, err
	}

	return base.HookType, nil
}

// VerifyHookSignature takes your pre-shared key, the value of the signature header, and the JSON payload
// and verifies the signature.  tolerance determines how large of a time difference to tolerate in order
// to prevent a replay attack
func VerifyHookSignature(preSharedKey, sigHeader string, payload []byte, tolerance time.Duration) error {
	header, err := parseHeader(sigHeader, tolerance)
	if err != nil {
		return err
	}

	expectedSig, err := generateExpectedSignature(header, preSharedKey, payload)
	if err != nil {
		return err
	}

	for _, sig := range header.signatures {
		if hmac.Equal(expectedSig, sig) {
			return nil
		}
	}

	return ErrInvalidSignature
}

func generateExpectedSignature(sh *signedHeader, preSharedKey string, payload []byte) ([]byte, error) {
	psk, err := hex.DecodeString(preSharedKey)
	if err != nil {
		return nil, ErrInvalidPreSharedKey
	}

	h := hmac.New(sha256.New, psk)
	h.Write([]byte(fmt.Sprintf("%d", sh.timestamp.Unix())))
	h.Write([]byte(","))
	h.Write(payload)
	return h.Sum(nil), nil
}

func parseHeader(sigHeader string, tolerance time.Duration) (*signedHeader, error) {
	var err error
	sh := &signedHeader{}

	if sigHeader == "" {
		return sh, ErrInvalidSignatureHeader
	}

	pairs := strings.Split(sigHeader, ",")
	sh, err = decode(sh, pairs, tolerance)
	if err != nil {
		return sh, err
	}

	if len(sh.signatures) == 0 {
		return sh, ErrInvalidSignature
	}

	return sh, nil
}

func decode(sh *signedHeader, pairs []string, tolerance time.Duration) (*signedHeader, error) {
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return sh, ErrInvalidHeader
		}

		item := parts[0]

		if item == "t" {
			timestamp, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return sh, ErrInvalidHeader
			}

			sh.timestamp = time.Unix(timestamp, 0)
			continue
		}

		if strings.Contains(item, "v") {
			sig, err := hex.DecodeString(parts[1])
			if err != nil {
				continue
			}

			sh.signatures = append(sh.signatures, sig)
		}
	}

	expiredTimestamp := time.Since(sh.timestamp) > tolerance
	if expiredTimestamp {
		return nil, ErrTimestampExpired
	}

	return sh, nil
}
