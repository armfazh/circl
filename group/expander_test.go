package group_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
)

func TestExpander(t *testing.T) {
	fileNames, err := filepath.Glob("./testdata/expand*.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, fileName := range fileNames {
		f, err := os.Open(fileName)
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(f)
		var v vectorExpanderSuite
		err = dec.Decode(&v)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()

		t.Run(v.Name+"/"+v.Hash, func(t *testing.T) { testExpander(t, &v) })
	}
}

func testExpander(t *testing.T, vs *vectorExpanderSuite) {
	var h crypto.Hash
	switch vs.Hash {
	case "SHA256":
		h = crypto.SHA256
	case "SHA512":
		h = crypto.SHA512
	default:
		t.Skip("hash not supported: " + vs.Hash)
	}

	var exp group.Expander
	if strings.Contains(vs.Name, "xmd") {
		exp = group.NewExpanderMD(h, []byte(vs.DST))
	} else if strings.Contains(vs.Name, "xof") {
		// not implemented yet
	} else {
		panic("expander not recognized")
	}

	for i, v := range vs.Tests {
		lenBytes, err := strconv.ParseUint(v.Len, 0, 64)
		if err != nil {
			t.Fatal(err)
		}

		got := exp.Expand([]byte(v.Msg), uint(lenBytes))
		want, err := hex.DecodeString(v.UniformBytes)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, i)
		}
	}
}

type vectorExpanderSuite struct {
	DST   string `json:"DST"`
	Hash  string `json:"hash"`
	Name  string `json:"name"`
	Tests []struct {
		DstPrime     string `json:"DST_prime"`
		Len          string `json:"len_in_bytes"`
		Msg          string `json:"msg"`
		MsgPrime     string `json:"msg_prime"`
		UniformBytes string `json:"uniform_bytes"`
	} `json:"tests"`
}
