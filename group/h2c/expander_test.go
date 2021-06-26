package h2c_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cloudflare/circl/group/h2c"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/xof"
)

func TestExpanderStream(t *testing.T) {
	in := []byte("input")
	dst := []byte("dst")
	max := 100
	got := make([]byte, max)
	want := make([]byte, max)

	for ei, e := range []h2c.Expander{
		h2c.NewExpanderMD(crypto.SHA256, dst),
		h2c.NewExpanderXOF(xof.SHAKE128, 0, dst),
	} {
		exp := e

		// Write input by byte
		for i := range in {
			n, err := exp.Write(in[i : i+1])
			test.CheckNoErr(t, err, "must be nil")
			test.CheckOk(n == 1, "must be one", t)
		}

		exp.Expand(got)

		err := test.CheckPanic(func() { exp.Expand(nil) })
		test.CheckNoErr(t, err, "must panic after expand")

		exp.Reset()
		n, err := exp.Write(in)
		test.CheckNoErr(t, err, "must be nil")
		test.CheckOk(n == len(in), "must be one", t)
		exp.Expand(want)

		err = test.CheckPanic(func() { _, _ = exp.Write(nil) })
		test.CheckNoErr(t, err, "must panic after expand")

		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, ei)
		}
	}
}

func TestExpander(t *testing.T) {
	fileNames, err := filepath.Glob("./testdata/*.json")
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
	var exp h2c.Expander
	switch vs.Hash {
	case "SHA256":
		exp = h2c.NewExpanderMD(crypto.SHA256, []byte(vs.DST))
	case "SHA512":
		exp = h2c.NewExpanderMD(crypto.SHA512, []byte(vs.DST))
	case "SHAKE128":
		exp = h2c.NewExpanderXOF(xof.SHAKE128, 0, []byte(vs.DST))
	case "SHAKE256":
		exp = h2c.NewExpanderXOF(xof.SHAKE256, 0, []byte(vs.DST))
	default:
		t.Skip("hash not supported: " + vs.Hash)
	}

	for i, v := range vs.Tests {
		exp.Reset()

		_, err := exp.Write([]byte(v.Msg))
		test.CheckNoErr(t, err, "failed to write on expander")

		lenBytes, err := strconv.ParseUint(v.Len, 0, 64)
		test.CheckNoErr(t, err, "failed parsing output length")

		got := make([]byte, lenBytes)
		exp.Expand(got)

		want, err := hex.DecodeString(v.UniformBytes)
		test.CheckNoErr(t, err, "failed parsing output")

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

func BenchmarkExpander(b *testing.B) {
	in := []byte("input")
	dst := []byte("dst")

	for _, v := range []struct {
		Name string
		Exp  h2c.Expander
	}{
		{"XMD", h2c.NewExpanderMD(crypto.SHA256, dst)},
		{"XOF", h2c.NewExpanderXOF(xof.SHAKE128, 0, dst)},
	} {
		for l := 8; l <= 10; l++ {
			max := int64(1) << uint(l)
			bytes := make([]byte, max)

			b.Run(fmt.Sprintf("%v/%v", v.Name, max), func(b *testing.B) {
				b.SetBytes(max)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					v.Exp.Reset()
					_, _ = v.Exp.Write(in)
					v.Exp.Expand(bytes)
				}
			})
		}
	}
}
