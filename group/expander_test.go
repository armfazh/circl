package group_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/xof"
)

func TestExpanderStream(t *testing.T) {
	in := []byte("input")
	dst := []byte("dst")
	max := uint16(75)

	xmdE, err := group.NewExpanderMD(crypto.SHA256, dst, max)
	test.CheckNoErr(t, err, "bad xmd expander creation")
	xofE, err := group.NewExpanderXOF(xof.SHAKE128, 0, dst, max)
	test.CheckNoErr(t, err, "bad xof expander creation")

	for _, exp := range []group.Expander{xmdE, xofE} {
		// Write input by byte
		for i := range in {
			n, err := exp.Write(in[i : i+1])
			test.CheckNoErr(t, err, "must be nil")
			test.CheckOk(n == 1, "must be one", t)
		}

		// Read using loop of read
		got := make([]byte, 80)
		for i := 0; i < 70; i += 10 {
			n, err := exp.Read(got[i : i+10])
			test.CheckNoErr(t, err, "must be nil")
			test.CheckOk(n == 10, "must be ten", t)
		}
		n, err := exp.Read(nil)
		test.CheckNoErr(t, err, "must be nil")
		test.CheckOk(n == 0, "must be zero", t)

		n, err = exp.Read(got[70:])
		test.CheckIsErr(t, err, "must be EOF")
		test.CheckOk(n == 5, "must be five", t)

		exp.Reset()

		// Write the whole input
		n, err = exp.Write(in)
		test.CheckNoErr(t, err, "")
		test.CheckOk(n == len(in), "", t)

		// Read nothing
		n, err = exp.Read(nil)
		test.CheckNoErr(t, err, "must be nil")
		test.CheckOk(n == 0, "must be zero", t)

		// Read using io.ReadAll
		want, err := io.ReadAll(exp)
		test.CheckNoErr(t, err, "must be nil")

		if !bytes.Equal(got[:max], want) {
			test.ReportError(t, got, want)
		}

		err = test.CheckPanic(func() { _, _ = exp.Write(in) })
		test.CheckNoErr(t, err, "must panic")
	}
}

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

func getExpander(t *testing.T, vs *vectorExpanderSuite, l uint16) (group.Expander, error) {
	switch vs.Hash {
	case "SHA256":
		return group.NewExpanderMD(crypto.SHA256, []byte(vs.DST), l)
	case "SHA512":
		return group.NewExpanderMD(crypto.SHA512, []byte(vs.DST), l)
	case "SHAKE128":
		return group.NewExpanderXOF(xof.SHAKE128, 0, []byte(vs.DST), l)
	case "SHAKE256":
		return group.NewExpanderXOF(xof.SHAKE256, 0, []byte(vs.DST), l)
	default:
		t.Skip("hash not supported: " + vs.Hash)
		return nil, nil
	}
}

func testExpander(t *testing.T, vs *vectorExpanderSuite) {
	for i, v := range vs.Tests {
		lenBytes, err := strconv.ParseUint(v.Len, 0, 64)
		test.CheckNoErr(t, err, "failed parsing output length")

		exp, err := getExpander(t, vs, uint16(lenBytes))
		test.CheckNoErr(t, err, "failed to create expander")

		_, err = exp.Write([]byte(v.Msg))
		test.CheckNoErr(t, err, "failed to write on expander")
		got, err := io.ReadAll(exp)
		test.CheckNoErr(t, err, "failed to read from expander")

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
	in := []byte("Input")
	dst := []byte("DST")

	for l := 256; l <= 1<<10; l += 256 {
		ll := uint16(l)

		b.Run("XMD/reader/"+fmt.Sprint(l), func(b *testing.B) {
			exp, _ := group.NewExpanderMD(crypto.SHA256, dst, ll)
			b.SetBytes(int64(ll))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				exp.Reset()
				_, _ = exp.Write(in)
				_, _ = io.ReadAll(exp)
			}
		})
		b.Run("XMD/exp/"+fmt.Sprint(l), func(b *testing.B) {
			exp, _ := group.NewExpanderMD(crypto.SHA256, dst, ll)
			b.SetBytes(int64(ll))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				exp.Expand(in, uint(ll))
			}
		})
		b.Run("XOF/reader/"+fmt.Sprint(l), func(b *testing.B) {
			exp, _ := group.NewExpanderXOF(xof.SHAKE128, 0, dst, ll)
			b.SetBytes(int64(ll))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				exp.Reset()
				_, _ = exp.Write(in)
				_, _ = io.ReadAll(exp)
			}
		})
		b.Run("XOF/exp/"+fmt.Sprint(l), func(b *testing.B) {
			exp, _ := group.NewExpanderXOF(xof.SHAKE128, 0, dst, ll)
			b.SetBytes(int64(ll))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				exp.Expand(in, uint(ll))
			}
		})
	}
}
