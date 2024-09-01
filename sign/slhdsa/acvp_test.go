package slhdsa

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

type acvpHeader struct {
	VsID      int    `json:"vsId"`
	Algorithm string `json:"algorithm"`
	Mode      string `json:"mode"`
	Revision  string `json:"revision"`
	IsSample  bool   `json:"isSample"`
}

type acvpKeygenVector struct {
	acvpHeader
	TestGroups []struct {
		TgID         int           `json:"tgId"`
		TestType     string        `json:"testType"`
		ParameterSet string        `json:"parameterSet"`
		Tests        []keygenInput `json:"tests"`
	} `json:"testGroups"`
}

type keygenInput struct {
	TcID     int      `json:"tcId"`
	Deferred bool     `json:"deferred"`
	SkSeed   hexBytes `json:"skSeed"`
	SkPrf    hexBytes `json:"skPrf"`
	PkSeed   hexBytes `json:"pkSeed"`
	Sk       hexBytes `json:"sk"`
	Pk       hexBytes `json:"pk"`
}

type acvpSigGenPrompt struct {
	acvpHeader
	TestGroups []struct {
		TgID          int         `json:"tgId"`
		TestType      string      `json:"testType"`
		ParameterSet  string      `json:"parameterSet"`
		Deterministic bool        `json:"deterministic"`
		Tests         []signInput `json:"tests"`
	} `json:"testGroups"`
}

type signInput struct {
	TcID    int      `json:"tcId"`
	Sk      hexBytes `json:"sk"`
	MsgLen  int      `json:"messageLength"`
	Msg     hexBytes `json:"message"`
	AddRand hexBytes `json:"additionalRandomness,omitempty"`
}

type acvpSigGenResult struct {
	acvpHeader
	TestGroups []struct {
		TgID  int `json:"tgId"`
		Tests []struct {
			TcID      int      `json:"tcId"`
			Signature hexBytes `json:"signature"`
		} `json:"tests"`
	} `json:"testGroups"`
}

type acvpVerifyInput struct {
	acvpHeader
	TestGroups []struct {
		TgID         int           `json:"tgId"`
		TestType     string        `json:"testType"`
		ParameterSet string        `json:"parameterSet"`
		Tests        []verifyInput `json:"tests"`
	} `json:"testGroups"`
}

type verifyInput struct {
	TcID          int      `json:"tcId"`
	Pk            hexBytes `json:"pk"`
	MessageLength int      `json:"messageLength"`
	Message       hexBytes `json:"message"`
	Signature     hexBytes `json:"signature"`
	Reason        string   `json:"reason"`
}

type acvpVerifyResult struct {
	acvpHeader
	TestGroups []struct {
		TgID  int `json:"tgId"`
		Tests []struct {
			TcID       int  `json:"tcId"`
			TestPassed bool `json:"testPassed"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func TestACVP(t *testing.T) {
	t.Run("Keygen", testKeygen)
	t.Run("Sign", testSign)
	t.Run("Verify", testVerify)
}

func testKeygen(t *testing.T) {
	// https://github.com/usnistgov/ACVP-Server/tree/v1.1.0.35/gen-val/json-files/SLH-DSA-keyGen-FIPS205
	inputs := new(acvpKeygenVector)
	readVector(t, "testdata/keygen.json.zip", inputs)

	for _, group := range inputs.TestGroups {
		t.Run(fmt.Sprintf("TgID_%v", group.TgID), func(t *testing.T) {
			for ti := range group.Tests {
				t.Run(fmt.Sprintf("TcID_%v", group.Tests[ti].TcID), func(t *testing.T) {
					acvpKeygen(t, group.ParameterSet, &group.Tests[ti])
				})
			}
		})
	}
}

func testSign(t *testing.T) {
	// https://github.com/usnistgov/ACVP-Server/tree/v1.1.0.35/gen-val/json-files/SLH-DSA-sigGen-FIPS205
	inputs := new(acvpSigGenPrompt)
	readVector(t, "testdata/sigGen_prompt.json.zip", inputs)
	outputs := new(acvpSigGenResult)
	readVector(t, "testdata/sigGen_results.json.zip", outputs)

	for gi, group := range inputs.TestGroups {
		test.CheckOk(group.TgID == outputs.TestGroups[gi].TgID, "mismatch of TgID", t)

		t.Run(fmt.Sprintf("TgID_%v", group.TgID), func(t *testing.T) {
			for ti := range group.Tests {
				test.CheckOk(group.Tests[ti].TcID == outputs.TestGroups[gi].Tests[ti].TcID, "mismatch of TcID", t)

				t.Run(fmt.Sprintf("TcID_%v", group.Tests[ti].TcID), func(t *testing.T) {
					acvpSign(t, group.ParameterSet, &group.Tests[ti], outputs.TestGroups[gi].Tests[ti].Signature, group.Deterministic)
				})
			}
		})
	}
}

func testVerify(t *testing.T) {
	// https://github.com/usnistgov/ACVP-Server/tree/v1.1.0.35/gen-val/json-files/SLH-DSA-sigVer-FIPS205
	inputs := new(acvpVerifyInput)
	readVector(t, "testdata/verify_prompt.json.zip", inputs)
	outputs := new(acvpVerifyResult)
	readVector(t, "testdata/verify_results.json.zip", outputs)

	for gi, group := range inputs.TestGroups {
		test.CheckOk(group.TgID == outputs.TestGroups[gi].TgID, "mismatch of TgID", t)

		t.Run(fmt.Sprintf("TgID_%v", group.TgID), func(t *testing.T) {
			for ti := range group.Tests {
				test.CheckOk(group.Tests[ti].TcID == outputs.TestGroups[gi].Tests[ti].TcID, "mismatch of TcID", t)

				t.Run(fmt.Sprintf("TcID_%v", group.Tests[ti].TcID), func(t *testing.T) {
					acvpVerify(t, group.ParameterSet, &group.Tests[ti], outputs.TestGroups[gi].Tests[ti].TestPassed)
				})
			}
		})
	}
}

func acvpKeygen(t *testing.T, instanceName string, in *keygenInput) {
	t.Parallel()

	ins, err := InstanceByName(instanceName)
	test.CheckNoErr(t, err, "invalid instance name")
	params, err := ins.getParams()
	test.CheckNoErr(t, err, "getParams failed")

	sk, pk := slhKeyGenInternal(params, in.SkSeed, in.SkPrf, in.PkSeed)

	skGot, err := sk.MarshalBinary()
	test.CheckNoErr(t, err, "PrivateKey.MarshalBinary failed")

	if !bytes.Equal(skGot, in.Sk) {
		test.ReportError(t, skGot, in.Sk)
	}

	pkGot, err := pk.MarshalBinary()
	test.CheckNoErr(t, err, "PublicKey.MarshalBinary failed")

	if !bytes.Equal(pkGot, in.Pk) {
		test.ReportError(t, pkGot, in.Pk)
	}
}

func acvpSign(t *testing.T, instanceName string, in *signInput, wantSignature []byte, deterministic bool) {
	t.Parallel()

	ins, err := InstanceByName(instanceName)
	test.CheckNoErr(t, err, "invalid instance name")
	params, err := ins.getParams()
	test.CheckNoErr(t, err, "getParams failed")

	sk := &PrivateKey{Instance: ins}
	err = sk.UnmarshalBinary(in.Sk)
	test.CheckNoErr(t, err, "PrivateKey.UnmarshalBinary failed")

	addRand := sk.publicKey.seed
	if !deterministic {
		addRand = in.AddRand
	}

	gotSignature, err := slhSignInternal(params, sk, in.Msg, addRand)
	test.CheckNoErr(t, err, "slhSignInternal failed")

	if !bytes.Equal(gotSignature, wantSignature) {
		got := hex.EncodeToString(gotSignature[:10]) + " ... (more bytes)"
		want := hex.EncodeToString(wantSignature[:10]) + " ... (more bytes)"
		test.ReportError(t, got, want)
	}

	valid := slhVerifyInternal(params, &sk.publicKey, in.Msg, gotSignature)
	test.CheckOk(valid, "slhVerifyInternal failed", t)
}

func acvpVerify(t *testing.T, instanceName string, in *verifyInput, want bool) {
	ins, err := InstanceByName(instanceName)
	test.CheckNoErr(t, err, "invalid instance name")
	params, err := ins.getParams()
	test.CheckNoErr(t, err, "getParams failed")

	pk := &PublicKey{Instance: ins}
	err = pk.UnmarshalBinary(in.Pk)
	test.CheckNoErr(t, err, "PublicKey.UnmarshalBinary failed")

	got := slhVerifyInternal(params, pk, in.Message, in.Signature)

	if got != want {
		test.ReportError(t, got, want)
	}
}

type hexBytes []byte

func (b *hexBytes) UnmarshalJSON(data []byte) (err error) {
	var s string
	err = json.Unmarshal(data, &s)
	if err != nil {
		return
	}
	*b, err = hex.DecodeString(s)
	return
}

func readVector(t *testing.T, fileName string, vector interface{}) {
	zipFile, err := zip.OpenReader(fileName)
	test.CheckNoErr(t, err, "error opening file")
	defer zipFile.Close()

	jsonFile, err := zipFile.File[0].Open()
	test.CheckNoErr(t, err, "error opening unzipping file")
	defer jsonFile.Close()

	input, err := io.ReadAll(jsonFile)
	test.CheckNoErr(t, err, "error reading bytes")

	err = json.Unmarshal(input, &vector)
	test.CheckNoErr(t, err, "error unmarshalling JSON file")
}
