package slhdsa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

type acvpKeygen struct {
	VsID       int    `json:"vsId"`
	Algorithm  string `json:"algorithm"`
	Mode       string `json:"mode"`
	Revision   string `json:"revision"`
	IsSample   bool   `json:"isSample"`
	TestGroups []struct {
		TgID         int    `json:"tgId"`
		TestType     string `json:"testType"`
		ParameterSet string `json:"parameterSet"`
		Tests        []struct {
			TcID     int      `json:"tcId"`
			Deferred bool     `json:"deferred"`
			SkSeed   hexBytes `json:"skSeed"`
			SkPrf    hexBytes `json:"skPrf"`
			PkSeed   hexBytes `json:"pkSeed"`
			Sk       hexBytes `json:"sk"`
			Pk       hexBytes `json:"pk"`
		} `json:"tests"`
	} `json:"testGroups"`
}

type hexBytes []byte

func (b hexBytes) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(b)) }
func (b *hexBytes) UnmarshalJSON(data []byte) (err error) {
	var s string
	if err = json.Unmarshal(data, &s); err != nil {
		return err
	}
	*b, err = hex.DecodeString(s)
	return err
}

func readVector(t *testing.T, fileName string, vector interface{}) {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, err := io.ReadAll(jsonFile)
	if err != nil {
		t.Fatalf("File %v can not be read. Error: %v", fileName, err)
	}

	err = json.Unmarshal(input, &vector)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}
}

func testKeygen(t *testing.T) {
	vectors := new(acvpKeygen)
	readVector(t, "testdata/keygen.json", vectors)

	for _, group := range vectors.TestGroups {
		ins, err := InstanceByName(group.ParameterSet)
		test.CheckNoErr(t, err, "invalid instance name")
		state, err := ins.newState()
		test.CheckNoErr(t, err, "newState failed")

		t.Run(fmt.Sprintf("TgID_%v", group.TgID), func(t *testing.T) {
			for _, v := range group.Tests {
				t.Run(fmt.Sprintf("TcID_%v", v.TcID), func(t *testing.T) {
					sk, pk := state.slhKeyGenInternal(v.SkSeed, v.SkPrf, v.PkSeed)
					skBytes, err := sk.MarshalBinary()
					test.CheckNoErr(t, err, "PrivateKey.MarshalBinary failed")
					if !bytes.Equal(skBytes, v.Sk) {
						test.ReportError(t, skBytes, v.Sk, v.TcID)
					}

					pkBytes, err := pk.MarshalBinary()
					test.CheckNoErr(t, err, "PublicKey.MarshalBinary failed")
					if !bytes.Equal(pkBytes, v.Pk) {
						test.ReportError(t, pkBytes, v.Pk, v.TcID)
					}
				})
			}
		})
	}
}

type acvpSigGenPrompt struct {
	VsID       int    `json:"vsId"`
	Algorithm  string `json:"algorithm"`
	Mode       string `json:"mode"`
	Revision   string `json:"revision"`
	IsSample   bool   `json:"isSample"`
	TestGroups []struct {
		TgID          int    `json:"tgId"`
		TestType      string `json:"testType"`
		ParameterSet  string `json:"parameterSet"`
		Deterministic bool   `json:"deterministic"`
		Tests         []struct {
			TcID    int      `json:"tcId"`
			Sk      hexBytes `json:"sk"`
			MsgLen  int      `json:"messageLength"`
			Msg     hexBytes `json:"message"`
			AddRand hexBytes `json:"additionalRandomness,omitempty"`
		} `json:"tests"`
	} `json:"testGroups"`
}

type acvpSigGenResult struct {
	VsID       int    `json:"vsId"`
	Algorithm  string `json:"algorithm"`
	Mode       string `json:"mode"`
	Revision   string `json:"revision"`
	IsSample   bool   `json:"isSample"`
	TestGroups []struct {
		TgID  int `json:"tgId"`
		Tests []struct {
			TcID      int      `json:"tcId"`
			Signature hexBytes `json:"signature"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func testSign(t *testing.T) {
	inputs := new(acvpSigGenPrompt)
	readVector(t, "testdata/sigGen_prompt.json", inputs)
	outputs := new(acvpSigGenResult)
	readVector(t, "testdata/sigGen_results.json", outputs)

	for g, group := range inputs.TestGroups {
		ins, err := InstanceByName(group.ParameterSet)
		test.CheckNoErr(t, err, "invalid instance name")
		state, err := ins.newState()
		test.CheckNoErr(t, err, "newState failed")

		t.Run(fmt.Sprintf("TgID_%v", group.TgID), func(t *testing.T) {
			for te, v := range group.Tests {
				test.CheckOk(v.TcID == outputs.TestGroups[g].Tests[te].TcID, "mismatch of TcID", t)

				t.Run(fmt.Sprintf("TcID_%v", v.TcID), func(t *testing.T) {
					sk := &PrivateKey{Instance: ins}
					err := sk.UnmarshalBinary(v.Sk)
					test.CheckNoErr(t, err, "PrivateKey.UnmarshalBinary failed")

					var addRand []byte
					if group.Deterministic {
						addRand = sk.publicKey.seed
					} else {
						addRand = v.AddRand
					}

					got, err := state.slhSignInternal(sk, v.Msg, addRand)
					test.CheckNoErr(t, err, "slhSignInternal failed")
					want := outputs.TestGroups[g].Tests[te].Signature

					if !bytes.Equal(got, want) {
						test.ReportError(t, got, want, group.TgID, v.TcID)
					}
				})
			}
		})
	}
}

func TestACVP(t *testing.T) {
	t.Run("Keygen", testKeygen)
	t.Run("Sign", testSign)
}
