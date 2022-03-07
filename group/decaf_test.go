package group_test

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
)

type testJSONFile struct {
	Group     string `json:"group"`
	Version   string `json:"version"`
	Generator struct {
		X string `json:"x"`
		Y string `json:"y"`
		T string `json:"t"`
		Z string `json:"z"`
	} `json:"generator"`
	Vectors []struct {
		K  string `json:"k"`
		KG string `json:"kG"`
		KP string `json:"kP"`
	} `json:"vectors"`
}

func (kat *testJSONFile) readFile(t *testing.T, fileName string) {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, _ := ioutil.ReadAll(jsonFile)

	err = json.Unmarshal(input, &kat)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}
}

// func verify(t *testing.T, i int, gotkG *decaf448.Elt, wantEnckG []byte) {
// 	wantkG := &decaf448.Elt{}
//
// 	gotEnckG, err := gotkG.MarshalBinary()
// 	got := err == nil && bytes.Equal(gotEnckG, wantEnckG)
// 	want := true
// 	if got != want {
// 		test.ReportError(t, got, want, i)
// 	}
//
// 	err = wantkG.UnmarshalBinary(wantEnckG)
// 	got = err == nil &&
// 		decaf448.IsValid(gotkG) &&
// 		decaf448.IsValid(wantkG) &&
// 		gotkG.IsEqual(wantkG)
// 	want = true
// 	if got != want {
// 		test.ReportError(t, got, want, i)
// 	}
// }
//
// // Source: https://gist.github.com/armfazh/af01e1794dcf6942f2d404c5a0832676
// func TestDecafv1_0(t *testing.T) {
// 	var kat testJSONFile
// 	kat.readFile(t, "testdata/decafv1.0_vectors.json")
//
// 	got := kat.Group
// 	want := "decaf"
// 	if got != want {
// 		test.ReportError(t, got, want)
// 	}
// 	got = kat.Version
// 	want = decaf448.Version
// 	if got != want {
// 		test.ReportError(t, got, want)
// 	}
// 	var scalar decaf448.Scalar
// 	var P decaf448.Elt
// 	G := decaf448.Generator()
// 	for i := range kat.Vectors {
// 		k, _ := hex.DecodeString(kat.Vectors[i].K)
// 		wantEnckG, _ := hex.DecodeString(kat.Vectors[i].KG)
// 		wantEnckP, _ := hex.DecodeString(kat.Vectors[i].KP)
// 		scalar.FromBytes(k)
//
// 		decaf448.MulGen(&P, &scalar)
// 		verify(t, i, &P, wantEnckG)
//
// 		decaf448.Mul(&P, &scalar, G)
// 		verify(t, i, &P, wantEnckG)
//
// 		decaf448.Mul(&P, &scalar, &P)
// 		verify(t, i, &P, wantEnckP)
// 	}
// }
//
// func TestDecafRandom(t *testing.T) {
// 	const testTimes = 1 << 10
// 	var e decaf448.Elt
// 	var enc [decaf448.EncodingSize]byte
//
// 	for i := 0; i < testTimes; i++ {
// 		for found := false; !found; {
// 			_, _ = rand.Read(enc[:])
// 			err := e.UnmarshalBinary(enc[:])
// 			found = err == nil
// 		}
// 		got, err := e.MarshalBinary()
// 		want := enc[:]
// 		if err != nil || !bytes.Equal(got, want) {
// 			test.ReportError(t, got, want, e)
// 		}
// 	}
// }

// func randomPoint() group.Element {
// 	var k group.Scalar
// 	_, _ = rand.Read(k[:])
// 	P := decaf448{}.NewElement()
// 	decaf448{}.MulGen(&P, &k)
// 	return &P
// }
//
// func TestPointAdd(t *testing.T) {
// 	const testTimes = 1 << 10
// 	Q := decaf448{}.NewElement()
// 	for i := 0; i < testTimes; i++ {
// 		P := randomPoint()
// 		// Q = 16P = 2^4P
// 		decaf448.Double(Q, &P) // 2P
// 		decaf448.Double(Q, Q)  // 4P
// 		decaf448.Double(Q, Q)  // 8P
// 		decaf448.Double(Q, Q)  // 16P
// 		got := Q
// 		// R = 16P = P+P...+P
// 		R := decaf448.Identity()
// 		for j := 0; j < 16; j++ {
// 			decaf448.Add(R, R, &P)
// 		}
// 		want := R
// 		if !decaf448.IsValid(got) || !decaf448.IsValid(want) || !got.IsEqual(want) {
// 			test.ReportError(t, got, want, P)
// 		}
// 	}
// }
//
// func TestPointNeg(t *testing.T) {
// 	const testTimes = 1 << 10
// 	Q := decaf448{}.NewElement()
// 	for i := 0; i < testTimes; i++ {
// 		P := randomPoint()
// 		decaf448.Neg(Q, &P)
// 		decaf448.Add(Q, Q, &P)
// 		got := Q.IsIdentity()
// 		want := true
// 		if got != want {
// 			test.ReportError(t, got, want, P)
// 		}
// 	}
// }
//
// func TestDecafOrder(t *testing.T) {
// 	const testTimes = 1 << 10
// 	Q := decaf448{}.NewElement()
// 	order := decaf448{}.Order()
// 	for i := 0; i < testTimes; i++ {
// 		P := randomPoint()
//
// 		decaf448.Mul(Q, &order, &P)
// 		got := Q.IsIdentity()
// 		want := true
// 		if got != want {
// 			test.ReportError(t, got, want, P, order)
// 		}
// 	}
// }
//
// func TestDecafInvalid(t *testing.T) {
// 	bigS := fp.P()
// 	negativeS := fp.Elt{1} // the smallest s that is negative
// 	nonQR := fp.Elt{4}     // the shortest s such that (a^2s^4 + (2a - 4d)*s^2 + 1) is non-QR.
//
// 	badEncodings := [][]byte{
// 		{},           // wrong size input
// 		bigS[:],      // s is out of the interval [0,p-1].
// 		negativeS[:], // s is not positive
// 		nonQR[:],     // s=4 and (a^2s^4 + (2a - 4d)*s^2 + 1) is non-QR.
// 	}
//
// 	e := decaf448{}.NewElement()
// 	for _, enc := range badEncodings {
// 		got := e.UnmarshalBinary(enc)
// 		want := decaf448.ErrInvalidDecoding
// 		if got != want {
// 			test.ReportError(t, got, want, enc)
// 		}
// 	}
// }
