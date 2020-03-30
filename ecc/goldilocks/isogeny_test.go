package goldilocks

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestIsogeny(t *testing.T) {
	const testTimes = 1 << 10
	var goldl Curve
	var twist twistCurve
	var P Point

	for i := 0; i < testTimes; i++ {
		randomPoint(&P)
		got := twist.push(goldl.push(&P))      // phi^-(phi^+(P))
		want := goldl.Double(goldl.Double(&P)) // 4P
		if got.IsEqual(want) {
			test.ReportError(t, got, want, P)
		}
	}
}
