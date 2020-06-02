package p503

import "golang.org/x/sys/cpu"

// According to https://github.com/golang/go/issues/28230,
// variables referred from the assembly must be in the same package.
var (
	// HasBMI2 signals support for MULX which is in BMI2
	HasBMI2 = cpu.X86.HasBMI2

	// HasADXandBMI2 signals support for ADX and BMI2
	HasADXandBMI2 = cpu.X86.HasBMI2 && cpu.X86.HasADX
)
