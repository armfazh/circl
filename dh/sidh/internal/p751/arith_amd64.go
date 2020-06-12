package p751

import "golang.org/x/sys/cpu"

var (
	// HasBMI2 signals support for MULX which is in BMI2
	HasBMI2 = cpu.X86.HasBMI2
	// HasADXandBMI2 signals support for ADX and BMI2
	HasADXandBMI2 = cpu.X86.HasBMI2 && cpu.X86.HasADX
)
