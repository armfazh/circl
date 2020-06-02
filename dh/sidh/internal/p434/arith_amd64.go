package p434

import "golang.org/x/sys/cpu"

// HasADXandBMI2 signals support for ADX and BMI2
var HasADXandBMI2 = cpu.X86.HasBMI2 && cpu.X86.HasADX
