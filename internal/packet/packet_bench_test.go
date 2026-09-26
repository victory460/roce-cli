package packet

import (
	"testing"

	"roce-cli/internal/sequence"
)

// BenchmarkBuild measures complete validated frame construction, including checksums.
func BenchmarkBuild(b *testing.B) {
	for _, encap := range []string{"none", "vxlan"} {
		b.Run(encap, func(b *testing.B) {
			c := base()
			c.Payload = make([]byte, 1024)
			c.Encap = encap
			if encap == "vxlan" {
				c.VNI = 100
				c.Outer = c.Inner
			}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Build(c, sequence.At(c, uint64(i))); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
