package sequence

import (
	"roce-cli/internal/config"
	"testing"
)

func TestWrapAndList(t *testing.T) {
	c := config.Defaults()
	c.PSN = 0xfffffe
	c.Inner.SrcPort = 65535
	c.SrcPortStep = 1
	for i, want := range []uint32{0xfffffe, 0xffffff, 0, 1} {
		f := At(c, uint64(i))
		if f.PSN != want || f.SrcPort != uint16(65535+i) {
			t.Fatal(i, f)
		}
	}
	c.PSNList = []uint32{100, 101, 101, 103, 102}
	for i, p := range c.PSNList {
		if At(c, uint64(i)).PSN != p {
			t.Fatal(i)
		}
	}
	c.Template = "cnp"
	if At(c, 0).PSN != 0 {
		t.Fatal("cnp")
	}
	c = config.Defaults()
	c.PSNStep = 0
	if At(c, ^uint64(0)).PSN != 0 {
		t.Fatal("fixed")
	}
	c.PSN = 7
	c.PSNStep = 0xffffff
	if At(c, 1<<40|3).PSN != 4 {
		t.Fatal("large index wrap")
	}
}
