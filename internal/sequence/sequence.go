// Package sequence calculates fields without retaining packet buffers.
package sequence

import "roce-cli/internal/config"

type Fields struct {
	PSN     uint32
	SrcPort uint16
}

// At requires index < FrameCount when an explicit list is configured.
func At(c config.Config, index uint64) Fields {
	psn := (c.PSN + uint32(index&0xffffff)*c.PSNStep) & 0xffffff
	if len(c.PSNList) > 0 {
		psn = c.PSNList[index]
	}
	if c.Template == "cnp" {
		psn = 0
	}
	return Fields{psn, c.Inner.SrcPort + uint16(index)*c.SrcPortStep}
}
