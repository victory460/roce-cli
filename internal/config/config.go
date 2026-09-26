// Package config defines the validated inputs shared by the CLI and packet builder.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

type Layer struct {
	SrcMAC, DstMAC   net.HardwareAddr
	SrcIP, DstIP     netip.Addr
	SrcPort, DstPort uint16
	DSCP, ECN, TTL   uint8
	VLAN             int // -1 means absent; 0 is a priority tag.
	PCP              uint8
	ZeroChecksum     bool
}

type Config struct {
	Command, Template, Encap string
	Inner, Outer             Layer
	DQPN, PSN, PSNStep       uint32
	PKey                     uint16
	AckRequest, BadICRC      bool
	Payload                  []byte
	RemoteAddr               uint64
	RKey, VNI                uint32
	MTU                      int
	Count                    uint64
	PSNList                  []uint32
	SrcPortStep              uint16
	Interval, Duration       time.Duration
	Continuous               bool
	PCAP, Interface          string
	Hex, Overwrite           bool
	Port, VXLANPort          uint16
	FilterDQPN, JSON, Strict bool
}

func Defaults() Config {
	return Config{Template: "send-only", Encap: "none", Inner: Layer{SrcPort: 49152, DstPort: 4791, TTL: 64, VLAN: -1}, Outer: Layer{SrcPort: 55000, DstPort: 4789, TTL: 64, VLAN: -1}, PKey: 0xffff, PSNStep: 1, MTU: 1500, Count: 1}
}

func (c Config) FrameCount() uint64 {
	if len(c.PSNList) > 0 {
		return uint64(len(c.PSNList))
	}
	return c.Count
}

// ValidatePacket also protects callers which do not use the CLI.
func (c Config) ValidatePacket() error {
	if c.Template != "send-only" && c.Template != "write-only" && c.Template != "cnp" {
		return fmt.Errorf("invalid template %q", c.Template)
	}
	if c.Encap != "none" && c.Encap != "vxlan" {
		return fmt.Errorf("invalid encap %q", c.Encap)
	}
	if c.MTU < 68 || c.MTU > 65535 {
		return fmt.Errorf("mtu must be 68..65535")
	}
	if c.DQPN > 0xffffff || c.PSN > 0xffffff || c.PSNStep > 0xffffff {
		return fmt.Errorf("QPN and PSN must fit in 24 bits")
	}
	if len(c.Payload) > 65535 {
		return fmt.Errorf("payload exceeds IPv4 capacity")
	}
	if c.Template == "cnp" && (len(c.Payload) > 0 || c.AckRequest) {
		return fmt.Errorf("cnp cannot carry payload or ack-request")
	}
	if err := c.Inner.Validate(); err != nil {
		return fmt.Errorf("RoCE layer: %w", err)
	}
	if c.Encap == "vxlan" {
		if c.VNI == 0 || c.VNI > 0xffffff {
			return fmt.Errorf("vni must be 1..0xffffff")
		}
		if err := c.Outer.Validate(); err != nil {
			return fmt.Errorf("outer layer: %w", err)
		}
	}
	return nil
}
func (l Layer) Validate() error {
	if len(l.SrcMAC) != 6 || len(l.DstMAC) != 6 {
		return fmt.Errorf("source and destination MAC must be 6 bytes")
	}
	if !l.SrcIP.Is4() || !l.DstIP.Is4() {
		return fmt.Errorf("source and destination IPv4 required")
	}
	if l.TTL == 0 || l.DSCP > 63 || l.ECN > 3 || l.PCP > 7 || l.VLAN < -1 || l.VLAN > 4094 {
		return fmt.Errorf("invalid QoS, TTL or VLAN field")
	}
	if l.VLAN < 0 && l.PCP != 0 {
		return fmt.Errorf("pcp requires vlan-id")
	}
	return nil
}
