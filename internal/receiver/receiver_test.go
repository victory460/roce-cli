package receiver

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRestoreVLAN(t *testing.T) {
	frame := make([]byte, 60)
	frame[12] = 8
	aux := make([]byte, 20)
	got, e := RestoreVLAN(frame, aux)
	if e != nil || !bytes.Equal(got, frame) {
		t.Fatal(e)
	}
	binary.NativeEndian.PutUint32(aux, 1<<4)
	got, e = RestoreVLAN(frame, aux)
	if e != nil || len(got) != 64 || binary.BigEndian.Uint16(got[12:14]) != 0x8100 || binary.BigEndian.Uint16(got[14:16]) != 0 || !bytes.Equal(got[16:], frame[12:]) {
		t.Fatal(got, e)
	}
	binary.NativeEndian.PutUint32(aux, 1<<4|1<<6)
	binary.NativeEndian.PutUint16(aux[16:], 0xe123)
	binary.NativeEndian.PutUint16(aux[18:], 0x88a8)
	got, e = RestoreVLAN(frame, aux)
	if e != nil || binary.BigEndian.Uint16(got[12:14]) != 0x88a8 || binary.BigEndian.Uint16(got[14:16]) != 0xe123 {
		t.Fatal(got, e)
	}
	if _, e = RestoreVLAN(frame, aux[:19]); e == nil {
		t.Fatal("short aux")
	}
	if _, e = RestoreVLAN(frame[:13], aux); e == nil {
		t.Fatal("short Ethernet")
	}
}
