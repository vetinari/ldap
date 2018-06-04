package controls

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
	"testing"

	ber "gopkg.in/asn1-ber.v1"
)

func TestControlManageDsaIT(t *testing.T) {
	runControlTest(t, ManageDsaIT(true))
	runControlTest(t, ManageDsaIT(false))
}

func TestControlPaging(t *testing.T) {
	runControlTest(t, &Paging{Size: 0})
	runControlTest(t, &Paging{Size: 100})
}

func TestControlBehera(t *testing.T) {
	runControlTest(t, &BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: -1})
	runControlTest(t, &BeheraPasswordPolicy{Expire: 127, Grace: -1, Error: -1})
	runControlTest(t, &BeheraPasswordPolicy{Expire: -1, Grace: 127, Error: -1})
	runControlTest(t, &BeheraPasswordPolicy{Expire: -1, Grace: 4294967298, Error: -1})
	runControlTest(t, &BeheraPasswordPolicy{Expire: -1, Grace: -1, Error: 4})
}

func TestControlProxiedAuthz(t *testing.T) {
	runControlTest(t, &ProxiedAuthorization{Critical: true, AuthzID: "uid=someone,dc=example,dc=org"})
}

func TestControlVChuPassword(t *testing.T) {
	runControlTest(t, VChuPasswordMustChange(true))
	runControlTest(t, VChuPasswordWarning(123345))
}

func runControlTest(t *testing.T, originalControl Control) {
	header := ""
	if callerpc, _, line, ok := runtime.Caller(1); ok {
		if caller := runtime.FuncForPC(callerpc); caller != nil {
			header = fmt.Sprintf("%s:%d: ", caller.Name(), line)
		}
	}

	encodedPacket := originalControl.Encode()
	encodedBytes := encodedPacket.Bytes()

	// ber.PrintPacket(encodedPacket)
	// Decode directly from the encoded packet (ensures Value is correct)
	fromPacket, err := Decode(encodedPacket)
	if err != nil {
		t.Errorf("%sdecoding encoded bytes control failed: %s", header, err)
	}
	if !bytes.Equal(encodedBytes, fromPacket.Encode().Bytes()) {
		t.Errorf("%sround-trip from encoded packet failed", header)
	}
	if reflect.TypeOf(originalControl) != reflect.TypeOf(fromPacket) {
		t.Errorf("%sgot different type decoding from encoded packet: %T vs %T", header, fromPacket, originalControl)
	}

	// Decode from the wire bytes (ensures ber-encoding is correct)
	pkt, err := ber.DecodePacketErr(encodedBytes)
	if err != nil {
		t.Errorf("%sdecoding encoded bytes failed: %s", header, err)
	}
	// ber.PrintPacket(pkt)
	fromBytes, err := Decode(pkt)
	if err != nil {
		t.Errorf("%sdecoding control failed: %s", header, err)
	}
	if !bytes.Equal(encodedBytes, fromBytes.Encode().Bytes()) {
		t.Errorf("%sround-trip from encoded bytes failed", header)
	}
	if reflect.TypeOf(originalControl) != reflect.TypeOf(fromPacket) {
		t.Errorf("%sgot different type decoding from encoded bytes: %T vs %T", header, fromBytes, originalControl)
	}
}
