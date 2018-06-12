package controls

import (
	"errors"
	"fmt"
	"strconv"

	ber "gopkg.in/asn1-ber.v1"
)

// VChuPasswordMustChange implements the Password Must be changed control
type VChuPasswordMustChange bool

// VChuPasswordWarning implements the Password warning control
type VChuPasswordWarning int64

// ControlOIDVChuPasswordMustChange is the OID defined for the password must change control
const ControlOIDVChuPasswordMustChange string = "2.16.840.1.113730.3.4.4"

// ControlOIDVChuPasswordWarning is the OID defined for the password expiry warning control
const ControlOIDVChuPasswordWarning string = "2.16.840.1.113730.3.4.5"

// OID is part of the Control interface
func (c VChuPasswordMustChange) OID() string {
	return ControlOIDVChuPasswordMustChange
}

// Name is part of the Control interface
func (c VChuPasswordMustChange) Name() string {
	return "VChu Password Policy - Password Must Change"
}

// Criticality is part of the Control interface
func (c VChuPasswordMustChange) Criticality() bool {
	return false
}

// Encode is part of the Control interface
func (c VChuPasswordMustChange) Encode() *ber.Packet {
	val := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control Value",
	)
	val.AppendChild(
		ber.Encode(
			ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "0", "Value",
		))
	return Encode(c, val)
}

// OID is part of the Control interface
func (c VChuPasswordWarning) OID() string {
	return ControlOIDVChuPasswordWarning
}

// Name is part of the Control interface
func (c VChuPasswordWarning) Name() string {
	return "VChu Password Policy - Password Expires"
}

// Criticality is part of the Control interface
func (c VChuPasswordWarning) Criticality() bool {
	return false
}

// Encode is part of the Control interface
func (c VChuPasswordWarning) Encode() *ber.Packet {
	val := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control Value",
	)
	val.AppendChild(
		ber.Encode(
			ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, fmt.Sprintf("%d", int64(c)), "Expire time",
		))
	return Encode(c, val)
}

func decodeVChuPassword(oid string, criticality bool, pkt *ber.Packet) (Control, error) {
	switch oid {
	case ControlOIDVChuPasswordMustChange:
		return VChuPasswordMustChange(true), nil
	case ControlOIDVChuPasswordWarning:
		expireStr := ber.DecodeString(pkt.Children[0].Data.Bytes())
		expire, err := strconv.ParseInt(expireStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse value as int: %s", err)
		}
		pkt.Children[0].Description = fmt.Sprintf("Password expires in %d seconds", expire)
		return VChuPasswordWarning(expire), nil
	default:
		return nil, errors.New("invalid control passwd to decoder")
	}
}
