package controls

import (
	ber "gopkg.in/asn1-ber.v1"
)

// Paging is the control for paged searches
type Paging struct {
	Critical bool
	Size     uint32
	Cookie   []byte
}

// ControlOIDPaging is the OID of the "Paging" Control, see also RFC 2696
const ControlOIDPaging string = "1.2.840.113556.1.4.319"

func decodePaging(_ string, c bool, val *ber.Packet) (Control, error) {
	if len(val.Children) != 2 {
		return nil, ErrInvalidControlValue
	}

	s, ok := val.Children[0].Value.(int64)
	if !ok {
		return nil, ErrInvalidControlValue
	}

	return &Paging{
		Critical: c,
		Size:     uint32(s),
		Cookie:   val.Children[1].Data.Bytes(),
	}, nil
}

// OID is part of the Control interface
func (c *Paging) OID() string {
	return ControlOIDPaging
}

// Name is part of the Control interface
func (c *Paging) Name() string {
	return "Paging"
}

// Encode is part of the Control interface
func (c *Paging) Encode() *ber.Packet {
	val := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control Value",
	)
	val.AppendChild(ber.NewInteger(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c.Size), "Paging Size",
	))

	cookie := ber.Encode(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie",
	)
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	val.AppendChild(cookie)
	return Encode(c, val)
}

// Criticality is part of the Control interface
func (c *Paging) Criticality() bool {
	return c.Critical
}
