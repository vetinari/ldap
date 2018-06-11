package controls

import (
	"errors"
	"fmt"

	ber "gopkg.in/asn1-ber.v1"
)

const ControlOIDPreRead string = "1.3.6.1.1.13.1"
const ControlOIDPostRead string = "1.3.6.1.1.13.2"

type AttributeSelection struct {
	Type   string
	Values []string
}

type PrePostRead struct {
	IsRequest  bool
	ControlOID string
	Critical   bool

	Attrs []string

	DN       string
	AttrVals []AttributeSelection
}

func NewPreReadRequest(c bool, attrs []string) *PrePostRead {
	return &PrePostRead{
		Critical:   c,
		IsRequest:  true,
		Attrs:      attrs,
		ControlOID: ControlOIDPreRead,
	}
}

func NewPreReadResult(c bool, dn string, attrs []AttributeSelection) *PrePostRead {
	return &PrePostRead{
		Critical:   c,
		IsRequest:  false,
		ControlOID: ControlOIDPreRead,
		DN:         dn,
		AttrVals:   attrs,
	}
}

func NewPostReadRequest(c bool, attrs []string) *PrePostRead {
	return &PrePostRead{
		Critical:   c,
		IsRequest:  true,
		Attrs:      attrs,
		ControlOID: ControlOIDPostRead,
	}
}

func NewPostReadResult(c bool, dn string, attrs []AttributeSelection) *PrePostRead {
	return &PrePostRead{
		Critical:   c,
		IsRequest:  false,
		ControlOID: ControlOIDPostRead,
		DN:         dn,
		AttrVals:   attrs,
	}
}

func decodePrePostRead(oid string, c bool, pkt *ber.Packet) (Control, error) {
	switch oid {
	case ControlOIDPreRead, ControlOIDPostRead:
	default:
		return nil, errors.New("invalid OID passed to decoder")
	}
	read := &PrePostRead{
		Critical:   c,
		ControlOID: oid,
	}

	switch pkt.Tag {
	case ber.TagSequence: // we got a request
		read.IsRequest = true
		for _, child := range pkt.Children {
			child.Description = "Request Attribute"
			read.Attrs = append(read.Attrs, child.Value.(string))
		}
		return read, nil

	case ber.TagOctetString:
		entry, err := ber.DecodePacketErr(pkt.Data.Bytes())
		if err != nil {
			return nil, fmt.Errorf("failed to decode control value: %s", err)
		}
		read.DN = entry.Children[0].Value.(string)
		entry.Children[0].Description = "DN"

		for _, child := range entry.Children[1].Children {
			attr := child.Children[0].Value.(string)
			child.Children[0].Description = "Attribute Name"
			as := AttributeSelection{Type: attr}
			for _, value := range child.Children[1].Children {
				as.Values = append(as.Values, value.Value.(string))
				value.Description = "Attribute Value"
			}
			read.AttrVals = append(read.AttrVals, as)
		}
		return read, nil

	default:
		return nil, errors.New("invalid tag on control value")
	}
}

func (c *PrePostRead) Criticality() bool {
	return c.Critical
}

func (c *PrePostRead) OID() string {
	return c.ControlOID
}

func (c *PrePostRead) Name() string {
	if c.ControlOID == ControlOIDPreRead {
		return "Pre Read - RFC 4527"
	}
	return "Post Read - RFC 4527"
}

func (c *PrePostRead) Encode() *ber.Packet {
	if c.IsRequest {
		val := ber.Encode(
			ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control Value",
		)
		for _, attr := range c.Attrs {
			val.AppendChild(
				ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr, "Request Attribute"),
			)
		}
		return Encode(c, val)
	}

	entry := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Result Entry",
	)
	entry.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.DN, "Response DN"),
	)
	attrVals := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Result Attributes",
	)
	for _, attrs := range c.AttrVals {
		av := ber.Encode(
			ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Result Attribute",
		)
		av.AppendChild(
			ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attrs.Type, "Result Attr Name"),
		)
		avs := ber.Encode(
			ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Result Attribute Values",
		)
		for _, val := range attrs.Values {
			avs.AppendChild(
				ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, val, "Result Attribute"),
			)
		}
		av.AppendChild(avs)
		attrVals.AppendChild(av)
	}
	entry.AppendChild(attrVals)
	val := ber.Encode(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value",
	)
	val.AppendChild(entry)
	return Encode(c, val)
}
