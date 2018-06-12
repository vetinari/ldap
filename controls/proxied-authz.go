package controls

import ber "gopkg.in/asn1-ber.v1"

// ControlOIDProxiedAuthorization is the OID defined in RFC 4370
// for the proxied authorization control
const ControlOIDProxiedAuthorization = "2.16.840.1.113730.3.4.18"

// ProxiedAuthorization implements the control described in
// https://tools.ietf.org/html/rfc4370
type ProxiedAuthorization struct {
	Critical bool
	AuthzID  string
}

// NewProxiedAuthorization returns a proxied authorization control for the given authzID
func NewProxiedAuthorization(authzID string) *ProxiedAuthorization {
	return &ProxiedAuthorization{Critical: true, AuthzID: authzID}
}

// OID returns the OID, part of the Control interface
func (c *ProxiedAuthorization) OID() string {
	return ControlOIDProxiedAuthorization
}

// Name is part of the Control interface
func (c *ProxiedAuthorization) Name() string {
	return "Proxied Authorization"
}

// Encode is part of the Control interface
func (c *ProxiedAuthorization) Encode() *ber.Packet {
	id := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.AuthzID, "AuthzID")
	val := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagOctetString, id.Bytes(), "Control Value",
	)

	return Encode(c, val)
}

// Criticality is part of the Control interface
func (c *ProxiedAuthorization) Criticality() bool {
	return c.Critical
}

func decodeProxiedAuthorization(_ string, criticality bool, pkt *ber.Packet) (Control, error) {
	pkt.Description = "AuthzID"
	return &ProxiedAuthorization{
		Critical: criticality,
		AuthzID:  ber.DecodeString(pkt.Data.Bytes()),
	}, nil
}
