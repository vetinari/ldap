package controls

import ber "gopkg.in/asn1-ber.v1"

const ControlOIDProxiedAuthorization = "2.16.840.1.113730.3.4.18"

// ProxiedAuthorization implements the control described in
// https://tools.ietf.org/html/rfc4370
type ProxiedAuthorization struct {
	Critical bool
	AuthzID  string
}

func NewProxiedAuthorization(authzID string) *ProxiedAuthorization {
	return &ProxiedAuthorization{Critical: true, AuthzID: authzID}
}

// OID returns the OID
func (c *ProxiedAuthorization) OID() string {
	return ControlOIDProxiedAuthorization
}

func (c *ProxiedAuthorization) Name() string {
	return "Proxied Authorization"
}

func (c *ProxiedAuthorization) Encode() *ber.Packet {
	id := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.AuthzID, "AuthzID")
	val := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagOctetString, id.Bytes(), "Control Value",
	)

	return Encode(c, val)
}

func (c *ProxiedAuthorization) Criticality() bool {
	return c.Critical
}

func decodeProxiedAuthorization(_ string, criticality bool, pkt *ber.Packet) (Control, error) {
	val.Description = "AuthzID"
	return &ProxiedAuthorization{
		Critical: criticality,
		AuthzID:  ber.DecodeString(pkt.Data.Bytes()),
	}, nil
}
