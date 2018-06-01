package controls

import "gopkg.in/asn1-ber.v1"

// ManageDsaIT is the Manage DSA IT Control
type ManageDsaIT bool

// ControlOIDManageDsaIT is the OID of the "Manage DSA IT" Control
const ControlOIDManageDsaIT string = "2.16.840.1.113730.3.4.2"

func decodeManageDsaIT(_ string, c bool, _ *ber.Packet) (Control, error) {
	return ManageDsaIT(c), nil
}

// OID is part of the Control interface
func (c ManageDsaIT) OID() string {
	return ControlOIDManageDsaIT
}

// Name is part of the Control interface
func (c ManageDsaIT) Name() string {
	return "Manage DSA IT"
}

// Encode is part of the Control interface
func (c ManageDsaIT) Encode() *ber.Packet {
	return Encode(c, nil)
}

// Criticality is part of the Control interface
func (c ManageDsaIT) Criticality() bool {
	return bool(c)
}
