// Package controls contains LDAP controls
package controls

import (
	"errors"
	"fmt"
	"sync"

	ber "gopkg.in/asn1-ber.v1"
)

// Control is the interface which every control must implement
type Control interface {
	OID() string
	Criticality() bool
	Name() string
	Encode() *ber.Packet // note: may return nil
}

// Decoder must be implemented by control parsers, most implementations will ignore
// the oid argument.
type Decoder func(oid string, criticality bool, value *ber.Packet) (Control, error)

type controlRegister struct {
	sync.Mutex
	Decoders map[string]Decoder
}

var registeredControls = &controlRegister{
	Decoders: map[string]Decoder{
		ControlOIDManageDsaIT:            decodeManageDsaIT,
		ControlOIDPaging:                 decodePaging,
		ControlOIDBeheraPasswordPolicy:   decodeBehera,
		ControlOIDProxiedAuthorization:   decodeProxiedAuthorization,
		ControlOIDVChuPasswordMustChange: decodeVChuPassword,
		ControlOIDVChuPasswordWarning:    decodeVChuPassword,
		ControlOIDPreRead:                decodePrePostRead,
		ControlOIDPostRead:               decodePrePostRead,
	},
}

var (
	// ErrMissingControlValue is returned by controls which expect a value and none
	// is present
	ErrMissingControlValue = errors.New("missing control value")
	// ErrInvalidControlData is a generic error for invalid data in a control
	// packet
	ErrInvalidControlData = errors.New("invalid control data")
	// ErrInvalidControlValue is returned by control decoders when the value is not
	// in the expected format
	ErrInvalidControlValue = errors.New("invalid control value")
	// ErrMissingControlDecoder is returned by RegisterControl when the decoder is nil
	ErrMissingControlDecoder = errors.New("missing control decoder")
)

// RegisterControl registers a control decoder.
func RegisterControl(oid string, decoder Decoder) error {
	if decoder == nil {
		return ErrMissingControlDecoder
	}
	registeredControls.Lock()
	registeredControls.Decoders[oid] = decoder
	registeredControls.Unlock()
	return nil
}

// UnregisterControl removes a previously registered control decoder.
func UnregisterControl(oid string) {
	registeredControls.Lock()
	if _, ok := registeredControls.Decoders[oid]; ok {
		delete(registeredControls.Decoders, oid)
	}
	registeredControls.Unlock()
}

// GetDecoder returns the registered decoder func for the given OID.
func GetDecoder(oid string) Decoder {
	registeredControls.Lock()
	dec := registeredControls.Decoders[oid]
	registeredControls.Unlock()
	return dec
}

// GetControlOIDs returns the OIDs of all registered controls.
func GetControlOIDs() (ctrls []string) {
	registeredControls.Lock()
	for oid := range registeredControls.Decoders {
		ctrls = append(ctrls, oid)
	}
	registeredControls.Unlock()
	return ctrls
}

// UnknownControl is a control unknown to the service, used to check for unknown controls
// with a criticality set to true
type UnknownControl struct {
	oid         string
	criticality bool
}

// NewUnknownControl returns a new UnknownControl
func NewUnknownControl(oid string, crit bool) Control {
	return &UnknownControl{oid: oid, criticality: crit}
}

// OID is part of the Control interface
func (u *UnknownControl) OID() string {
	return u.oid
}

// Criticality is part of the Control interface
func (u *UnknownControl) Criticality() bool {
	return u.criticality
}

// Name is part of the Control interface
func (u *UnknownControl) Name() string {
	return "unknown"
}

// Encode is part of the Control interface
func (u *UnknownControl) Encode() *ber.Packet {
	return nil
}

// Describe is part of the Control interface
func (u *UnknownControl) Describe(_ string, val *ber.Packet) error {
	if val != nil {
		val.Description = "Control Value of unknown control"
	}
	return nil
}

// Encode encodes the Control to a BER packet suitable to be added to a response.
// The val argument is the already BER encoded control value
func Encode(c Control, val *ber.Packet) *ber.Packet {
	packet := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control",
	)
	packet.AppendChild(ber.NewString(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.OID(), c.Name(),
	))
	if c.Criticality() {
		packet.AppendChild(ber.NewBoolean(
			ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality(), "Criticality",
		))
	}
	if val != nil {
		packet.AppendChild(val)
	}
	return packet
}

// Decode returns the decoded control. Any control not registered is returned as
// UnknownControl.
func Decode(pkt *ber.Packet) (ctrl Control, err error) {
	if pkt.Tag != ber.TagSequence {
		return nil, ErrInvalidControlData
	}
	if len(pkt.Children) == 0 || len(pkt.Children) > 3 {
		return nil, ErrInvalidControlData
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic caught: %s", r)
			ctrl = nil
		}
	}()

	oid, ok := pkt.Children[0].Value.(string)
	if !ok {
		return nil, ErrInvalidControlData
	}

	var criticality bool
	var value *ber.Packet
	switch len(pkt.Children) {
	case 1:
	case 2:
		// both are optional, check the type to see what we got
		if crit, ok := pkt.Children[1].Value.(bool); ok {
			criticality = crit
			pkt.Children[1].Description = fmt.Sprintf("Criticality: %t", criticality)
		} else {
			pkt.Children[1].Description = "Control Value"
			value = pkt.Children[1]
		}
	case 3:
		criticality = pkt.Children[1].Value.(bool)
		pkt.Children[1].Description = fmt.Sprintf("Criticality: %t", criticality)
		value = pkt.Children[2]
		pkt.Children[2].Description = "Control Value"
	}

	decode := GetDecoder(oid)
	if decode == nil {
		return NewUnknownControl(oid, criticality), nil
	}

	// explicitly set ctrl, err so we can catch panics in bad decoders
	ctrl, err = decode(oid, criticality, value)
	if err != nil {
		return nil, err
	}
	pkt.Children[0].Description = "Control OID: " + ctrl.Name()
	return ctrl, nil
}
