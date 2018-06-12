package controls

import (
	"fmt"

	ber "gopkg.in/asn1-ber.v1"
)

// ControlOIDBeheraPasswordPolicy is the OID defined for the Password Policy Control
const ControlOIDBeheraPasswordPolicy = "1.3.6.1.4.1.42.2.27.8.5.1"

// Ldap Behera Password Policy Draft 10 (https://tools.ietf.org/html/draft-behera-ldap-password-policy-10)
const (
	BeheraPasswordExpired             = 0
	BeheraAccountLocked               = 1
	BeheraChangeAfterReset            = 2
	BeheraPasswordModNotAllowed       = 3
	BeheraMustSupplyOldPassword       = 4
	BeheraInsufficientPasswordQuality = 5
	BeheraPasswordTooShort            = 6
	BeheraPasswordTooYoung            = 7
	BeheraPasswordInHistory           = 8
)

// BeheraPasswordPolicyErrorMap contains human readable descriptions of Behera Password Policy error codes
var BeheraPasswordPolicyErrorMap = map[int8]string{
	BeheraPasswordExpired:             "Password expired",
	BeheraAccountLocked:               "Account locked",
	BeheraChangeAfterReset:            "Password must be changed",
	BeheraPasswordModNotAllowed:       "Policy prevents password modification",
	BeheraMustSupplyOldPassword:       "Policy requires old password in order to change password",
	BeheraInsufficientPasswordQuality: "Password fails quality checks",
	BeheraPasswordTooShort:            "Password is too short for policy",
	BeheraPasswordTooYoung:            "Password has been changed too recently",
	BeheraPasswordInHistory:           "New password is in list of old passwords",
}

// BeheraPasswordPolicy implements the control described in https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
type BeheraPasswordPolicy struct {
	// Expire contains the number of seconds before a password will expire
	Expire int64
	// Grace indicates the remaining number of times a user will be allowed to authenticate with an expired password
	Grace int64
	// Error indicates the error code
	Error int8
	// ErrorString is a human readable error
	ErrorString string
	// Critical is the criticality indicated by the client
	Critical bool
}

// OID is part of the Control interface
func (c *BeheraPasswordPolicy) OID() string {
	return ControlOIDBeheraPasswordPolicy
}

// Name is part of the Control interface
func (c *BeheraPasswordPolicy) Name() string {
	return "Password Policy - Behera Draft"
}

// Encode encodes the BeheraPasswordPolicy control.
//
//       PasswordPolicyResponseValue ::= SEQUENCE {
//         warning [0] CHOICE {
//            timeBeforeExpiration [0] INTEGER (0 .. maxInt),
//            graceAuthNsRemaining [1] INTEGER (0 .. maxInt) } OPTIONAL,
//         error   [1] ENUMERATED {
//            passwordExpired             (0),
//            accountLocked               (1),
//            changeAfterReset            (2),
//            passwordModNotAllowed       (3),
//            mustSupplyOldPassword       (4),
//            insufficientPasswordQuality (5),
//            passwordTooShort            (6),
//            passwordTooYoung            (7),
//            passwordInHistory           (8) } OPTIONAL }
func (c *BeheraPasswordPolicy) Encode() *ber.Packet {
	if c.Grace < 0 && c.Expire < 0 && c.Error < 0 {
		return Encode(c, nil)
	}
	val := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control Value",
	)

	if c.Grace >= 0 || c.Expire >= 0 {
		var p *ber.Packet
		if c.Expire >= 0 {
			p = ber.NewInteger(
				ber.ClassContext, ber.TypePrimitive, ber.Tag(0), c.Expire, "Time Before Expiration",
			)
		} else {
			p = ber.NewInteger(
				ber.ClassContext, ber.TypePrimitive, ber.Tag(1), c.Grace, "graceAuthNsRemaining",
			)
		}
		wp := ber.Encode(ber.ClassContext, ber.TypeConstructed, ber.Tag(0), nil, "Warning Packet")
		wp.AppendChild(p)
		val.AppendChild(wp)
	}

	if c.Error >= 0 {
		p := ber.NewInteger(
			ber.ClassContext, ber.TypePrimitive, ber.Tag(1), c.Error, BeheraPasswordPolicyErrorMap[c.Error],
		)
		val.AppendChild(p)
	}

	return Encode(c, val)
}

// Criticality is part of the Control interface
func (c *BeheraPasswordPolicy) Criticality() bool {
	return c.Critical
}

// NewBeheraPasswordPolicy returns a new BeheraPasswordPolicy control initialized
// with the required values
func NewBeheraPasswordPolicy() *BeheraPasswordPolicy {
	return &BeheraPasswordPolicy{
		Expire: -1,
		Grace:  -1,
		Error:  -1,
	}
}

func decodeBehera(_ string, criticality bool, pkt *ber.Packet) (Control, error) {
	ctrl := NewBeheraPasswordPolicy()
	ctrl.Critical = criticality
	if pkt == nil { // as sent from client to server
		return ctrl, nil
	}
	// fmt.Printf("PACKET=%x\n", pkt.Bytes())

	for _, child := range pkt.Children {
		switch child.Tag {
		case 0:
			val, err := ber.ParseInt64(child.Children[0].Data.Bytes())
			child.Description = "Warning Packet"
			if err != nil {
				return nil, fmt.Errorf("ParseInt64: %s", err)
			}
			switch child.Children[0].Tag {
			case 0:
				child.Children[0].Description = "Expire Time"
				ctrl.Expire = val
			case 1:
				child.Children[0].Description = "Grace Time"
				ctrl.Grace = val
			default:
				return nil, fmt.Errorf("invalid tag %d on warning packet child", child.Children[0].Tag)
			}
		case 1:
			child.Description = "Error Packet"
			val, err := ber.ParseInt64(child.Data.Bytes())
			if err != nil {
				return nil, fmt.Errorf("ParseInt64: %s", err)
			}
			ctrl.Error = int8(val)
			ctrl.ErrorString = BeheraPasswordPolicyErrorMap[ctrl.Error]
			child.Description += ": " + ctrl.ErrorString

		default:
			return nil, fmt.Errorf("invalid tag on child: %d", child.Tag)
		}
	}
	return ctrl, nil
}
