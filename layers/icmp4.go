package layers

import "unsafe"

const (
	ICMPv4TypeEchoReply              = 0
	ICMPv4TypeDestinationUnreachable = 3
	ICMPv4TypeSourceQuench           = 4
	ICMPv4TypeRedirect               = 5
	ICMPv4TypeEchoRequest            = 8
	ICMPv4TypeRouterAdvertisement    = 9
	ICMPv4TypeRouterSolicitation     = 10
	ICMPv4TypeTimeExceeded           = 11
	ICMPv4TypeParameterProblem       = 12
	ICMPv4TypeTimestampRequest       = 13
	ICMPv4TypeTimestampReply         = 14
	ICMPv4TypeInfoRequest            = 15
	ICMPv4TypeInfoReply              = 16
	ICMPv4TypeAddressMaskRequest     = 17
	ICMPv4TypeAddressMaskReply       = 18
)

const (
	// DestinationUnreachable
	ICMPv4CodeNet                 = 0
	ICMPv4CodeHost                = 1
	ICMPv4CodeProtocol            = 2
	ICMPv4CodePort                = 3
	ICMPv4CodeFragmentationNeeded = 4
	ICMPv4CodeSourceRoutingFailed = 5
	ICMPv4CodeNetUnknown          = 6
	ICMPv4CodeHostUnknown         = 7
	ICMPv4CodeSourceIsolated      = 8
	ICMPv4CodeNetAdminProhibited  = 9
	ICMPv4CodeHostAdminProhibited = 10
	ICMPv4CodeNetTOS              = 11
	ICMPv4CodeHostTOS             = 12
	ICMPv4CodeCommAdminProhibited = 13
	ICMPv4CodeHostPrecedence      = 14
	ICMPv4CodePrecedenceCutoff    = 15

	// TimeExceeded
	ICMPv4CodeTTLExceeded                    = 0
	ICMPv4CodeFragmentReassemblyTimeExceeded = 1

	// ParameterProblem
	ICMPv4CodePointerIndicatesError = 0
	ICMPv4CodeMissingOption         = 1
	ICMPv4CodeBadLength             = 2

	// Redirect
	// ICMPv4CodeNet  = same as for DestinationUnreachable
	// ICMPv4CodeHost = same as for DestinationUnreachable
	ICMPv4CodeTOSNet  = 2
	ICMPv4CodeTOSHost = 3
)

type ICMPv4 []byte

const LengthICMPv4 = 8

func (i *ICMPv4) GetType() uint8 {
	return *&(*i)[0]
}

func (i *ICMPv4) SetType(u uint8) {
	(*i)[0] = u
}

func (i *ICMPv4) GetCode() uint8 {
	return *&(*i)[1]
}

func (i *ICMPv4) SetCode(u uint8) {
	(*i)[1] = u
}

func (i *ICMPv4) GetChecksum() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*i)[2]))
}

func (i *ICMPv4) SetChecksum(u uint16) {
	(*i)[2] = (*(*[2]byte)(unsafe.Pointer(&u)))[0]
	(*i)[3] = (*(*[2]byte)(unsafe.Pointer(&u)))[1]
}

func (i *ICMPv4) GetID() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*i)[4]))
}

func (i *ICMPv4) SetID(u uint16) {
	(*i)[4] = (*(*[2]byte)(unsafe.Pointer(&u)))[0]
	(*i)[5] = (*(*[2]byte)(unsafe.Pointer(&u)))[1]
}

func (i *ICMPv4) GetSequence() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*i)[6]))
}

func (i *ICMPv4) SetSequence(u uint16) {
	(*i)[6] = (*(*[2]byte)(unsafe.Pointer(&u)))[0]
	(*i)[7] = (*(*[2]byte)(unsafe.Pointer(&u)))[1]
}
