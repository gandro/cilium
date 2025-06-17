package lib

type Attachment interface {
	IfName() string
	IPAM() IPAMAllocationRequest
}
