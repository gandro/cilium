package lib

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	cniInvoke "github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

const (
	IPAMOwner Property "CiliumIPAMOwner"
	IPAMPoolName Property = "CiliumIPAMPoolName"
)

type IPAMReleaseFunc func(context.Context)

type IPAMAllocator interface {
	AllocateIPs(ctx context.Context, attachment *AttachmentInfo) (*models.IPAMResponse, IPAMReleaseFunc, error)
}

func IPv6IsEnabled(ipam *models.IPAMResponse) bool {
	if ipam == nil || ipam.Address.IPV6 == "" {
		return false
	}

	if ipam.HostAddressing == nil || ipam.HostAddressing.IPV6 == nil {
		return false
	}

	return ipam.HostAddressing.IPV6.Enabled
}

func IPv4IsEnabled(ipam *models.IPAMResponse) bool {
	if ipam == nil || ipam.Address.IPV4 == "" {
		return false
	}

	if ipam.HostAddressing == nil || ipam.HostAddressing.IPV4 == nil {
		return false
	}

	return ipam.HostAddressing.IPV4.Enabled
}

func NewIPAMAllocator(c CNIContext) IPAMAllocator {
	if c.CiliumConf.IpamMode == ipamOption.IPAMDelegatedPlugin {
		return &delegatedIPAMAllocator{
			args:       c.Args,
			netConf:    c.NetConf,
			ciliumConf: c.CiliumConf,
		}
	} else {
		return &ciliumAgentIPAMAllocator{
			cniArgs: c.CniArgs,
			client:  c.Client,
			logger:  c.Logger,
		}
	}
}

type ciliumAgentIPAMAllocator struct {
	cniArgs *types.ArgsSpec
	client  *client.Client
	logger  *slog.Logger
}

func (c *ciliumAgentIPAMAllocator) releaseIP(ip, pool string) {
	if ip != "" {
		if err := c.client.IPAMReleaseIP(ip, pool); err != nil {
			c.logger.Warn(
				"Unable to release IP",
				logfields.Error, err,
				logfields.IPAddr, ip,
				logfields.PoolName, pool,
			)
		}
	}
}

func (c *ciliumAgentIPAMAllocator) AllocateIPs(ctx context.Context, attachment *AttachmentProperties) (*models.IPAMResponse, IPAMReleaseFunc, error) {
	owner := cmp.Or(attachment.K8sPodNameAndNamespace(), GetProperty[string](attachment., IPAMOwner))
	pool := GetAttachmentProperty[string](attachment, IPAMPoolName)

	ipam, err := c.client.IPAMAllocate("", owner, pool, true)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to allocate IP via local cilium agent: %w", err)
	}

	if ipam.Address == nil {
		return nil, nil, errors.New("invalid IPAM response, missing addressing")
	}

	releaseFunc := func(context.Context) {
		if ipam.Address != nil {
			c.releaseIP(ipam.Address.IPV4, ipam.Address.IPV4PoolName)
			c.releaseIP(ipam.Address.IPV6, ipam.Address.IPV6PoolName)
		}
	}

	return ipam, releaseFunc, nil
}

type delegatedIPAMAllocator struct {
	args       *skel.CmdArgs
	netConf    *types.NetConf
	ciliumConf *models.DaemonConfigurationStatus
}

func (d *delegatedIPAMAllocator) AllocateIPs(ctx context.Context, attachment *AttachmentInfo) (*models.IPAMResponse, IPAMReleaseFunc, error) {
	ipamRawResult, err := cniInvoke.DelegateAdd(ctx, d.netConf.IPAM.Type, d.args.StdinData, nil)
	if err != nil {
		// Since IP allocation failed, there are no IPs to clean up, so we don't need to return a releaseFunc.
		return nil, nil, fmt.Errorf("failed to invoke delegated plugin ADD for IPAM: %w", err)
	}

	// CNI spec says if an error occurs, invoke DEL on the delegated plugin to release IPs.
	releaseFunc := func(ctx context.Context) {
		cniInvoke.DelegateDel(ctx, d.netConf.IPAM.Type, d.args.StdinData, nil)
	}

	ipamResult, err := cniTypesV1.NewResultFromResult(ipamRawResult)
	if err != nil {
		return nil, releaseFunc, fmt.Errorf("could not interpret delegated IPAM result for CNI version %s: %w", cniTypesV1.ImplementedSpecVersion, err)
	}

	// Translate the IPAM result into the same format as a response from Cilium agent.
	ipam := &models.IPAMResponse{
		HostAddressing: d.ciliumConf.Addressing,
		Address:        &models.AddressPair{},
	}

	// Safe to assume at most one IP per family. The K8s API docs say:
	// "Pods may be allocated at most 1 value for each of IPv4 and IPv6"
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/
	// Interface returned by IPAM should be treated as the uplink for the Pod as CNI spec introduced by:
	// https://github.com/containernetworking/cni/pull/1137
	masterMac := ""
	for _, iface := range ipamResult.Interfaces {
		if iface.Sandbox != "" {
			continue
		}

		if iface.Mac != "" {
			if ifMac, err := net.ParseMAC(iface.Mac); err != nil {
				return nil, releaseFunc, fmt.Errorf("failed to parse interface MAC %q: %w", iface.Mac, err)
			} else {
				masterMac = ifMac.String()
			}
		} else if iface.Name != "" {
			if uplink, err := safenetlink.LinkByName(iface.Name); err != nil {
				return nil, releaseFunc, fmt.Errorf("failed to get uplink %q: %w", iface.Name, err)
			} else {
				masterMac = uplink.Attrs().HardwareAddr.String()
			}
		}
		break
	}
	// Interface number could not be determined from IPAM result for now.
	// Set a static value zero before we have a proper solution.
	// option.Config.EgressMultiHomeIPRuleCompat also needs to be set to true.
	for _, ipConfig := range ipamResult.IPs {
		ipNet := ipConfig.Address
		if ipNet.IP.To4() != nil {
			if d.ciliumConf.Addressing.IPV4 != nil {
				ipam.Address.IPV4 = ipNet.String()
				ipam.IPV4 = &models.IPAMAddressResponse{
					IP:              ipNet.IP.String(),
					Gateway:         ipConfig.Gateway.String(),
					MasterMac:       masterMac,
					InterfaceNumber: "0",
				}
			}
		} else {
			if d.ciliumConf.Addressing.IPV6 != nil {
				ipam.Address.IPV6 = ipNet.String()
				ipam.IPV6 = &models.IPAMAddressResponse{
					IP:              ipNet.IP.String(),
					Gateway:         ipConfig.Gateway.String(),
					MasterMac:       masterMac,
					InterfaceNumber: "0",
				}
			}
		}
	}

	return ipam, releaseFunc, nil
}
