package lib

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type IPAMAllocationRequest interface {
	Owner() string
	Pool() string
}

type IPAMReleaseFunc func(context.Context)

type IPAMAllocator interface {
	AllocateIPs(req IPAMAllocationRequest) (*models.IPAMResponse, IPAMReleaseFunc, error)
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

type ciliumAgentIPAMAllocator struct {
	client *client.Client
	logger *slog.Logger
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

func (c *ciliumAgentIPAMAllocator) AllocateIPs(req IPAMAllocationRequest) (*models.IPAMResponse, IPAMReleaseFunc, error) {
	ipam, err := c.client.IPAMAllocate("", req.Owner(), req.Pool(), true)
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
