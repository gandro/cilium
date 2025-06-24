package lib

import (
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

type CNIContext struct {
	Logger     *slog.Logger
	Args       *skel.CmdArgs
	CniArgs    *types.ArgsSpec
	NetConf    *types.NetConf
	Client     *client.Client
	CiliumConf *models.DaemonConfigurationStatus
}

func (c *CNIContext) K8sPodName() string {
	return string(c.CniArgs.K8S_POD_NAMESPACE)
}

func (c *CNIContext) K8sPodNamespace() string {
	return string(c.CniArgs.K8S_POD_NAMESPACE)
}

func (c *CNIContext) K8sPodUID() string {
	return string(c.CniArgs.K8S_POD_UID)
}

func (c *CNIContext) K8sPodNameAndNamespace() string {
	if c.K8sPodName() == "" {
		return ""
	}
	return c.K8sPodNamespace() + "/" + c.K8sPodName()
}

type Hooks struct {
}
