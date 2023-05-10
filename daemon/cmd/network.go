// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/network"
)

type getNetworkAttachment struct {
	daemon *Daemon
}

// NewGetNetworkAttachmentHandler returns a new /network/attachment handler
func NewGetNetworkAttachmentHandler(d *Daemon) restapi.GetNetworkAttachmentHandler {
	return &getNetworkAttachment{daemon: d}
}

func (g getNetworkAttachment) Handle(params restapi.GetNetworkAttachmentParams) middleware.Responder {
	//TODO implement me
	panic("implement me")

	return restapi.NewGetNetworkAttachmentOK().
		WithPayload(&models.NetworkAttachmentList{Attachments: nil})
}
