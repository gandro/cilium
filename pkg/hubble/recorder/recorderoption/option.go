// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package recorderoption

// Options stores all the configuration values for the Hubble recorder.
type Options struct {
	// MonitorQueueSize is the number of events which may be queued by the monitor
	// before the Recorder needs to start dropping captured packets
	MonitorQueueSize int
	// StoragePath is the path to the directory where the captured pcap files
	// will be stored
	StoragePath string
}

// Default contains the default values
var Default = Options{
	StoragePath:      "",
	MonitorQueueSize: 128,
}

// Option customizes then configuration of the Hubble recorder.
type Option func(o *Options) error
