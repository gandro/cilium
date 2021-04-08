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

package sink

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hubble/recorder/pcap"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "recorder-sink")

// Statistics contains the statistics for a pcap sink
type Statistics struct {
	PacketsWritten uint64
	BytesWritten   uint64
	PacketsLost    uint64
	BytesLost      uint64
}

// record is a captured packet which will be written to file in the pcap format
type record struct {
	timestamp time.Time
	ruleID    uint16
	inclLen   uint32
	origLen   uint32
	data      []byte
}

// Dispatch implements consumer.MonitorConsumer and dispatches incoming
// recorder captures to registered sinks based on their rule ID.
type Dispatch struct {
	mutex lock.RWMutex

	startBootTime int64
	startWallTime time.Time

	sinkQueueSize int
	sinkByRuleID  map[uint16]*sink
}

// NewDispatch creates a new sink dispatcher. Each registered sink may have a
// queue of up to sinkQueueSize pending captures.
func NewDispatch(sinkQueueSize int) (*Dispatch, error) {
	bootTime, wallTime, err := getTimeNow()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain boot time clock: %w", err)
	}

	return &Dispatch{
		startBootTime: bootTime,
		startWallTime: wallTime,
		sinkQueueSize: sinkQueueSize,
		sinkByRuleID:  map[uint16]*sink{},
	}, nil
}

// RegisterSink registers a new sink for the given rule ID. Any captures with a
// matching rule ID will be forwarded to the pcap sink w. The sink will
// initialize the pcap file with the provided header.
func (d *Dispatch) RegisterSink(ruleID uint16, w pcap.RecordWriter, header pcap.Header) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, ok := d.sinkByRuleID[ruleID]; ok {
		return fmt.Errorf("sink for rule id %d already registered", ruleID)
	}

	d.sinkByRuleID[ruleID] = startSink(w, header, d.sinkQueueSize)
	return nil
}

// UnregisterSink will stop and unregister the sink for the given ruleID.
// It waits for any pending packets to be forwarded to the sink before closing
// it and returns the final statistics.
func (d *Dispatch) UnregisterSink(ruleID uint16) (stats Statistics, err error) {
	d.mutex.Lock()
	s, ok := d.sinkByRuleID[ruleID]
	delete(d.sinkByRuleID, ruleID)
	// unlock early to avoid holding the lock during s.close() which may block
	d.mutex.Unlock()

	if !ok {
		return Statistics{}, fmt.Errorf("no sink found for rule id %d", ruleID)
	}

	err = s.close()
	stats = s.copyStats()
	return stats, err
}

// SinkStatistics returns the current statistics for the sink with the given ruleID
func (d *Dispatch) SinkStatistics(ruleID uint16) (stats Statistics, ok bool) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if s, found := d.sinkByRuleID[ruleID]; found {
		return s.copyStats(), true
	}

	return Statistics{}, false
}

func (d *Dispatch) decodeRecordCaptureLocked(data []byte) (rec record, err error) {
	dataLen := uint32(len(data))
	if dataLen < monitor.RecorderCaptureLen {
		return record{}, fmt.Errorf("not enough data to decode capture message: %d", dataLen)
	}

	// This needs to stay in sync with struct capture_msg from
	// bpf/include/pcap.h.
	// We could use binary.Read on monitor.RecorderCapture, but since it
	// requires reflection, it is too slow to use on the critical path here.
	const (
		offsetRuleID         = 2
		offsetBootTime       = 8
		offsetCaptureLength  = 16
		offsetOriginalLength = 20
	)
	n := byteorder.Native
	ruleID := n.Uint16(data[offsetRuleID:])
	bootTime := n.Uint64(data[offsetBootTime:])
	capLen := n.Uint32(data[offsetCaptureLength:])
	origLen := n.Uint32(data[offsetOriginalLength:])

	// data may contain trailing garbage from the perf ring buffer
	// https://lore.kernel.org/patchwork/patch/1244339/
	packetEnd := monitor.RecorderCaptureLen + capLen
	if dataLen < packetEnd {
		return record{}, fmt.Errorf("capture record too short: want:%d < got:%d", dataLen, packetEnd)
	}
	packet := data[monitor.RecorderCaptureLen:packetEnd]

	return record{
		timestamp: d.bootTimeToWallTimeLocked(int64(bootTime)),
		ruleID:    ruleID,
		inclLen:   capLen,
		origLen:   origLen,
		data:      packet,
	}, nil
}

func (d *Dispatch) bootTimeToWallTimeLocked(bootTime int64) time.Time {
	elapsedSinceStart := time.Duration(bootTime - d.startBootTime)
	return d.startWallTime.Add(elapsedSinceStart)
}

func getTimeNow() (bootTime int64, wallTime time.Time, err error) {
	var bootTimespec unix.Timespec

	// Ideally we would use __vdso_clock_gettime for both clocks here, to have
	// as little overhead as possible such that the two timestamps are taken
	// as close together as possible. time.Now() will actually use VDSO on
	// Go 1.9+, but the unix.ClockGettime call is a regular system call for
	// now.
	wallTime = time.Now()
	err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &bootTimespec)
	if err != nil {
		return 0, time.Time{}, err
	}

	return bootTimespec.Nano(), wallTime, nil
}

// NotifyAgentEvent implements consumer.MonitorConsumer
func (d *Dispatch) NotifyPerfEvent(data []byte, cpu int) {
	if len(data) == 0 || data[0] != monitorAPI.MessageTypeRecCapture {
		return
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	rec, err := d.decodeRecordCaptureLocked(data)
	if err != nil {
		log.WithError(err).Warning("Failed to parse capture record")
		return
	}

	// We silently drop records with unknown rule ids
	if s, ok := d.sinkByRuleID[rec.ruleID]; ok {
		s.enqueue(rec)
	}
}

// NotifyPerfEventLost implements consumer.MonitorConsumer
func (d *Dispatch) NotifyPerfEventLost(numLostEvents uint64, cpu int) {
	log.WithFields(logrus.Fields{
		"numEvents": numLostEvents,
		"cpu":       cpu,
	}).Warning("Perf ring buffer events lost. This may affect captured packets.")
}

// NotifyAgentEvent implements consumer.MonitorConsumer
func (d *Dispatch) NotifyAgentEvent(typ int, message interface{}) {
	// ignored
}
