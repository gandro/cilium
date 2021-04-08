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
	"errors"
	"time"

	"github.com/cilium/cilium/pkg/hubble/recorder/pcap"
	"github.com/cilium/cilium/pkg/lock"
)

const closeTimeout = 30 * time.Second

// sink wraps a pcap.RecordWriter by adding a queue and managing its statistics
// regarding written and dropped packets and bytes.
type sink struct {
	lock.RWMutex
	queue chan record
	err   chan error
	stats Statistics
}

// startSink creates a queue and go routine for the sink. The spawned go
// routine must be stopped via a call to close()
func startSink(w pcap.RecordWriter, hdr pcap.Header, queueSize int) *sink {
	s := &sink{
		queue: make(chan record, queueSize),
		err:   make(chan error, 1),
	}

	go func() {
		var lastErr error
		// this defer executes w.Close(), but also makes sure lastErr
		// is sent to the channel upon exit
		defer func() {
			err := w.Close()
			if lastErr == nil {
				lastErr = err
			}
			s.err <- lastErr
		}()

		if err := w.WriteHeader(hdr); err != nil {
			lastErr = err
			return
		}

		// s.queue will be closed when the sink is unregistered
		for rec := range s.queue {
			pcapRecord := pcap.Record{
				Timestamp:      rec.timestamp,
				CaptureLength:  rec.inclLen,
				OriginalLength: rec.origLen,
			}

			if err := w.WriteRecord(pcapRecord, rec.data); err != nil {
				lastErr = err
				return
			}

			s.Lock()
			s.stats.BytesWritten += uint64(rec.inclLen)
			s.stats.PacketsWritten++
			s.Unlock()
		}
	}()

	return s
}

// close waits for this sink to drain its queue and then closes the underlying
// pcap writer
func (s *sink) close() error {
	s.Lock()
	defer s.Unlock()

	// closing the queue will cause drain to exit and send back an error
	// value in the err channel
	close(s.queue)

	t := time.NewTimer(closeTimeout)
	defer t.Stop()

	select {
	case err := <-s.err:
		return err
	case <-t.C:
		return errors.New("timed out waiting for sink to close")
	}
}

// enqueue submits a new record to this sink. If the sink is not keeping up,
// the record is dropped and the sink statistics are updated accordingly
func (s *sink) enqueue(rec record) {
	s.Lock()
	defer s.Unlock()

	select {
	// mutex must be held when sending to avoid concurrent close
	case s.queue <- rec:
		// successfully enqueued rec in sink
		return
	default:
	}

	// sink queue was full, update statistics
	s.stats.BytesLost += uint64(rec.inclLen)
	s.stats.PacketsLost++
}

// copyStats creates a snapshot of the current statistics
func (s *sink) copyStats() Statistics {
	s.RLock()
	stats := s.stats
	s.RUnlock()

	return stats
}
