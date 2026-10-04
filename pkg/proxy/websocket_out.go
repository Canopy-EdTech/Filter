package proxy

import (
	"encoding/binary"
	"errors"

	"github.com/Canopy-EdTech/Filter/pkg/filter"
)

const maxWebSocketFrame = 16 * 1024 * 1024

var errWebSocketBlocked = errors.New("websocket message blocked by policy")

// Write receives raw client-to-server bytes in arbitrary chunks. It reassembles
// frames, scans complete text messages for blocked keywords, and forwards
// everything else untouched. A blocked message ends the connection.
func (f *webSocketFilter) Write(p []byte) (int, error) {
	if f.outBlocked {
		return 0, errWebSocketBlocked
	}
	f.outBuf = append(f.outBuf, p...)

	for {
		frame, payload, opcode, fin, ok, err := nextClientFrame(f.outBuf)
		if err != nil {
			return 0, err
		}
		if !ok {
			return len(p), nil
		}
		// Copy: frame aliases outBuf, which later appends may reuse.
		frame = append([]byte(nil), frame...)
		f.outBuf = f.outBuf[len(frame):]

		if err := f.handleClientFrame(frame, payload, opcode, fin); err != nil {
			return 0, err
		}
	}
}

func (f *webSocketFilter) handleClientFrame(frame, payload []byte, opcode byte, fin bool) error {
	switch {
	case opcode >= 8: // control frames may interleave with fragmented messages
		return f.forward(frame)
	case opcode == 1 || (opcode == 0 && f.outKind == 1):
		if opcode == 1 {
			f.outKind = 1
			f.outPayload = append(f.outPayload[:0], payload...)
			f.outFrames = append(f.outFrames[:0], frame...)
		} else {
			f.outPayload = append(f.outPayload, payload...)
			f.outFrames = append(f.outFrames, frame...)
		}
		if !fin {
			return nil
		}
		f.outKind = 0
		decision, reason := f.checkOutgoing(f.outPayload)
		if decision == filter.Block {
			f.outBlocked = true
			f.reportBlock(reason)
			return errWebSocketBlocked
		}
		return f.forward(f.outFrames)
	default: // binary messages and their continuations pass through
		if opcode == 2 {
			f.outKind = 2
		}
		if fin {
			f.outKind = 0
		}
		return f.forward(frame)
	}
}

func (f *webSocketFilter) forward(data []byte) error {
	_, err := f.ReadWriter.Write(data)
	return err
}

func (f *webSocketFilter) checkOutgoing(payload []byte) (filter.Decision, filter.BlockReason) {
	return checkVariants(payload, func(b []byte) (filter.Decision, filter.BlockReason) {
		return f.engine.CheckRequestBodyWithReason(f.resp.Request, b)
	})
}

// nextClientFrame parses one complete frame from the start of buf. ok is false
// when buf holds only part of a frame. payload is returned unmasked.
func nextClientFrame(buf []byte) (frame, payload []byte, opcode byte, fin, ok bool, err error) {
	if len(buf) < 2 {
		return nil, nil, 0, false, false, nil
	}

	length := uint64(buf[1] & 0x7f)
	offset := 2
	switch length {
	case 126:
		if len(buf) < 4 {
			return nil, nil, 0, false, false, nil
		}
		length = uint64(binary.BigEndian.Uint16(buf[2:4]))
		offset = 4
	case 127:
		if len(buf) < 10 {
			return nil, nil, 0, false, false, nil
		}
		length = binary.BigEndian.Uint64(buf[2:10])
		offset = 10
	}
	if length > maxWebSocketFrame {
		return nil, nil, 0, false, false, errors.New("websocket frame exceeds inspection limit")
	}

	masked := buf[1]&0x80 != 0
	var maskKey []byte
	if masked {
		if len(buf) < offset+4 {
			return nil, nil, 0, false, false, nil
		}
		maskKey = buf[offset : offset+4]
		offset += 4
	}

	total := offset + int(length)
	if len(buf) < total {
		return nil, nil, 0, false, false, nil
	}

	payload = append([]byte(nil), buf[offset:total]...)
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return buf[:total], payload, buf[0] & 0x0f, buf[0]&0x80 != 0, true, nil
}
