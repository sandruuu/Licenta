package ipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const frameHeaderBytes = 4

func WriteFrame(writer io.Writer, payload []byte) error {
	if writer == nil {
		return fmt.Errorf("ipc writer is nil")
	}
	if len(payload) > MaxMessageBytes {
		return fmt.Errorf("ipc frame exceeds %d bytes", MaxMessageBytes)
	}
	var header [frameHeaderBytes]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writer.Write(header[:]); err != nil {
		return fmt.Errorf("write ipc frame header: %w", err)
	}
	if len(payload) == 0 {
		return nil
	}
	if _, err := writer.Write(payload); err != nil {
		return fmt.Errorf("write ipc frame payload: %w", err)
	}
	return nil
}

func ReadFrame(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, fmt.Errorf("ipc reader is nil")
	}
	var header [frameHeaderBytes]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, fmt.Errorf("read ipc frame header: %w", err)
	}
	messageSize := binary.BigEndian.Uint32(header[:])
	if messageSize > MaxMessageBytes {
		return nil, fmt.Errorf("ipc frame exceeds %d bytes", MaxMessageBytes)
	}
	payload := make([]byte, messageSize)
	if messageSize == 0 {
		return payload, nil
	}
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, fmt.Errorf("read ipc frame payload: %w", err)
	}
	return payload, nil
}

func WriteJSON(writer io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode ipc json frame: %w", err)
	}
	return WriteFrame(writer, payload)
}

func ReadJSON(reader io.Reader, target any) error {
	if target == nil {
		return fmt.Errorf("ipc json target is nil")
	}
	payload, err := ReadFrame(reader)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return fmt.Errorf("decode ipc json frame: %w", err)
	}
	return nil
}
