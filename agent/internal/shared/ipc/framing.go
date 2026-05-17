package ipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

func WriteJSON(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal ipc frame: %w", err)
	}
	return WriteFrame(writer, data)
}

func WriteFrame(writer io.Writer, data []byte) error {
	if writer == nil {
		return fmt.Errorf("ipc frame writer is nil")
	}
	if len(data) > MaxMessageBytes {
		return fmt.Errorf("ipc frame exceeds %d bytes", MaxMessageBytes)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err := writer.Write(header[:]); err != nil {
		return fmt.Errorf("write ipc frame header: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("write ipc frame body: %w", err)
	}
	return nil
}

func ReadFrame(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, fmt.Errorf("ipc frame reader is nil")
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > MaxMessageBytes {
		return nil, fmt.Errorf("ipc frame exceeds %d bytes", MaxMessageBytes)
	}
	data := make([]byte, int(length))
	if length == 0 {
		return data, nil
	}
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, err
	}
	return data, nil
}
