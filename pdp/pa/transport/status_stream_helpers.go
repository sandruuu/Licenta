package transport

import (
	"time"

	"pdp/pa/events"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

func sendStruct(stream grpc.ServerStream, payload map[string]interface{}) error {
	message, err := structpb.NewStruct(payload)
	if err != nil {
		return err
	}
	return stream.SendMsg(message)
}

func eventChannel(sub *events.Subscription) <-chan events.Event {
	if sub == nil {
		return nil
	}
	return sub.C
}

func statusExpiryTimer(expiresAt time.Time) *time.Timer {
	if expiresAt.IsZero() {
		return nil
	}
	wait := time.Until(expiresAt.UTC())
	if wait <= 0 {
		wait = time.Nanosecond
	}
	return time.NewTimer(wait)
}

func resetStatusExpiryTimer(timer *time.Timer, expiresAt time.Time) bool {
	if timer == nil || expiresAt.IsZero() {
		return false
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	wait := time.Until(expiresAt.UTC())
	if wait <= 0 {
		wait = time.Nanosecond
	}
	timer.Reset(wait)
	return true
}
