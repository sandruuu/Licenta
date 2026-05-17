package controlplane

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

func structFieldString(value *structpb.Struct, key string) string {
	if value == nil || value.GetFields()[key] == nil {
		return ""
	}
	return strings.TrimSpace(value.GetFields()[key].GetStringValue())
}

func nestedString(value *structpb.Struct, objectKey, key string) string {
	if value == nil || value.GetFields()[objectKey] == nil || value.GetFields()[objectKey].GetStructValue() == nil {
		return ""
	}
	return structFieldString(value.GetFields()[objectKey].GetStructValue(), key)
}

func intField(value *structpb.Struct, key string) (int, error) {
	if value == nil || value.GetFields()[key] == nil {
		return 0, fmt.Errorf("%s is required", key)
	}
	number := value.GetFields()[key].GetNumberValue()
	if number <= 0 || number != float64(int(number)) {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return int(number), nil
}

func optionalIntField(value *structpb.Struct, key string) (int, error) {
	if value == nil || value.GetFields()[key] == nil {
		return 0, nil
	}
	number := value.GetFields()[key].GetNumberValue()
	if number < 0 || number != float64(int(number)) {
		return 0, fmt.Errorf("%s must be a non-negative integer", key)
	}
	return int(number), nil
}

func timeField(value *structpb.Struct, key string) (time.Time, error) {
	text := structFieldString(value, key)
	if text == "" {
		return time.Time{}, fmt.Errorf("%s is required", key)
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339", key)
	}
	return parsed.UTC(), nil
}

func stringListField(value *structpb.Struct, key string, required bool) ([]string, error) {
	if value == nil {
		if required {
			return nil, fmt.Errorf("%s is required", key)
		}
		return nil, nil
	}
	field := value.GetFields()[key]
	if field == nil || field.GetListValue() == nil {
		if required {
			return nil, fmt.Errorf("%s must be a list", key)
		}
		return nil, nil
	}
	items := field.GetListValue().GetValues()
	values := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		if text := strings.TrimSpace(item.GetStringValue()); text != "" {
			values = append(values, text)
		}
	}
	return values, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
