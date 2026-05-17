package pa

import (
	"strings"

	"agent/internal/service/catalog"

	"google.golang.org/protobuf/types/known/structpb"
)

func structFieldString(value *structpb.Struct, key string) string {
	if value == nil {
		return ""
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil {
		return ""
	}
	return field.GetStringValue()
}

func structFieldBool(value *structpb.Struct, key string) bool {
	if value == nil {
		return false
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil {
		return false
	}
	return field.GetBoolValue()
}

func structFieldNumber(value *structpb.Struct, key string) (float64, bool) {
	if value == nil {
		return 0, false
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil {
		return 0, false
	}
	return field.GetNumberValue(), true
}

func structFieldNumberDefault(value *structpb.Struct, key string) float64 {
	number, _ := structFieldNumber(value, key)
	return number
}

func structFieldStringList(value *structpb.Struct, key string) []string {
	if value == nil {
		return nil
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil || field.GetListValue() == nil {
		return nil
	}
	values := field.GetListValue().GetValues()
	stringsOut := make([]string, 0, len(values))
	for _, item := range values {
		if item == nil {
			continue
		}
		stringsOut = append(stringsOut, item.GetStringValue())
	}
	return stringsOut
}

func structFieldResourceList(value *structpb.Struct, keys ...string) []catalog.Resource {
	if value == nil {
		return nil
	}
	var resources []catalog.Resource
	for _, key := range keys {
		field, ok := value.GetFields()[key]
		if !ok || field == nil || field.GetListValue() == nil {
			continue
		}
		for _, item := range field.GetListValue().GetValues() {
			if item == nil || item.GetStructValue() == nil {
				continue
			}
			fields := item.GetStructValue().GetFields()
			resource := catalog.Resource{
				FQDN:       strings.TrimSpace(fields["fqdn"].GetStringValue()),
				ResourceID: strings.TrimSpace(fields["resource_id"].GetStringValue()),
				Protocol:   strings.TrimSpace(fields["protocol"].GetStringValue()),
			}
			if numberField := fields["port"]; numberField != nil {
				resource.Port = int(numberField.GetNumberValue())
			}
			resources = append(resources, resource)
		}
	}
	return catalog.NormalizeResources(resources)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
