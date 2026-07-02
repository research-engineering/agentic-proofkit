package contractenv

import (
	"fmt"
	"reflect"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func Object(raw any, expectedSchema string, context string, allowedKeys ...string) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s contract envelope must be an object", context)
	}
	if len(allowedKeys) > 0 {
		keys := append([]string{"schema"}, allowedKeys...)
		if err := admit.KnownKeys(record, keys, context+" contract envelope"); err != nil {
			return nil, err
		}
	}
	if record["schema"] != expectedSchema {
		return nil, fmt.Errorf("%s contract envelope schema drift", context)
	}
	return cloneMap(record), nil
}

func ObjectField(record map[string]any, field string, context string) (map[string]any, error) {
	value, ok := record[field].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must declare object %s", context, field)
	}
	return cloneMap(value), nil
}

func StringField(record map[string]any, field string, context string) (string, error) {
	value, ok := record[field].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("%s must declare string %s", context, field)
	}
	return value, nil
}

func StringArrayField(record map[string]any, field string, context string) ([]string, error) {
	values, ok := record[field].([]any)
	if !ok {
		return nil, fmt.Errorf("%s must declare string array %s", context, field)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("%s must declare string array %s", context, field)
		}
		result = append(result, text)
	}
	return result, nil
}

func cloneMap(record map[string]any) map[string]any {
	result := make(map[string]any, len(record))
	for key, value := range record {
		result[key] = cloneValue(value)
	}
	return result
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case map[string]string:
		result := make(map[string]string, len(typed))
		for key, item := range typed {
			result[key] = item
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneValue(item)
		}
		return result
	case []string:
		return append([]string{}, typed...)
	case []map[string]any:
		result := make([]map[string]any, len(typed))
		for index, item := range typed {
			result[index] = cloneMap(item)
		}
		return result
	case []map[string]string:
		result := make([]map[string]string, len(typed))
		for index, item := range typed {
			cloned := make(map[string]string, len(item))
			for key, value := range item {
				cloned[key] = value
			}
			result[index] = cloned
		}
		return result
	default:
		return cloneReflectedValue(reflect.ValueOf(value))
	}
}

func cloneReflectedValue(value reflect.Value) any {
	if !value.IsValid() {
		return nil
	}
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		if value.IsNil() {
			return nil
		}
		return cloneReflectedValue(value.Elem())
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return value.Interface()
		}
		result := make(map[string]any, value.Len())
		iter := value.MapRange()
		for iter.Next() {
			result[iter.Key().String()] = cloneReflectedValue(iter.Value())
		}
		return result
	case reflect.Slice, reflect.Array:
		result := make([]any, 0, value.Len())
		for index := 0; index < value.Len(); index++ {
			result = append(result, cloneReflectedValue(value.Index(index)))
		}
		return result
	default:
		return value.Interface()
	}
}
