package requirementsourcecodec

import (
	"strconv"
	"strings"
)

type diagnosticPath struct {
	lookup   string
	reported string
}

func resolveModelPath(wire document, path string) diagnosticPath {
	segments := modelPathSegments(path)
	if len(segments) == 0 {
		return diagnosticPath{}
	}
	switch segments[0] {
	case "requirements":
		return resolveRequirementPath(wire, segments)
	case "profiles":
		return resolveIdentifiedPath(segments, "profiles", len(wire.Profiles), func(index int) string { return wire.Profiles[index].ProfileID })
	case "nonClaimDefinitions":
		return resolveIdentifiedPath(segments, "nonClaimDefinitions", len(wire.NonClaimDefinitions), func(index int) string { return wire.NonClaimDefinitions[index].NonClaimID })
	case "vocabulary":
		return resolveIdentifiedPath(segments, "vocabulary", len(wire.Vocabulary), func(index int) string { return wire.Vocabulary[index].TermID })
	default:
		return conventionalModelPath(segments)
	}
}

func resolveRequirementPath(wire document, segments []string) diagnosticPath {
	if len(segments) < 2 {
		return conventionalModelPath(segments)
	}
	for groupIndex, groupValue := range wire.Groups {
		for memberIndex, memberValue := range groupValue.Members {
			if memberValue.RequirementID != segments[1] {
				continue
			}
			base := pointer("groups", groupIndex, "members", memberIndex)
			tail := segments[2:]
			if len(tail) == 0 {
				return sameDiagnosticPath(base)
			}
			if isMetadataField(tail[0]) {
				base = metadataOwnerPath(wire, groupValue, memberValue, groupIndex, memberIndex, tail[0])
				base = joinPointer(base, tail[0])
				tail = tail[1:]
			}
			return appendSafeSegments(base, tail)
		}
	}
	return diagnosticPath{lookup: "/groups", reported: "/groups/<entry>"}
}

func metadataOwnerPath(wire document, groupValue group, memberValue member, groupIndex int, memberIndex int, field string) string {
	memberBase := pointer("groups", groupIndex, "members", memberIndex, "fields")
	if metadataFieldPresent(memberValue.Fields, field) || groupValue.ProfileID == "" {
		return memberBase
	}
	for profileIndex, profileValue := range wire.Profiles {
		if profileValue.ProfileID == groupValue.ProfileID && metadataFieldPresent(profileValue.Fields, field) {
			return pointer("profiles", profileIndex, "fields")
		}
	}
	return memberBase
}

func metadataFieldPresent(fields metadataFields, field string) bool {
	switch field {
	case "ownerId":
		return fields.OwnerID != nil
	case "claimLevel":
		return fields.ClaimLevel != nil
	case "riskClass":
		return fields.RiskClass != nil
	case "nonClaimRefs":
		return fields.NonClaimRefs != nil
	case "lifecycle":
		return fields.Lifecycle != nil
	case "deferral":
		return fields.Deferral != nil
	case "updatePolicy":
		return fields.UpdatePolicy != nil
	default:
		return false
	}
}

func isMetadataField(value string) bool {
	switch value {
	case "ownerId", "claimLevel", "riskClass", "nonClaimRefs", "lifecycle", "deferral", "updatePolicy":
		return true
	default:
		return false
	}
}

func resolveIdentifiedPath(segments []string, root string, count int, identity func(int) string) diagnosticPath {
	if len(segments) < 2 {
		return conventionalModelPath(segments)
	}
	if index, err := strconv.Atoi(segments[1]); err == nil && index >= 0 && index < count {
		return appendSafeSegments(pointer(root, index), segments[2:])
	}
	for index := 0; index < count; index++ {
		if identity(index) == segments[1] {
			return appendSafeSegments(pointer(root, index), segments[2:])
		}
	}
	return diagnosticPath{lookup: "/" + root, reported: "/" + root + "/<entry>"}
}

func conventionalModelPath(segments []string) diagnosticPath {
	lookup := ""
	reported := ""
	dynamicEntry := false
	for _, segment := range segments {
		lookup = joinPointer(lookup, segment)
		reportedSegment := segment
		if dynamicEntry {
			reportedSegment = "<entry>"
			dynamicEntry = false
		}
		reported = joinPointer(reported, reportedSegment)
		if segment == "values" {
			dynamicEntry = true
		}
	}
	return diagnosticPath{lookup: lookup, reported: reported}
}

func appendSafeSegments(base string, segments []string) diagnosticPath {
	lookup := base
	reported := base
	for _, segment := range segments {
		lookup = joinPointer(lookup, segment)
		reported = joinPointer(reported, segment)
	}
	return diagnosticPath{lookup: lookup, reported: reported}
}

func sameDiagnosticPath(path string) diagnosticPath {
	return diagnosticPath{lookup: path, reported: path}
}

func pointer(values ...any) string {
	result := ""
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			result = joinPointer(result, typed)
		case int:
			result = joinPointer(result, strconv.Itoa(typed))
		default:
			panic("unsupported pointer component")
		}
	}
	return result
}

func closestLocation(locations map[string]rawLocation, path string) rawLocation {
	for current := path; ; {
		if location, exists := locations[current]; exists {
			return location
		}
		index := strings.LastIndex(current, "/")
		if index < 0 {
			break
		}
		current = current[:index]
	}
	return locations[""]
}

func modelPathSegments(path string) []string {
	segments := make([]string, 0, 8)
	for offset := 0; offset < len(path); {
		switch path[offset] {
		case '.':
			offset++
		case '[':
			end := strings.IndexByte(path[offset:], ']')
			if end < 0 {
				return segments
			}
			end += offset
			if _, err := strconv.Atoi(path[offset+1 : end]); err == nil {
				segments = append(segments, path[offset+1:end])
			}
			offset = end + 1
		default:
			end := offset
			for end < len(path) && path[end] != '.' && path[end] != '[' {
				end++
			}
			if end > offset {
				segments = append(segments, path[offset:end])
			}
			offset = end
		}
	}
	return segments
}
