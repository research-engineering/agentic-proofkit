package requirementdiff

import "sort"

type changeOrderKey struct {
	EntityID    string
	JSONPointer string
	ChangeClass string
	ChangeID    string
}

func canonicalChangeOrderKey(change map[string]any) changeOrderKey {
	return changeOrderKey{
		EntityID:    change["entityId"].(string),
		JSONPointer: change["jsonPointer"].(string),
		ChangeClass: change["changeClass"].(string),
		ChangeID:    change["changeId"].(string),
	}
}

func sortChangesCanonical(changes []any) {
	sort.Slice(changes, func(left, right int) bool {
		return changeOrderLess(canonicalChangeOrderKey(changes[left].(map[string]any)), canonicalChangeOrderKey(changes[right].(map[string]any)))
	})
}

func changeOrderLess(left, right changeOrderKey) bool {
	if left.EntityID != right.EntityID {
		return left.EntityID < right.EntityID
	}
	if left.JSONPointer != right.JSONPointer {
		return left.JSONPointer < right.JSONPointer
	}
	if left.ChangeClass != right.ChangeClass {
		return left.ChangeClass < right.ChangeClass
	}
	return left.ChangeID < right.ChangeID
}
