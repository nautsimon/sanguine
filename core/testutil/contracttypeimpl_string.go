// Code generated by "stringer -type=contractTypeImpl -linecomment"; DO NOT EDIT.

package testutil

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[HomeType-0]
	_ = x[MessageHarnessType-1]
	_ = x[HomeHarnessType-2]
	_ = x[AttestationHarnessType-3]
	_ = x[TipsHarnessType-4]
	_ = x[HeaderHarnessType-5]
	_ = x[ReplicaManagerHarnessType-6]
	_ = x[UpdaterManagerType-7]
	_ = x[AttestationCollectorType-8]
	_ = x[ReplicaManagerType-9]
}

const _contractTypeImpl_name = "HomeMessageHarnessHomeHarnessAttestationHarnessTypeTipsHarnessTypeHeaderHarnessTypeReplicaManagerHarnessTypeUpdaterManagerAttestationCollectorReplicaManager"

var _contractTypeImpl_index = [...]uint8{0, 4, 18, 29, 51, 66, 83, 108, 122, 142, 156}

func (i contractTypeImpl) String() string {
	if i < 0 || i >= contractTypeImpl(len(_contractTypeImpl_index)-1) {
		return "contractTypeImpl(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _contractTypeImpl_name[_contractTypeImpl_index[i]:_contractTypeImpl_index[i+1]]
}
