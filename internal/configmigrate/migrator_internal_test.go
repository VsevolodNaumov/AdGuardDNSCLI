package configmigrate

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
)

func TestFieldChainVal(t *testing.T) {
	t.Parallel()

	obj := yObj{
		"nested": yObj{
			"nested": yObj{
				"int":    42,
				"string": "hello",
			},
			"not_yobj": "string",
		},
		"not_yobj": "string",
	}

	testCases := []struct {
		name       string
		wantErrMsg string
		keys       []string
	}{{
		name:       "valid_chain",
		wantErrMsg: "",
		keys:       []string{"nested", "nested", "string"},
	}, {
		name:       "invalid_chain",
		wantErrMsg: "nested: not_yobj: unexpected type string(string)",
		keys:       []string{"nested", "not_yobj", "int"},
	}, {
		name:       "missing_key",
		wantErrMsg: "nested: nested: missing: no value",
		keys:       []string{"nested", "nested", "missing"},
	}, {
		name:       "bad_type",
		wantErrMsg: "nested: nested: int: unexpected type int(42)",
		keys:       []string{"nested", "nested", "int"},
	}, {
		name:       "single_success",
		wantErrMsg: "",
		keys:       []string{"not_yobj"},
	}, {
		name: "single_failure",
		wantErrMsg: "nested: unexpected type map[string]interface " +
			"{}(map[nested:map[int:42 string:hello] not_yobj:string])",
		keys: []string{"nested"},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := fieldChainVal[string](obj, tc.keys...)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}
