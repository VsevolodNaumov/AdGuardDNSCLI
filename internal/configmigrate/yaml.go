package configmigrate

import (
	"fmt"
	"os"
	"strings"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
	"gopkg.in/yaml.v3"
)

// yObj is the convenience alias for YAML key-value object.
type yObj = map[string]any

// fieldVal returns the value of type T for key from obj.  It returns errors if
// the key is not found, the value is not set, or the value is not of type T.
func fieldVal[T any](obj yObj, key string) (v T, err error) {
	val, ok := obj[key]
	if !ok {
		return v, fmt.Errorf("%s: %w", key, errors.ErrNoValue)
	}

	if err = validate.NotNilInterface(key, val); err != nil {
		return v, err
	}

	v, ok = val.(T)
	if !ok {
		return v, fmt.Errorf("%s: unexpected type %T(%[2]v)", key, val)
	}

	return v, nil
}

// fieldChainVal goes through the chain of keys in obj, considering each nested
// value as a yObj, and returns the value of type T for the last key.  It
// returns errors if any key is not found, any value is not set, or any value is
// not of type yObj except for the last value, which should be of type T.  It
// panics if no keys are provided.
func fieldChainVal[T any](obj yObj, keys ...string) (v T, err error) {
	if err = validate.NotEmptySlice("keys", keys); err != nil {
		panic(err)
	}

	const errVerb = "%w"

	for i, key := range keys[:len(keys)-1] {
		obj, err = fieldVal[yObj](obj, key)
		if err != nil {
			chain := append(keys[:i], errVerb)

			return v, fmt.Errorf(strings.Join(chain, ": "), err)
		}
	}

	v, err = fieldVal[T](obj, keys[len(keys)-1])
	if err != nil {
		chain := append(keys[:len(keys)-1], errVerb)

		return v, fmt.Errorf(strings.Join(chain, ": "), err)
	}

	return v, nil
}

// readYAML reads the YAML file from filePath and returns the parsed YAML
// object.
func readYAML(filePath string) (obj yObj, data []byte, err error) {
	// #nosec G304 -- Trust the file path since it's constant now.
	data, err = os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading yaml document: %w", err)
	}

	err = yaml.Unmarshal(data, &obj)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding yaml document: %w", err)
	}

	return obj, data, nil
}
