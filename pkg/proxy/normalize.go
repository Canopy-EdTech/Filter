package proxy

import (
	"bytes"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Canopy-EdTech/Filter/pkg/filter"
)

// maxUnescapeRounds bounds how many nested layers of JSON string escaping
// (e.g. JSON embedded in a JSON string) are peeled off while scanning.
const maxUnescapeRounds = 4

// checkVariants runs check against data and then against progressively
// JSON-unescaped copies of it, so a phrase can't evade a keyword rule by being
// written as bad or inside an escaped nested JSON string.
func checkVariants(data []byte, check func([]byte) (filter.Decision, filter.BlockReason)) (filter.Decision, filter.BlockReason) {
	for round := 0; round <= maxUnescapeRounds; round++ {
		if decision, reason := check(data); decision == filter.Block {
			return decision, reason
		}
		next, changed := unescapeJSONStrings(data)
		if !changed {
			break
		}
		data = next
	}
	return filter.Accept, filter.BlockReason{}
}

// unescapeJSONStrings decodes JSON string escapes (\uXXXX including surrogate
// pairs, \", \\, \/, \n, \t, \r, \b, \f) wherever they appear in data.
// Malformed escapes are left untouched.
func unescapeJSONStrings(data []byte) ([]byte, bool) {
	if !bytes.Contains(data, []byte{'\\'}) {
		return data, false
	}

	out := make([]byte, 0, len(data))
	changed := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c != '\\' || i+1 >= len(data) {
			out = append(out, c)
			continue
		}

		switch next := data[i+1]; next {
		case '"', '\\', '/':
			out = append(out, next)
			i++
			changed = true
		case 'n':
			out = append(out, '\n')
			i++
			changed = true
		case 't':
			out = append(out, '\t')
			i++
			changed = true
		case 'r':
			out = append(out, '\r')
			i++
			changed = true
		case 'b':
			out = append(out, '\b')
			i++
			changed = true
		case 'f':
			out = append(out, '\f')
			i++
			changed = true
		case 'u':
			r, ok := parseHex4(data, i+2)
			if !ok {
				out = append(out, c)
				continue
			}
			consumed := 6
			if utf16.IsSurrogate(r) && i+12 <= len(data) && data[i+6] == '\\' && data[i+7] == 'u' {
				if low, ok := parseHex4(data, i+8); ok {
					r = utf16.DecodeRune(r, low)
					consumed = 12
				}
			}
			out = utf8.AppendRune(out, r)
			i += consumed - 1
			changed = true
		default:
			out = append(out, c)
		}
	}
	return out, changed
}

func parseHex4(data []byte, start int) (rune, bool) {
	if start+4 > len(data) {
		return 0, false
	}
	v, err := strconv.ParseUint(string(data[start:start+4]), 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(v), true
}
