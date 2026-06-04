package pycompat

import (
	"strings"
	"unicode"
)

// Lower approximates Python str.lower for Unicode special-casing cases that
// differ from Go's simple lower mapping and affect EQL comparisons.
func Lower(value string) string {
	var b strings.Builder
	changed := false
	runes := []rune(value)
	for i, r := range runes {
		switch r {
		case '\u0130':
			b.WriteString("i\u0307")
			changed = true
		case '\u03A3':
			if isFinalSigma(runes, i) {
				b.WriteRune('\u03C2')
			} else {
				b.WriteRune('\u03C3')
			}
			changed = true
		default:
			lowered := strings.ToLower(string(r))
			if lowered != string(r) {
				changed = true
			}
			b.WriteString(lowered)
		}
	}
	if !changed {
		return value
	}
	return b.String()
}

func isFinalSigma(runes []rune, index int) bool {
	hasCasedBefore := false
	for i := index - 1; i >= 0; i-- {
		if isCaseIgnorable(runes[i]) {
			continue
		}
		hasCasedBefore = isCased(runes[i])
		break
	}
	if !hasCasedBefore {
		return false
	}
	for i := index + 1; i < len(runes); i++ {
		if isCaseIgnorable(runes[i]) {
			continue
		}
		return !isCased(runes[i])
	}
	return true
}

func isCased(r rune) bool {
	return unicode.IsUpper(r) || unicode.IsLower(r) || unicode.IsTitle(r)
}

func isCaseIgnorable(r rune) bool {
	return unicode.Is(unicode.Mn, r) ||
		unicode.Is(unicode.Me, r) ||
		unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Lm, r) ||
		unicode.Is(unicode.Sk, r)
}
