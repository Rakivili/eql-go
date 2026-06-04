package pycompat

import (
	"fmt"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

const regexMatchTimeout = 250 * time.Millisecond

// CompileRegex compiles a Python EQL regex pattern for match/matchLite.
func CompileRegex(pattern string, caseInsensitive bool) (*regexp2.Regexp, error) {
	translated, err := translatePythonRegex(pattern)
	if err != nil {
		return nil, err
	}
	opts := regexp2.RegexOptions(regexp2.Singleline)
	if caseInsensitive {
		opts |= regexp2.IgnoreCase
	}
	re, err := regexp2.Compile(translated, opts)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = regexMatchTimeout
	return re, nil
}

func translatePythonRegex(pattern string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		switch {
		case pattern[i] == '\\':
			if i+1 >= len(pattern) {
				b.WriteByte(pattern[i])
				continue
			}
			i++
			switch pattern[i] {
			case 'Z':
				b.WriteString(`\z`)
			case 'z':
				return "", fmt.Errorf("invalid Python regular expression: bad escape \\z")
			default:
				b.WriteByte('\\')
				b.WriteByte(pattern[i])
			}
		case pattern[i] == '[':
			end := findClassEnd(pattern, i+1)
			b.WriteString(pattern[i : end+1])
			i = end
		case strings.HasPrefix(pattern[i:], "(?>"):
			return "", fmt.Errorf("invalid Python regular expression: atomic groups are not supported")
		case strings.HasPrefix(pattern[i:], "(?-") && bareInlineFlagDisable(pattern[i:]):
			return "", fmt.Errorf("invalid Python regular expression: missing : in flag group")
		case strings.HasPrefix(pattern[i:], "(?<=") || strings.HasPrefix(pattern[i:], "(?<!"):
			end := findGroupEnd(pattern, i+4)
			if end < 0 {
				b.WriteByte(pattern[i])
				continue
			}
			if _, ok := fixedRegexWidth(pattern[i+4 : end]); !ok {
				return "", fmt.Errorf("invalid Python regular expression: look-behind requires fixed-width pattern")
			}
			b.WriteString(pattern[i : end+1])
			i = end
		case strings.HasPrefix(pattern[i:], "(?P<"):
			end := strings.IndexByte(pattern[i+4:], '>')
			if end < 0 {
				b.WriteByte(pattern[i])
				continue
			}
			name := pattern[i+4 : i+4+end]
			b.WriteString("(?<")
			b.WriteString(name)
			b.WriteByte('>')
			i += 4 + end
		case strings.HasPrefix(pattern[i:], "(?P="):
			end := strings.IndexByte(pattern[i+4:], ')')
			if end < 0 {
				b.WriteByte(pattern[i])
				continue
			}
			name := pattern[i+4 : i+4+end]
			b.WriteString(`\k<`)
			b.WriteString(name)
			b.WriteByte('>')
			i += 4 + end
		default:
			b.WriteByte(pattern[i])
		}
	}
	return b.String(), nil
}

func bareInlineFlagDisable(pattern string) bool {
	end := strings.IndexByte(pattern, ')')
	colon := strings.IndexByte(pattern, ':')
	return end >= 0 && (colon < 0 || colon > end)
}

func fixedRegexWidth(expr string) (int, bool) {
	parts := splitTopLevelAlternatives(expr)
	width := -1
	for _, part := range parts {
		partWidth, ok := fixedRegexBranchWidth(part)
		if !ok {
			return 0, false
		}
		if width < 0 {
			width = partWidth
			continue
		}
		if partWidth != width {
			return 0, false
		}
	}
	if width < 0 {
		return 0, true
	}
	return width, true
}

func fixedRegexBranchWidth(expr string) (int, bool) {
	width := 0
	for i := 0; i < len(expr); i++ {
		atomWidth := 1
		switch expr[i] {
		case '\\':
			if i+1 < len(expr) {
				if strings.ContainsRune("bBAZzG", rune(expr[i+1])) {
					atomWidth = 0
				}
				i++
			}
		case '[':
			end := findClassEnd(expr, i+1)
			i = end
		case '(':
			end := findGroupEnd(expr, i+1)
			if end < 0 {
				return 0, false
			}
			contentStart := i + 1
			atomWidth = 0
			if strings.HasPrefix(expr[i:], "(?:") {
				contentStart = i + 3
				var ok bool
				atomWidth, ok = fixedRegexWidth(expr[contentStart:end])
				if !ok {
					return 0, false
				}
			} else if strings.HasPrefix(expr[i:], "(?P<") {
				nameEnd := strings.IndexByte(expr[i+4:end], '>')
				if nameEnd < 0 {
					return 0, false
				}
				contentStart = i + 4 + nameEnd + 1
				var ok bool
				atomWidth, ok = fixedRegexWidth(expr[contentStart:end])
				if !ok {
					return 0, false
				}
			} else if strings.HasPrefix(expr[i:], "(?=") || strings.HasPrefix(expr[i:], "(?!") ||
				strings.HasPrefix(expr[i:], "(?<=") || strings.HasPrefix(expr[i:], "(?<!") {
				atomWidth = 0
			} else if strings.HasPrefix(expr[i:], "(?") {
				return 0, false
			} else {
				var ok bool
				atomWidth, ok = fixedRegexWidth(expr[contentStart:end])
				if !ok {
					return 0, false
				}
			}
			i = end
		case '^', '$':
			atomWidth = 0
		}
		multiplier, next, ok := fixedQuantifier(expr, i+1)
		if !ok {
			return 0, false
		}
		width += atomWidth * multiplier
		i = next - 1
	}
	return width, true
}

func fixedQuantifier(expr string, index int) (int, int, bool) {
	if index >= len(expr) {
		return 1, index, true
	}
	switch expr[index] {
	case '*', '+', '?':
		return 0, index, false
	case '{':
		end := strings.IndexByte(expr[index+1:], '}')
		if end < 0 {
			return 1, index, true
		}
		body := expr[index+1 : index+1+end]
		next := index + end + 2
		if strings.Contains(body, ",") {
			parts := strings.SplitN(body, ",", 2)
			if parts[0] == "" || parts[1] == "" || parts[0] != parts[1] {
				return 0, index, false
			}
			n, ok := parseSmallDecimal(parts[0])
			return n, next, ok
		}
		n, ok := parseSmallDecimal(body)
		return n, next, ok
	default:
		return 1, index, true
	}
}

func parseSmallDecimal(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
		n = n*10 + int(value[i]-'0')
	}
	return n, true
}

func splitTopLevelAlternatives(expr string) []string {
	var parts []string
	start := 0
	depth := 0
	for i := 0; i < len(expr); i++ {
		switch expr[i] {
		case '\\':
			if i+1 < len(expr) {
				i++
			}
		case '[':
			i = findClassEnd(expr, i+1)
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '|':
			if depth == 0 {
				parts = append(parts, expr[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, expr[start:])
	return parts
}

func findClassEnd(pattern string, start int) int {
	for i := start; i < len(pattern); i++ {
		if pattern[i] == '\\' {
			if i+1 < len(pattern) {
				i++
			}
			continue
		}
		if pattern[i] == ']' {
			return i
		}
	}
	return len(pattern) - 1
}

func findGroupEnd(pattern string, start int) int {
	depth := 1
	for i := start; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			if i+1 < len(pattern) {
				i++
			}
		case '[':
			i = findClassEnd(pattern, i+1)
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
