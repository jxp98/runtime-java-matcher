package version

import (
	"strconv"
	"strings"
	"unicode"
)

type tokenKind int

const (
	tokenEmpty tokenKind = iota
	tokenNumeric
	tokenQualifier
)

type token struct {
	kind  tokenKind
	value string
}

func Compare(left, right string) int {
	leftTokens := tokenize(left)
	rightTokens := tokenize(right)
	maxLen := len(leftTokens)
	if len(rightTokens) > maxLen {
		maxLen = len(rightTokens)
	}

	for i := 0; i < maxLen; i++ {
		lt := getToken(leftTokens, i)
		rt := getToken(rightTokens, i)
		cmp := compareToken(lt, rt)
		if cmp != 0 {
			return cmp
		}
	}

	return 0
}

func Match(version string, constraint string) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" || constraint == "*" {
		return true
	}

	orParts := strings.Split(constraint, "||")
	for _, orPart := range orParts {
		andOK := true
		for _, raw := range strings.Split(orPart, ",") {
			part := strings.TrimSpace(raw)
			if part == "" {
				continue
			}
			if !matchSingle(version, part) {
				andOK = false
				break
			}
		}
		if andOK {
			return true
		}
	}

	return false
}

func matchSingle(version string, constraint string) bool {
	operator := "="
	target := constraint
	for _, candidate := range []string{"<=", ">=", "<", ">", "="} {
		if strings.HasPrefix(constraint, candidate) {
			operator = candidate
			target = strings.TrimSpace(strings.TrimPrefix(constraint, candidate))
			break
		}
	}
	cmp := Compare(version, target)
	switch operator {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	default:
		return cmp == 0
	}
}

func tokenize(value string) []token {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return nil
	}

	result := make([]token, 0, len(value))
	var current []rune
	var currentIsDigit *bool
	flush := func() {
		if len(current) == 0 {
			return
		}
		part := string(current)
		kind := tokenQualifier
		if isNumeric(part) {
			kind = tokenNumeric
		}
		result = append(result, token{kind: kind, value: part})
		current = current[:0]
		currentIsDigit = nil
	}

	for _, r := range value {
		if !(unicode.IsDigit(r) || unicode.IsLetter(r)) {
			flush()
			continue
		}

		isDigit := unicode.IsDigit(r)
		if currentIsDigit != nil && *currentIsDigit != isDigit {
			flush()
		}

		current = append(current, r)
		flag := isDigit
		currentIsDigit = &flag
	}
	flush()

	return result
}

func compareToken(left, right token) int {
	if left.kind == tokenEmpty && right.kind == tokenEmpty {
		return 0
	}
	if left.kind == tokenNumeric && right.kind == tokenNumeric {
		return compareNumeric(left.value, right.value)
	}
	if left.kind == tokenQualifier && right.kind == tokenQualifier {
		return compareQualifier(left.value, right.value)
	}
	if left.kind == tokenNumeric {
		return 1
	}
	if right.kind == tokenNumeric {
		return -1
	}
	return compareQualifier(left.value, right.value)
}

func compareNumeric(left, right string) int {
	left = strings.TrimLeft(left, "0")
	right = strings.TrimLeft(right, "0")
	if left == "" {
		left = "0"
	}
	if right == "" {
		right = "0"
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func compareQualifier(left, right string) int {
	leftRank := qualifierRank(left)
	rightRank := qualifierRank(right)
	if leftRank < rightRank {
		return -1
	}
	if leftRank > rightRank {
		return 1
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func qualifierRank(value string) int {
	switch normalizeQualifier(value) {
	case "snapshot":
		return 0
	case "alpha":
		return 1
	case "beta":
		return 2
	case "milestone":
		return 3
	case "rc":
		return 4
	case "":
		return 5
	case "sp":
		return 6
	default:
		return 5
	}
}

func normalizeQualifier(value string) string {
	switch value {
	case "snapshot":
		return "snapshot"
	case "a", "alpha":
		return "alpha"
	case "b", "beta":
		return "beta"
	case "m", "milestone":
		return "milestone"
	case "cr", "rc":
		return "rc"
	case "ga", "final", "release":
		return ""
	case "sp":
		return "sp"
	default:
		return value
	}
}

func getToken(tokens []token, index int) token {
	if index >= len(tokens) {
		return token{kind: tokenEmpty, value: ""}
	}
	return tokens[index]
}

func isNumeric(value string) bool {
	_, err := strconv.Atoi(value)
	return err == nil
}
