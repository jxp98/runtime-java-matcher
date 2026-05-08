package trivyexport

import (
	"fmt"
	"strings"
)

type yamlLine struct {
	indent int
	text   string
}

func parseYAMLSubset(content string) (any, error) {
	lines := preprocessYAMLLines(content)
	if len(lines) == 0 {
		return nil, nil
	}
	index := 0
	return parseYAMLNode(lines, &index, lines[0].indent)
}

func preprocessYAMLLines(content string) []yamlLine {
	rawLines := strings.Split(content, "\n")
	result := make([]yamlLine, 0, len(rawLines))
	for _, raw := range rawLines {
		trimmedRight := strings.TrimRight(raw, " \r\t")
		if strings.TrimSpace(trimmedRight) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(trimmedRight), "#") {
			continue
		}
		indent := 0
		for indent < len(trimmedRight) && trimmedRight[indent] == ' ' {
			indent++
		}
		result = append(result, yamlLine{indent: indent, text: strings.TrimSpace(trimmedRight)})
	}
	return result
}

func parseYAMLNode(lines []yamlLine, index *int, indent int) (any, error) {
	if *index >= len(lines) {
		return nil, nil
	}
	if lines[*index].indent < indent {
		return nil, nil
	}
	if strings.HasPrefix(lines[*index].text, "- ") {
		return parseYAMLSequence(lines, index, indent)
	}
	return parseYAMLMap(lines, index, indent)
}

func parseYAMLSequence(lines []yamlLine, index *int, indent int) ([]any, error) {
	items := make([]any, 0)
	for *index < len(lines) {
		line := lines[*index]
		if line.indent != indent || !strings.HasPrefix(line.text, "- ") {
			break
		}
		content := strings.TrimSpace(strings.TrimPrefix(line.text, "- "))
		*index++
		if content == "" {
			if *index < len(lines) && lines[*index].indent > indent {
				child, err := parseYAMLNode(lines, index, lines[*index].indent)
				if err != nil {
					return nil, err
				}
				items = append(items, child)
			} else {
				items = append(items, "")
			}
			continue
		}

		if key, value, hasValue, ok := splitYAMLKeyValue(content); ok {
			item := map[string]any{}
			if hasValue {
				item[key] = parseYAMLScalar(value)
			} else if *index < len(lines) && lines[*index].indent > indent {
				child, err := parseYAMLNode(lines, index, lines[*index].indent)
				if err != nil {
					return nil, err
				}
				item[key] = child
			} else {
				item[key] = ""
			}

			if *index < len(lines) && lines[*index].indent > indent {
				child, err := parseYAMLNode(lines, index, lines[*index].indent)
				if err != nil {
					return nil, err
				}
				if childMap, ok := child.(map[string]any); ok {
					for nestedKey, nestedValue := range childMap {
						item[nestedKey] = nestedValue
					}
				}
			}
			items = append(items, item)
			continue
		}

		items = append(items, parseYAMLScalar(content))
	}
	return items, nil
}

func parseYAMLMap(lines []yamlLine, index *int, indent int) (map[string]any, error) {
	result := make(map[string]any)
	for *index < len(lines) {
		line := lines[*index]
		if line.indent != indent || strings.HasPrefix(line.text, "- ") {
			break
		}
		key, value, hasValue, ok := splitYAMLKeyValue(line.text)
		if !ok {
			return nil, fmt.Errorf("无法解析 YAML 行: %s", line.text)
		}
		*index++
		if hasValue {
			result[key] = parseYAMLScalar(value)
			continue
		}
		if *index < len(lines) && lines[*index].indent > indent {
			child, err := parseYAMLNode(lines, index, lines[*index].indent)
			if err != nil {
				return nil, err
			}
			result[key] = child
		} else {
			result[key] = ""
		}
	}
	return result, nil
}

func splitYAMLKeyValue(text string) (key string, value string, hasValue bool, ok bool) {
	separator := strings.Index(text, ":")
	if separator < 0 {
		return "", "", false, false
	}
	key = strings.TrimSpace(text[:separator])
	value = strings.TrimSpace(text[separator+1:])
	if key == "" {
		return "", "", false, false
	}
	if value == "" {
		return key, "", false, true
	}
	return key, value, true, true
}

func parseYAMLScalar(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 {
		if (raw[0] == '"' && raw[len(raw)-1] == '"') || (raw[0] == '\'' && raw[len(raw)-1] == '\'') {
			return raw[1 : len(raw)-1]
		}
	}
	return raw
}
