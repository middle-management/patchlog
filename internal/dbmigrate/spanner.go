package dbmigrate

import "strings"

// splitSQL splits a script into its statements, without comments: at
// semicolons outside quotes, quoted identifiers, dollar quotes and
// comments.
func splitSQL(s string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if q := strings.TrimSpace(b.String()); q != "" {
			out = append(out, q)
		}
		b.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				i = len(s)
			} else {
				i += end + 3
			}
			b.WriteByte(' ')
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(s) && s[j] != c {
				j++
			}
			b.WriteString(s[i:min(j+1, len(s))])
			i = j
		case c == '$':
			j := i + 1
			for j < len(s) && (s[j] == '_' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z') {
				j++
			}
			if j < len(s) && s[j] == '$' {
				tag := s[i : j+1]
				end := strings.Index(s[j+1:], tag)
				if end < 0 {
					end = len(s) - j - 1
				} else {
					end += len(tag)
				}
				b.WriteString(s[i:min(j+1+end, len(s))])
				i = j + end
			} else {
				b.WriteByte(c)
			}
		case c == ';':
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return out
}
