package janitor

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var isoDur = regexp.MustCompile(`^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$`)

// AddDuration adds an ISO 8601 duration ("P7D", "PT12H", "P1Y2M3DT4H5M6.5S",
// "P2W") to t. Years, months, weeks and days are calendar units (AddDate);
// hours, minutes and seconds are exact.
func AddDuration(t time.Time, s string) (time.Time, error) {
	m := isoDur.FindStringSubmatch(s)
	if m == nil || s == "P" || s[len(s)-1] == 'T' {
		return time.Time{}, fmt.Errorf("janitor: %q is not an ISO 8601 duration", s)
	}
	n := func(i int) int {
		if m[i] == "" {
			return 0
		}
		v, _ := strconv.Atoi(m[i])
		return v
	}
	t = t.AddDate(n(1), n(2), 7*n(3)+n(4))
	t = t.Add(time.Duration(n(5))*time.Hour + time.Duration(n(6))*time.Minute)
	if m[7] != "" {
		f, _ := strconv.ParseFloat(m[7], 64)
		t = t.Add(time.Duration(f * float64(time.Second)))
	}
	return t, nil
}
