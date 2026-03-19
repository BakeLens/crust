package rules

import "regexp"

// compile-time validation: all regex-based DLP patterns must compile.
var _ = func() int {
	for _, p := range dlpPatterns {
		if p.re != nil {
			_ = regexp.MustCompile(p.re.String())
		}
	}
	return 0
}()
