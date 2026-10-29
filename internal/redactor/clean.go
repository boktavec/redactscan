package redactor

// IsClean is true only when the redactor accepts s and finds nothing but
// label-like text, which is already neutralised output. It fails closed: any
// redactor error means not clean.
func IsClean(s string) bool {
	res, err := Redact([]byte(s))
	if err != nil {
		return false
	}
	for kind := range res.Counts {
		if kind != KindLabelLike {
			return false
		}
	}
	return true
}
