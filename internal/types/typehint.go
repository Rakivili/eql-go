package types

// TypeHint is an EQL primitive or composite type category.
type TypeHint string

const (
	// TypeArray represents EQL arrays.
	TypeArray TypeHint = "array"
	// TypeBoolean represents EQL booleans.
	TypeBoolean TypeHint = "boolean"
	// TypeNumeric represents EQL numbers.
	TypeNumeric TypeHint = "number"
	// TypeNull represents EQL null.
	TypeNull TypeHint = "null"
	// TypeObject represents EQL objects.
	TypeObject TypeHint = "object"
	// TypeString represents EQL strings.
	TypeString TypeHint = "string"
	// TypeUnknown represents mixed or unknown values.
	TypeUnknown TypeHint = "mixed"
	// TypeVariable represents scoped variables.
	TypeVariable TypeHint = "variable"
)

// PrimitiveHints returns all primitive EQL type hints.
func PrimitiveHints() []TypeHint {
	return []TypeHint{TypeBoolean, TypeNumeric, TypeNull, TypeString}
}

// Normalize returns TypeUnknown for the zero-value hint.
func (h TypeHint) Normalize() TypeHint {
	if h == "" {
		return TypeUnknown
	}
	return h
}

// String returns the Python EQL schema string for this type hint.
func (h TypeHint) String() string {
	return string(h.Normalize())
}

// IsPrimitive reports whether this hint is one of Python EQL's primitive types.
func (h TypeHint) IsPrimitive() bool {
	h = h.Normalize()
	for _, primitive := range PrimitiveHints() {
		if h == primitive {
			return true
		}
	}
	return false
}

// RequireLiteral returns a type check requiring an unfolded literal node.
func (h TypeHint) RequireLiteral() TypeFoldCheck {
	return TypeFoldCheck{TypeInfo: h.Normalize(), RequireLiteral: true}
}

// RequireDynamic returns a type check requiring a value that does not fold to a literal.
func (h TypeHint) RequireDynamic() TypeFoldCheck {
	return TypeFoldCheck{TypeInfo: h.Normalize(), RequireLiteral: false}
}

// ParseTypeHint converts a Python EQL schema type string to a TypeHint.
func ParseTypeHint(value string) (TypeHint, bool) {
	switch TypeHint(value) {
	case TypeArray,
		TypeBoolean,
		TypeNumeric,
		TypeNull,
		TypeObject,
		TypeString,
		TypeUnknown,
		TypeVariable:
		return TypeHint(value), true
	default:
		return TypeUnknown, false
	}
}

// TypeFoldCheck is a type requirement with a literal/dynamic folding constraint.
type TypeFoldCheck struct {
	TypeInfo       TypeHint
	RequireLiteral bool
}

// Normalize returns a copy whose TypeInfo zero value is TypeUnknown.
func (c TypeFoldCheck) Normalize() TypeFoldCheck {
	c.TypeInfo = c.TypeInfo.Normalize()
	return c
}

// Expect returns an expectation containing this fold check.
func (c TypeFoldCheck) Expect() Expectation {
	return ExpectFold(c)
}

// Expect returns an expectation containing this type hint.
func (h TypeHint) Expect() Expectation {
	return Expect(h)
}
