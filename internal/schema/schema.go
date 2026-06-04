package schema

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/Rakivili/eql-go/internal/types"
)

const (
	// EventTypeAny is Python EQL's wildcard event type.
	EventTypeAny = "any"
	// EventTypeGeneric is Python EQL's generic event type.
	EventTypeGeneric = "generic"
)

const mixedTypes = string(types.TypeUnknown)

var identRE = regexp.MustCompile(`^[_a-zA-Z][a-zA-Z0-9_]*$`)

// Error describes invalid schema input.
type Error struct {
	Msg string
}

// Error returns the schema error message.
func (e Error) Error() string {
	return e.Msg
}

// Schema stores EQL field type information by event type.
type Schema struct {
	Events       map[string]map[string]any
	AllowGeneric bool
	AllowAny     bool
	AllowMissing bool
}

// Option configures a Schema.
type Option func(*Schema)

// WithAllowGeneric configures whether generic events are accepted.
func WithAllowGeneric(allow bool) Option {
	return func(s *Schema) {
		s.AllowGeneric = allow
	}
}

// WithAllowAny configures whether any-event queries are accepted.
func WithAllowAny(allow bool) Option {
	return func(s *Schema) {
		s.AllowAny = allow
	}
}

// WithAllowMissing configures whether missing fields return mixed instead of failing.
func WithAllowMissing(allow bool) Option {
	return func(s *Schema) {
		s.AllowMissing = allow
	}
}

// New creates and validates a schema.
func New(events map[string]map[string]any, opts ...Option) (*Schema, error) {
	if events == nil {
		return nil, Error{Msg: "invalid input schema <nil>"}
	}
	s := &Schema{
		Events:       cloneEvents(events),
		AllowGeneric: true,
		AllowAny:     true,
	}
	for _, opt := range opts {
		opt(s)
	}
	if !s.Validate() {
		return nil, Error{Msg: fmt.Sprintf("invalid input schema %v", events)}
	}
	return s, nil
}

// Validate reports whether the schema has Python-compatible shape and type names.
func (s *Schema) Validate() bool {
	if s == nil || s.Events == nil {
		return false
	}
	for eventType, eventSchema := range s.Events {
		if eventType == "" || eventSchema == nil {
			return false
		}
		for name, fieldSchema := range eventSchema {
			if name == "" || !validateFieldSchema(fieldSchema) {
				return false
			}
		}
	}
	return true
}

// ConvertToType converts one schema value to its EQL type hint and nested schema.
func ConvertToType(value any) (types.TypeHint, any, bool) {
	value = normalizeSchemaValue(value)
	if value == nil {
		return types.TypeUnknown, nil, false
	}
	if value == mixedTypes {
		return types.TypeUnknown, nil, true
	}
	switch v := value.(type) {
	case map[string]any:
		if len(v) == 0 {
			return types.TypeUnknown, nil, true
		}
		return types.TypeObject, v, true
	case []any:
		return types.TypeArray, v, true
	case string:
		hint, ok := types.ParseTypeHint(v)
		if !ok || !hint.IsPrimitive() {
			return types.TypeUnknown, nil, false
		}
		return hint, nil, true
	default:
		return types.TypeUnknown, nil, false
	}
}

// PathPart is one dotted field name or numeric array index.
type PathPart struct {
	Name    string
	Index   int
	IsIndex bool
}

// Field creates a string field path segment.
func Field(name string) PathPart {
	return PathPart{Name: name}
}

// Index creates a numeric array-index path segment.
func Index(index int) PathPart {
	return PathPart{Index: index, IsIndex: true}
}

// GetRelativePath resolves a field path relative to one event schema.
func GetRelativePath(eventSchema any, path []PathPart) (types.TypeHint, any, bool) {
	if len(path) == 0 {
		return ConvertToType(eventSchema)
	}
	eventSchema = normalizeSchemaValue(eventSchema)
	base := path[0]
	subpath := path[1:]
	if base.IsIndex {
		items, ok := eventSchema.([]any)
		if !ok || len(items) == 0 {
			return types.TypeUnknown, nil, false
		}
		if len(subpath) > 0 {
			for _, item := range items {
				if hint, schema, ok := GetRelativePath(item, subpath); ok {
					return hint, schema, true
				}
			}
			return types.TypeUnknown, nil, false
		}
		return ConvertToType(items[0])
	}
	if _, ok := eventSchema.([]any); ok {
		return types.TypeUnknown, nil, false
	}
	object, ok := eventSchema.(map[string]any)
	if !ok {
		return types.TypeUnknown, nil, false
	}
	if len(object) == 0 {
		return ConvertToType(object)
	}
	child, ok := object[base.Name]
	if !ok {
		return types.TypeUnknown, nil, false
	}
	if len(subpath) > 0 {
		return GetRelativePath(child, subpath)
	}
	return ConvertToType(child)
}

// GetEventTypeHint resolves a path for one event type.
func (s *Schema) GetEventTypeHint(eventType string, path []PathPart) (types.TypeHint, any, bool) {
	if s == nil || len(s.Events) == 0 {
		return types.TypeUnknown, nil, true
	}
	if eventType == EventTypeAny {
		if !s.AllowAny {
			return types.TypeUnknown, nil, false
		}
		for _, known := range anyEventTypes(s.Events) {
			hint, schema, ok := s.GetEventTypeHint(known, path)
			if ok {
				return hint, schema, true
			}
		}
		if s.AllowMissing {
			return types.TypeUnknown, nil, true
		}
		return types.TypeUnknown, nil, false
	}
	if eventSchema, ok := s.Events[eventType]; ok {
		hint, schema, ok := GetRelativePath(eventSchema, path)
		if ok {
			return hint, schema, true
		}
		if s.AllowMissing {
			return types.TypeUnknown, nil, true
		}
		return types.TypeUnknown, nil, false
	}
	if eventType == EventTypeGeneric && s.AllowGeneric {
		return types.TypeUnknown, nil, true
	}
	return types.TypeUnknown, nil, false
}

// EventSchema returns the schema for an event type. For any-event queries, it
// returns a first-wins merge of known event schemas in canonical EQL order.
func (s *Schema) EventSchema(eventType string) map[string]any {
	if s == nil {
		return map[string]any{}
	}
	if eventSchema, ok := s.Events[eventType]; ok {
		return eventSchema
	}
	if eventType != EventTypeAny || !s.AllowAny {
		return map[string]any{}
	}
	out := map[string]any{}
	for _, known := range anyEventTypes(s.Events) {
		for field, fieldSchema := range s.Events[known] {
			if _, exists := out[field]; exists {
				continue
			}
			out[field] = cloneSchemaValue(fieldSchema)
		}
	}
	return out
}

// ValidateEventType reports whether an event type is allowed by this schema.
func (s *Schema) ValidateEventType(eventType string) bool {
	if s == nil {
		return false
	}
	if eventType == EventTypeAny {
		return s.AllowAny
	}
	if _, ok := s.Events[eventType]; ok {
		return true
	}
	if eventType == EventTypeGeneric {
		return s.AllowGeneric
	}
	return len(s.Events) == 0
}

// Merge overlays this schema over another schema, matching Python's non-recursive merge.
func (s *Schema) Merge(other *Schema) (*Schema, error) {
	if s == nil || other == nil {
		return nil, Error{Msg: "cannot merge nil schema"}
	}
	emptySchemas := hasEmptyEventSchema(other.Events)
	full := cloneEvents(other.Events)
	for eventType, eventSchema := range s.Events {
		if _, ok := full[eventType]; !ok {
			full[eventType] = map[string]any{}
		}
		for field, fieldSchema := range eventSchema {
			full[eventType][field] = cloneSchemaValue(fieldSchema)
		}
	}
	return New(
		full,
		WithAllowGeneric(s.AllowGeneric || other.AllowGeneric),
		WithAllowAny(s.AllowAny || other.AllowAny),
		WithAllowMissing(s.AllowMissing || other.AllowMissing || emptySchemas),
	)
}

// Flatten collapses all event schemas into generic, with later sorted event types winning.
func (s *Schema) Flatten() (*Schema, error) {
	if s == nil {
		return nil, Error{Msg: "cannot flatten nil schema"}
	}
	flattened := map[string]any{}
	for _, eventType := range sortedEventTypes(s.Events) {
		for field, fieldSchema := range s.Events[eventType] {
			flattened[field] = cloneSchemaValue(fieldSchema)
		}
	}
	return New(
		map[string]map[string]any{EventTypeGeneric: flattened},
		WithAllowGeneric(false),
		WithAllowAny(true),
		WithAllowMissing(s.AllowMissing || hasEmptyEventSchema(s.Events)),
	)
}

// Event is the minimal input shape needed to learn a schema.
type Event struct {
	Type string
	Data map[string]any
}

// EventFromData converts raw event data into an Event for schema learning.
func EventFromData(data map[string]any) Event {
	eventType, _ := data["event_type"].(string)
	if eventType == "" {
		eventType = EventTypeGeneric
	}
	return Event{Type: eventType, Data: data}
}

// Learn infers a schema from event data.
func Learn(events []Event) (*Schema, error) {
	schema := map[string]map[string]any{}
	allowGeneric := false
	for _, event := range events {
		if event.Type == "" {
			event.Type = EventTypeGeneric
		}
		if event.Type == EventTypeGeneric {
			allowGeneric = true
		}
		itemSchema := getItemSchema(event.Data)
		eventSchema, ok := itemSchema.(map[string]any)
		if !ok {
			eventSchema = map[string]any{}
		}
		merged := mergeSubschema(schema[event.Type], eventSchema)
		schema[event.Type], _ = merged.(map[string]any)
	}
	return New(schema, WithAllowGeneric(allowGeneric))
}

// LearnFromData infers a schema from raw event maps.
func LearnFromData(events []map[string]any) (*Schema, error) {
	converted := make([]Event, 0, len(events))
	for _, event := range events {
		converted = append(converted, EventFromData(event))
	}
	return Learn(converted)
}

func validateFieldSchema(value any) bool {
	value = normalizeSchemaValue(value)
	switch v := value.(type) {
	case string:
		hint, ok := types.ParseTypeHint(v)
		return ok && (hint.IsPrimitive() || hint == types.TypeUnknown)
	case []any:
		for _, item := range v {
			if !validateFieldSchema(item) {
				return false
			}
		}
		return true
	case map[string]any:
		for name, nested := range v {
			if !identRE.MatchString(name) || !validateFieldSchema(nested) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func normalizeSchemaValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, value := range v {
			out[key] = normalizeSchemaValue(value)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(v))
		for key, value := range v {
			out[key] = value
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, value := range v {
			out = append(out, normalizeSchemaValue(value))
		}
		return out
	case []string:
		out := make([]any, 0, len(v))
		for _, value := range v {
			out = append(out, value)
		}
		return out
	default:
		return value
	}
}

func cloneEvents(events map[string]map[string]any) map[string]map[string]any {
	out := make(map[string]map[string]any, len(events))
	for eventType, eventSchema := range events {
		if eventSchema == nil {
			out[eventType] = nil
			continue
		}
		out[eventType] = cloneSchemaMap(eventSchema)
	}
	return out
}

func cloneSchemaMap(schema map[string]any) map[string]any {
	out := make(map[string]any, len(schema))
	for key, value := range schema {
		out[key] = cloneSchemaValue(value)
	}
	return out
}

func cloneSchemaValue(value any) any {
	switch v := normalizeSchemaValue(value).(type) {
	case map[string]any:
		return cloneSchemaMap(v)
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, cloneSchemaValue(item))
		}
		return out
	default:
		return v
	}
}

func mergeSubschema(a any, b any) any {
	a = normalizeSchemaValue(a)
	b = normalizeSchemaValue(b)
	if a == nil {
		return cloneSchemaValue(b)
	}
	if b == nil {
		return cloneSchemaValue(a)
	}
	if a == mixedTypes || b == mixedTypes {
		return mixedTypes
	}
	if aString, ok := a.(string); ok {
		bString, ok := b.(string)
		if !ok || aString != bString {
			return mixedTypes
		}
		return aString
	}
	switch av := a.(type) {
	case []any:
		bv, ok := b.([]any)
		if !ok {
			return mixedTypes
		}
		return mergeSchemaLists(av, bv)
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return mixedTypes
		}
		out := map[string]any{}
		keys := map[string]struct{}{}
		for key := range av {
			keys[key] = struct{}{}
		}
		for key := range bv {
			keys[key] = struct{}{}
		}
		for key := range keys {
			out[key] = mergeSubschema(av[key], bv[key])
		}
		return out
	default:
		return mixedTypes
	}
}

func mergeSchemaLists(a []any, b []any) any {
	if len(a) == 0 {
		return cloneSchemaValue(b)
	}
	if len(b) == 0 {
		return cloneSchemaValue(a)
	}
	stringsA := schemaStrings(a)
	stringsB := schemaStrings(b)
	// DESIGN: Python EQL accidentally derives both nested lists from b. Keep
	// this behavior so learned/merged array schemas stay oracle-compatible.
	nestedA := schemaNested(b)
	nestedB := schemaNested(b)
	if (len(stringsA) > 0 || len(stringsB) > 0) && (len(nestedA) > 0 || len(nestedB) > 0) {
		return []any{}
	}
	if len(stringsA) > 0 {
		values := append(stringsA, stringsB...)
		sort.Strings(values)
		return uniqueStringsAsAny(values)
	}
	if len(nestedA) == 1 && len(nestedB) == 1 {
		return []any{mergeSubschema(nestedA[0], nestedB[0])}
	}
	return []any{mixedTypes}
}

func schemaStrings(values []any) []string {
	var out []string
	for _, value := range values {
		if text, ok := value.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func schemaNested(values []any) []any {
	var out []any
	for _, value := range values {
		if _, ok := value.(string); !ok {
			out = append(out, value)
		}
	}
	return out
}

func uniqueStringsAsAny(values []string) []any {
	var out []any
	var last string
	for i, value := range values {
		if i > 0 && value == last {
			continue
		}
		out = append(out, value)
		last = value
	}
	return out
}

func getItemSchema(data any) any {
	switch v := data.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, value := range v {
			child := getItemSchema(value)
			if child != nil && identRE.MatchString(key) {
				out[key] = child
			}
		}
		return out
	case nil:
		return string(types.TypeNull)
	case []any:
		return getListItemSchema(v)
	case []string:
		items := make([]any, 0, len(v))
		for _, value := range v {
			items = append(items, value)
		}
		return getListItemSchema(items)
	case string:
		return string(types.TypeString)
	case bool:
		return string(types.TypeBoolean)
	case json.Number:
		if _, err := strconv.ParseFloat(v.String(), 64); err == nil {
			return string(types.TypeNumeric)
		}
		return nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return string(types.TypeNumeric)
	default:
		return nil
	}
}

func getListItemSchema(values []any) any {
	schemaBase := map[string]struct{}{}
	var nestedSchema any
	for _, value := range values {
		child := getItemSchema(value)
		if text, ok := child.(string); ok {
			schemaBase[text] = struct{}{}
			continue
		}
		if child != nil && nestedSchema == nil {
			nestedSchema = child
		}
	}
	if nestedSchema != nil && len(schemaBase) > 0 {
		return mixedTypes
	}
	if len(schemaBase) > 0 {
		values := make([]string, 0, len(schemaBase))
		for value := range schemaBase {
			values = append(values, value)
		}
		sort.Strings(values)
		return uniqueStringsAsAny(values)
	}
	return nestedSchema
}

func sortedEventTypes(events map[string]map[string]any) []string {
	keys := make([]string, 0, len(events))
	for key := range events {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func anyEventTypes(events map[string]map[string]any) []string {
	keys := sortedEventTypes(events)
	sort.SliceStable(keys, func(i, j int) bool {
		left := eventTypePriority(keys[i])
		right := eventTypePriority(keys[j])
		if left != right {
			return left < right
		}
		return keys[i] < keys[j]
	})
	return keys
}

func eventTypePriority(eventType string) int {
	switch eventType {
	case "process":
		return 0
	case "file":
		return 1
	case "registry":
		return 2
	case "network":
		return 3
	case "dns":
		return 4
	default:
		return 100
	}
}

func hasEmptyEventSchema(events map[string]map[string]any) bool {
	for _, eventSchema := range events {
		if len(eventSchema) == 0 {
			return true
		}
	}
	return false
}
