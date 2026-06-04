package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Rakivili/eql-go/internal/ast"
	"github.com/Rakivili/eql-go/internal/pycompat"
)

const (
	// EventTypeGeneric is the default event type for events without explicit type fields.
	EventTypeGeneric = "generic"
	// EventTypeAny is Python EQL's wildcard event type.
	EventTypeAny = "any"
)

const hostField = "hostname"

type ruleConfig struct {
	caseInsensitive     bool
	elasticsearchSyntax bool
	dataSource          string
}

// RuleOption configures internal rule evaluation.
type RuleOption func(*ruleConfig)

// EventNormalizer converts a raw event map into an internal runtime event.
type EventNormalizer func(map[string]any) *Event

func defaultRuleConfig() ruleConfig {
	return ruleConfig{caseInsensitive: true}
}

// CaseSensitive disables default case-insensitive string comparison.
func CaseSensitive() RuleOption {
	return func(c *ruleConfig) { c.caseInsensitive = false }
}

// ElasticsearchSyntax enables runtime behavior differences for Elasticsearch EQL syntax.
func ElasticsearchSyntax() RuleOption {
	return func(c *ruleConfig) { c.elasticsearchSyntax = true }
}

// DataSource sets the data source mode. Use "endgame" for Endgame endpoint sensor data
// which uses opcode-based process lifecycle signals instead of ECS subtype strings.
func DataSource(ds string) RuleOption {
	return func(c *ruleConfig) { c.dataSource = strings.ToLower(ds) }
}

// Event is the normalized runtime representation consumed by Engine.Feed.
type Event struct {
	Type      string
	Timestamp int64
	Data      map[string]any
}

// Match is one rule match emitted by the engine.
type Match struct {
	Events     []*Event
	RuleID     string
	AnalyticID string
}

// Rule is an internal compiled query plus evaluation configuration.
type Rule struct {
	query  *ast.Query
	config ruleConfig
}

// NewRule creates an internal rule from parsed query IR.
func NewRule(q *ast.Query, opts ...RuleOption) *Rule {
	cfg := defaultRuleConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Rule{query: q, config: cfg}
}

// Engine evaluates one or more rules against streaming events.
type Engine struct {
	rules []*runtimeRule
}

// New creates an internal streaming engine.
func New(rules ...*Rule) *Engine {
	runtimeRules := make([]*runtimeRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			runtimeRules = append(runtimeRules, nil)
			continue
		}
		runtimeRules = append(runtimeRules, newRuntimeRule(rule))
	}
	return &Engine{rules: runtimeRules}
}

type runtimeRule struct {
	rule     *Rule
	pipes    []pipeRuntime
	sequence sequenceRuntime
	sample   sampleRuntime
	join     joinRuntime
	named    namedRuntime
}

type sequenceRuntime struct {
	pending   [][]*Event
	pendingBy []map[string][]*Event
}

type joinRuntime struct {
	lookup map[string][]*Event
}

type sampleRuntime struct {
	events []*Event
	groups map[string][]*Event
}

type namedRuntime struct {
	nodes              []*ast.NamedSubquery
	eventOf            []*eventOfRuntime
	eventOfByNode      map[*ast.NamedSubquery]*eventOfRuntime
	childOf            []*childOfRuntime
	childOfByNode      map[*ast.NamedSubquery]*childOfRuntime
	descendantOf       []*descendantOfRuntime
	descendantOfByNode map[*ast.NamedSubquery]*descendantOfRuntime
}

type eventOfRuntime struct {
	query ast.EventQuery
	pids  map[string]struct{}
	dead  map[string]struct{}
}

type childOfRuntime struct {
	query    ast.EventQuery
	parents  map[string]struct{}
	children map[string]struct{}
	dead     map[string]struct{}
}

type descendantOfRuntime struct {
	query       ast.EventQuery
	sources     map[string]struct{}
	descendants map[string]struct{}
	dead        map[string]struct{}
}

type pipeRuntime struct {
	pipe       ast.Pipe
	headLimit  int64
	headCount  int64
	tailLimit  int64
	tailBuf    []*Event
	tailGroups [][]*Event
	sortBuf    []*Event
	sortGroups [][]*Event
	count      countRuntime
	unique     uniqueCountRuntime
	seen       map[string]struct{}
	finalized  bool
}

type countRuntime struct {
	total int64
	hosts map[string]struct{}
	table map[string]*countBucket
	order []string
}

type countBucket struct {
	key               any
	count             int64
	hosts             map[string]struct{}
	eofSeen           bool
	hostsFieldPresent bool
}

type uniqueCountRuntime struct {
	table map[string]*uniqueCountBucket
	order []string
}

type uniqueCountBucket struct {
	event             *Event
	count             numericValue
	hosts             map[string]struct{}
	eofSeen           bool
	hostsFieldPresent bool
}

func newRuntimeRule(rule *Rule) *runtimeRule {
	runtime := &runtimeRule{rule: rule}
	if rule.query == nil {
		return runtime
	}
	if len(rule.query.Sequence) > 0 {
		if usesSequenceKeys(rule.query) {
			runtime.sequence.pendingBy = make([]map[string][]*Event, len(rule.query.Sequence)-1)
			for i := range runtime.sequence.pendingBy {
				runtime.sequence.pendingBy[i] = map[string][]*Event{}
			}
		} else {
			runtime.sequence.pending = make([][]*Event, len(rule.query.Sequence)-1)
		}
	}
	if len(rule.query.Sample) > 0 && usesSampleKeys(rule.query) {
		runtime.sample.groups = map[string][]*Event{}
	}
	if len(rule.query.Join) > 0 {
		runtime.join.lookup = map[string][]*Event{}
	}
	runtime.pipes = make([]pipeRuntime, 0, len(rule.query.Pipes))
	for _, pipe := range rule.query.Pipes {
		state := pipeRuntime{pipe: pipe}
		if pipe.Name == "head" {
			state.headLimit = int64(50)
			if len(pipe.Args) == 1 {
				if limit, ok := literalInt(pipe.Args[0]); ok {
					state.headLimit = limit
				}
			}
		}
		if pipe.Name == "tail" {
			state.tailLimit = int64(50)
			if len(pipe.Args) == 1 {
				if limit, ok := literalInt(pipe.Args[0]); ok {
					state.tailLimit = limit
				}
			}
		}
		if pipe.Name == "unique" {
			state.seen = map[string]struct{}{}
		}
		if pipe.Name == "count" {
			state.count.hosts = map[string]struct{}{}
			state.count.table = map[string]*countBucket{}
		}
		if pipe.Name == "unique_count" {
			state.unique.table = map[string]*uniqueCountBucket{}
		}
		runtime.pipes = append(runtime.pipes, state)
	}
	runtime.collectNamedSubqueries()
	return runtime
}

func (r *runtimeRule) collectNamedSubqueries() {
	if r == nil || r.rule == nil || r.rule.query == nil {
		return
	}
	q := r.rule.query
	if len(q.Sequence) > 0 {
		for _, part := range q.Sequence {
			r.collectNamedExpr(part.Expr)
			for _, by := range part.By {
				r.collectNamedExpr(by)
			}
		}
		for _, by := range q.SequenceBy {
			r.collectNamedExpr(by)
		}
		if q.SequenceUntil != nil {
			r.collectNamedExpr(q.SequenceUntil.Expr)
			for _, by := range q.SequenceUntil.By {
				r.collectNamedExpr(by)
			}
		}
	} else if len(q.Sample) > 0 {
		for _, part := range q.Sample {
			r.collectNamedExpr(part.Expr)
			for _, by := range part.By {
				r.collectNamedExpr(by)
			}
		}
		for _, by := range q.SampleBy {
			r.collectNamedExpr(by)
		}
	} else if len(q.Join) > 0 {
		for _, part := range q.Join {
			r.collectNamedExpr(part.Expr)
			for _, by := range part.By {
				r.collectNamedExpr(by)
			}
		}
		for _, by := range q.JoinBy {
			r.collectNamedExpr(by)
		}
		if q.JoinUntil != nil {
			r.collectNamedExpr(q.JoinUntil.Expr)
			for _, by := range q.JoinUntil.By {
				r.collectNamedExpr(by)
			}
		}
	} else {
		r.collectNamedExpr(q.Expr)
	}
	for _, pipe := range q.Pipes {
		for _, arg := range pipe.Args {
			r.collectNamedExpr(arg)
		}
	}
}

func (r *runtimeRule) collectNamedExpr(expr ast.Expr) {
	switch n := expr.(type) {
	case *ast.Comparison:
		r.collectNamedExpr(n.Left)
		r.collectNamedExpr(n.Right)
	case *ast.IsNull:
		r.collectNamedExpr(n.Expr)
	case *ast.IsNotNull:
		r.collectNamedExpr(n.Expr)
	case *ast.MathOperation:
		r.collectNamedExpr(n.Left)
		r.collectNamedExpr(n.Right)
	case *ast.InSet:
		r.collectNamedExpr(n.Expr)
		for _, item := range n.Values {
			r.collectNamedExpr(item)
		}
	case *ast.Logical:
		for _, term := range n.Terms {
			r.collectNamedExpr(term)
		}
	case *ast.Not:
		r.collectNamedExpr(n.Term)
	case *ast.FunctionCall:
		for _, arg := range n.Args {
			r.collectNamedExpr(arg)
		}
	case *ast.NamedSubquery:
		switch n.QueryType {
		case "event":
			if r.named.eventOfByNode == nil {
				r.named.eventOfByNode = map[*ast.NamedSubquery]*eventOfRuntime{}
			}
			if _, exists := r.named.eventOfByNode[n]; !exists {
				state := &eventOfRuntime{
					query: n.Query,
					pids:  map[string]struct{}{},
					dead:  map[string]struct{}{},
				}
				r.named.eventOf = append(r.named.eventOf, state)
				r.named.eventOfByNode[n] = state
				r.named.nodes = append(r.named.nodes, n)
			}
		case "child":
			if r.named.childOfByNode == nil {
				r.named.childOfByNode = map[*ast.NamedSubquery]*childOfRuntime{}
			}
			if _, exists := r.named.childOfByNode[n]; !exists {
				state := &childOfRuntime{
					query:    n.Query,
					parents:  map[string]struct{}{},
					children: map[string]struct{}{},
					dead:     map[string]struct{}{},
				}
				r.named.childOf = append(r.named.childOf, state)
				r.named.childOfByNode[n] = state
				r.named.nodes = append(r.named.nodes, n)
			}
		case "descendant":
			if r.named.descendantOfByNode == nil {
				r.named.descendantOfByNode = map[*ast.NamedSubquery]*descendantOfRuntime{}
			}
			if _, exists := r.named.descendantOfByNode[n]; !exists {
				state := &descendantOfRuntime{
					query:       n.Query,
					sources:     map[string]struct{}{},
					descendants: map[string]struct{}{},
					dead:        map[string]struct{}{},
				}
				r.named.descendantOf = append(r.named.descendantOf, state)
				r.named.descendantOfByNode[n] = state
				r.named.nodes = append(r.named.nodes, n)
			}
		}
		r.collectNamedExpr(n.Query.Expr)
		for _, by := range n.Query.By {
			r.collectNamedExpr(by)
		}
	}
}

func (r *runtimeRule) updateNamedSubqueries(ev *Event) error {
	if r == nil || r.rule == nil || ev == nil || len(r.named.nodes) == 0 {
		return nil
	}
	if ev.Type == "process" {
		for _, state := range r.named.eventOf {
			r.updateEventOfProcessLifecycle(state, ev)
		}
		for _, state := range r.named.childOf {
			r.updateChildOfProcessLifecycle(state, ev)
		}
		for _, state := range r.named.descendantOf {
			r.updateDescendantOfProcessLifecycle(state, ev)
		}
	}
	for i := len(r.named.nodes) - 1; i >= 0; i-- {
		node := r.named.nodes[i]
		var err error
		switch node.QueryType {
		case "event":
			err = r.updateEventOfSource(r.named.eventOfByNode[node], ev)
		case "child":
			err = r.updateChildOfSource(r.named.childOfByNode[node], ev)
		case "descendant":
			err = r.updateDescendantOfSource(r.named.descendantOfByNode[node], ev)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *runtimeRule) updateEventOfSource(state *eventOfRuntime, ev *Event) error {
	if state == nil || ev == nil || !eventTypeMatches(state.query.EventType, ev.Type) {
		return nil
	}
	value, err := r.evalExpr(state.query.Expr, ev)
	if err != nil {
		return err
	}
	ok, isNull := truthy(value)
	if isNull || !ok {
		return nil
	}
	key, ok, err := eventPIDKey(ev, false)
	if err != nil {
		return err
	}
	if ok {
		state.pids[key] = struct{}{}
	}
	return nil
}

func (r *runtimeRule) updateEventOfProcessLifecycle(state *eventOfRuntime, ev *Event) {
	if state == nil || ev == nil || ev.Data == nil {
		return
	}
	for pid := range state.dead {
		delete(state.pids, pid)
	}
	clear(state.dead)

	ds := r.rule.config.dataSource
	if processCreateOrFork(ev.Data, ds) && processPIDIsFour(ev) && ev.Data["process_name"] == "System" {
		clear(state.pids)
		return
	}
	if !processTerminate(ev.Data, ds) {
		return
	}
	if key, ok, err := eventPIDKey(ev, true); err == nil && ok {
		state.dead[key] = struct{}{}
	}
}

func (r *runtimeRule) updateChildOfSource(state *childOfRuntime, ev *Event) error {
	if state == nil || ev == nil || !eventTypeMatches(state.query.EventType, ev.Type) {
		return nil
	}
	value, err := r.evalExpr(state.query.Expr, ev)
	if err != nil {
		return err
	}
	ok, isNull := truthy(value)
	if isNull || !ok {
		return nil
	}
	key, ok, err := eventPIDKey(ev, false)
	if err != nil {
		return err
	}
	if ok {
		state.parents[key] = struct{}{}
	}
	return nil
}

func (r *runtimeRule) updateChildOfProcessLifecycle(state *childOfRuntime, ev *Event) {
	if state == nil || ev == nil || ev.Data == nil {
		return
	}
	for pid := range state.dead {
		delete(state.children, pid)
		delete(state.parents, pid)
	}
	clear(state.dead)

	ds := r.rule.config.dataSource
	isCreateOrFork := processCreateOrFork(ev.Data, ds)
	if isCreateOrFork && processPIDIsFour(ev) && ev.Data["process_name"] == "System" {
		clear(state.children)
		clear(state.parents)
		return
	}
	if isCreateOrFork {
		parentKey, ok, err := eventFieldKey(ev, "ppid", true)
		if err != nil || !ok {
			return
		}
		if _, isChild := state.parents[parentKey]; !isChild {
			return
		}
		childKey, ok, err := eventPIDKey(ev, true)
		if err == nil && ok {
			state.children[childKey] = struct{}{}
		}
		return
	}
	if processTerminate(ev.Data, ds) {
		if key, ok, err := eventPIDKey(ev, true); err == nil && ok {
			state.dead[key] = struct{}{}
		}
	}
}

func (r *runtimeRule) updateDescendantOfSource(state *descendantOfRuntime, ev *Event) error {
	if state == nil || ev == nil || !eventTypeMatches(state.query.EventType, ev.Type) {
		return nil
	}
	value, err := r.evalExpr(state.query.Expr, ev)
	if err != nil {
		return err
	}
	ok, isNull := truthy(value)
	if isNull || !ok {
		return nil
	}
	key, ok, err := eventPIDKey(ev, false)
	if err != nil {
		return err
	}
	if ok {
		state.sources[key] = struct{}{}
	}
	return nil
}

func (r *runtimeRule) updateDescendantOfProcessLifecycle(state *descendantOfRuntime, ev *Event) {
	if state == nil || ev == nil || ev.Data == nil {
		return
	}
	for pid := range state.dead {
		delete(state.descendants, pid)
		delete(state.sources, pid)
	}
	clear(state.dead)

	ds := r.rule.config.dataSource
	isCreateOrFork := processCreateOrFork(ev.Data, ds)
	if isCreateOrFork && processPIDIsFour(ev) && ev.Data["process_name"] == "System" {
		clear(state.descendants)
		clear(state.sources)
		return
	}
	if isCreateOrFork {
		parentKey, ok, err := eventFieldKey(ev, "ppid", true)
		if err != nil || !ok {
			return
		}
		_, parentIsSource := state.sources[parentKey]
		_, parentIsDescendant := state.descendants[parentKey]
		if !parentIsSource && !parentIsDescendant {
			return
		}
		childKey, ok, err := eventPIDKey(ev, true)
		if err == nil && ok {
			state.descendants[childKey] = struct{}{}
		}
		return
	}
	if processTerminate(ev.Data, ds) {
		if key, ok, err := eventPIDKey(ev, true); err == nil && ok {
			state.dead[key] = struct{}{}
		}
	}
}

func (r *runtimeRule) processPipes(ev *Event) ([]*Event, error) {
	return r.processPipesFrom(0, []*Event{ev})
}

func (r *runtimeRule) processPipesFrom(start int, events []*Event) ([]*Event, error) {
	var outputs []*Event
	for _, ev := range events {
		out, err := r.processPipeEventFrom(start, ev)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, out...)
	}
	return outputs, nil
}

func (r *runtimeRule) processPipeEventFrom(index int, ev *Event) ([]*Event, error) {
	if index >= len(r.pipes) {
		return []*Event{ev}, nil
	}
	pipe := &r.pipes[index]
	headBefore := pipe.headCount
	out, err := pipe.process(ev, r.rule.config, r.pipeEvalScope(ev))
	if err != nil {
		return nil, err
	}
	var outputs []*Event
	for _, next := range out {
		downstream, err := r.processPipeEventFrom(index+1, next)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, downstream...)
	}
	if pipeHeadReachedLimit(pipe, headBefore) {
		flushed, err := r.finalizePipesFrom(index + 1)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, flushed...)
	}
	return outputs, nil
}

func (r *runtimeRule) processPipeGroups(events []*Event) ([][]*Event, error) {
	return r.processPipeGroupsFrom(0, [][]*Event{events})
}

func (r *runtimeRule) processPipeGroupsFrom(start int, groups [][]*Event) ([][]*Event, error) {
	var outputs [][]*Event
	for _, group := range groups {
		out, err := r.processPipeGroupFrom(start, group)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, out...)
	}
	return outputs, nil
}

func (r *runtimeRule) processPipeGroupFrom(index int, group []*Event) ([][]*Event, error) {
	if index >= len(r.pipes) {
		return [][]*Event{copyEventGroup(group)}, nil
	}
	pipe := &r.pipes[index]
	headBefore := pipe.headCount
	out, err := pipe.processGroup(group, r.rule.config, r.groupEvalScope(group))
	if err != nil {
		return nil, err
	}
	var outputs [][]*Event
	for _, next := range out {
		downstream, err := r.processPipeGroupFrom(index+1, next)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, downstream...)
	}
	if pipeHeadReachedLimit(pipe, headBefore) {
		flushed, err := r.finalizePipeGroupsFrom(index + 1)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, flushed...)
	}
	return outputs, nil
}

func pipeHeadReachedLimit(pipe *pipeRuntime, before int64) bool {
	return pipe != nil && pipe.pipe.Name == "head" && before < pipe.headLimit && pipe.headCount == pipe.headLimit
}

func (r *runtimeRule) finalizePipes() ([]*Event, error) {
	return r.finalizePipesFrom(0)
}

func (r *runtimeRule) finalizePipesFrom(start int) ([]*Event, error) {
	if r == nil || r.rule == nil {
		return nil, nil
	}
	var outputs []*Event
	for i := start; i < len(r.pipes); i++ {
		flushed, forwardEOF, err := r.pipes[i].finalize(r.rule.config)
		if err != nil {
			return nil, err
		}
		if len(flushed) == 0 {
			if !forwardEOF {
				break
			}
			continue
		}
		out, err := r.processPipesFrom(i+1, flushed)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, out...)
		if !forwardEOF {
			break
		}
	}
	return outputs, nil
}

func (r *runtimeRule) finalizePipeGroups() ([][]*Event, error) {
	return r.finalizePipeGroupsFrom(0)
}

func (r *runtimeRule) finalizePipeGroupsFrom(start int) ([][]*Event, error) {
	if r == nil || r.rule == nil {
		return nil, nil
	}
	var outputs [][]*Event
	for i := start; i < len(r.pipes); i++ {
		flushed, forwardEOF, err := r.pipes[i].finalizeGroups(r.rule.config)
		if err != nil {
			return nil, err
		}
		if len(flushed) == 0 {
			if !forwardEOF {
				break
			}
			continue
		}
		out, err := r.processPipeGroupsFrom(i+1, flushed)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, out...)
		if !forwardEOF {
			break
		}
	}
	return outputs, nil
}

func (p *pipeRuntime) process(ev *Event, cfg ruleConfig, scope evalScope) ([]*Event, error) {
	switch p.pipe.Name {
	case "filter":
		if len(p.pipe.Args) != 1 {
			return nil, fmt.Errorf("filter expects 1 argument, got %d", len(p.pipe.Args))
		}
		value, err := evalScoped(p.pipe.Args[0], ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		ok, isNull := truthy(value)
		if isNull || !ok {
			return nil, nil
		}
		return []*Event{ev}, nil
	case "head":
		if p.headCount >= p.headLimit {
			return nil, nil
		}
		p.headCount++
		return []*Event{ev}, nil
	case "tail":
		p.bufferTail(ev)
		return nil, nil
	case "sort":
		p.sortBuf = append(p.sortBuf, ev)
		return nil, nil
	case "count":
		if err := p.countEvent(ev, cfg, scope); err != nil {
			return nil, err
		}
		return nil, nil
	case "unique_count":
		if err := p.uniqueCountEvent(ev, cfg, scope); err != nil {
			return nil, err
		}
		return nil, nil
	case "unique":
		if len(p.pipe.Args) == 0 {
			return nil, fmt.Errorf("unique expects at least 1 argument, got 0")
		}
		key, err := pipeKeyWithScope(p.pipe.Args, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		if _, ok := p.seen[key]; ok {
			return nil, nil
		}
		p.seen[key] = struct{}{}
		return []*Event{ev}, nil
	default:
		return nil, fmt.Errorf("unsupported pipe %s", p.pipe.Name)
	}
}

func (p *pipeRuntime) processGroup(events []*Event, cfg ruleConfig, scope evalScope) ([][]*Event, error) {
	switch p.pipe.Name {
	case "filter":
		if len(p.pipe.Args) != 1 {
			return nil, fmt.Errorf("filter expects 1 argument, got %d", len(p.pipe.Args))
		}
		value, err := evalScoped(p.pipe.Args[0], firstGroupEvent(events), cfg, scope)
		if err != nil {
			return nil, err
		}
		ok, isNull := truthy(value)
		if isNull || !ok {
			return nil, nil
		}
		return [][]*Event{copyEventGroup(events)}, nil
	case "head":
		if p.headCount >= p.headLimit {
			return nil, nil
		}
		p.headCount++
		return [][]*Event{copyEventGroup(events)}, nil
	case "tail":
		p.bufferTailGroup(events)
		return nil, nil
	case "sort":
		p.sortGroups = append(p.sortGroups, copyEventGroup(events))
		return nil, nil
	case "count":
		if err := p.countGroup(events, cfg, scope); err != nil {
			return nil, err
		}
		return nil, nil
	case "unique_count":
		if err := p.uniqueCountGroup(events, cfg, scope); err != nil {
			return nil, err
		}
		return nil, nil
	case "unique":
		if len(p.pipe.Args) == 0 {
			return nil, fmt.Errorf("unique expects at least 1 argument, got 0")
		}
		key, err := pipeKeyGroupWithScope(p.pipe.Args, events, cfg, scope)
		if err != nil {
			return nil, err
		}
		if _, ok := p.seen[key]; ok {
			return nil, nil
		}
		p.seen[key] = struct{}{}
		return [][]*Event{copyEventGroup(events)}, nil
	default:
		return nil, fmt.Errorf("unsupported pipe %s", p.pipe.Name)
	}
}

func (p *pipeRuntime) finalize(cfg ruleConfig) ([]*Event, bool, error) {
	switch p.pipe.Name {
	case "tail":
		out := p.tailBuf
		p.finalized = true
		return out, true, nil
	case "sort":
		out, err := sortPipeEvents(p.sortBuf, p.pipe.Args, cfg)
		if err != nil {
			return nil, true, err
		}
		p.finalized = true
		return out, true, nil
	case "count":
		out, err := p.finalizeCount()
		if err != nil {
			return nil, true, err
		}
		p.finalized = true
		return out, true, nil
	case "unique_count":
		out, err := p.finalizeUniqueCount()
		if err != nil {
			return nil, true, err
		}
		p.finalized = true
		return out, true, nil
	case "head":
		return nil, p.headCount < p.headLimit, nil
	case "filter", "unique":
		return nil, true, nil
	default:
		return nil, true, fmt.Errorf("unsupported pipe %s", p.pipe.Name)
	}
}

func (p *pipeRuntime) finalizeGroups(cfg ruleConfig) ([][]*Event, bool, error) {
	switch p.pipe.Name {
	case "tail":
		out := p.tailGroups
		p.finalized = true
		return out, true, nil
	case "sort":
		out, err := sortPipeGroups(p.sortGroups, p.pipe.Args, cfg)
		if err != nil {
			return nil, true, err
		}
		p.finalized = true
		return out, true, nil
	case "count":
		out, err := p.finalizeCount()
		if err != nil {
			return nil, true, err
		}
		p.finalized = true
		return eventGroupsFromEvents(out), true, nil
	case "unique_count":
		out, err := p.finalizeUniqueCount()
		if err != nil {
			return nil, true, err
		}
		p.finalized = true
		return eventGroupsFromEvents(out), true, nil
	case "head":
		return nil, p.headCount < p.headLimit, nil
	case "filter", "unique":
		return nil, true, nil
	default:
		return nil, true, fmt.Errorf("unsupported pipe %s", p.pipe.Name)
	}
}

func (p *pipeRuntime) bufferTail(ev *Event) {
	if p.tailLimit <= 0 {
		return
	}
	if int64(len(p.tailBuf)) >= p.tailLimit {
		copy(p.tailBuf, p.tailBuf[1:])
		p.tailBuf[len(p.tailBuf)-1] = ev
		return
	}
	p.tailBuf = append(p.tailBuf, ev)
}

func (p *pipeRuntime) bufferTailGroup(events []*Event) {
	if p.tailLimit <= 0 {
		return
	}
	group := copyEventGroup(events)
	if int64(len(p.tailGroups)) >= p.tailLimit {
		copy(p.tailGroups, p.tailGroups[1:])
		p.tailGroups[len(p.tailGroups)-1] = group
		return
	}
	p.tailGroups = append(p.tailGroups, group)
}

func (p *pipeRuntime) countEvent(ev *Event, cfg ruleConfig, scope evalScope) error {
	if len(p.pipe.Args) == 0 {
		p.count.total++
		addHost(p.count.hosts, ev)
		return nil
	}
	values, err := pipeValuesWithScope(p.pipe.Args, ev, cfg, scope, false)
	if err != nil {
		return err
	}
	key := pipeKeyValue(values)
	normalizedKey := normalizeCountKey(key, cfg.caseInsensitive)
	keyID, err := marshalRuntimeKey(normalizedKey, len(values) > 1)
	if err != nil {
		return err
	}
	bucket := p.count.table[keyID]
	if bucket == nil {
		bucket = &countBucket{key: key, hosts: map[string]struct{}{}}
		p.count.table[keyID] = bucket
		p.count.order = append(p.count.order, keyID)
	}
	if bucket.eofSeen && eventHasHostField(ev) {
		return finalizedHostsMutationError("add", bucket.hostsFieldPresent)
	}
	bucket.count++
	addHost(bucket.hosts, ev)
	return nil
}

func (p *pipeRuntime) countGroup(events []*Event, cfg ruleConfig, scope evalScope) error {
	first := firstGroupEvent(events)
	if len(p.pipe.Args) == 0 {
		p.count.total++
		addHost(p.count.hosts, first)
		return nil
	}
	values, err := pipeValuesWithScope(p.pipe.Args, first, cfg, scope, false)
	if err != nil {
		return err
	}
	key := pipeKeyValue(values)
	normalizedKey := normalizeCountKey(key, cfg.caseInsensitive)
	keyID, err := marshalRuntimeKey(normalizedKey, len(values) > 1)
	if err != nil {
		return err
	}
	bucket := p.count.table[keyID]
	if bucket == nil {
		bucket = &countBucket{key: key, hosts: map[string]struct{}{}}
		p.count.table[keyID] = bucket
		p.count.order = append(p.count.order, keyID)
	}
	if bucket.eofSeen && eventHasHostField(first) {
		return finalizedHostsMutationError("add", bucket.hostsFieldPresent)
	}
	bucket.count++
	addHost(bucket.hosts, first)
	return nil
}

func (p *pipeRuntime) uniqueCountEvent(ev *Event, cfg ruleConfig, scope evalScope) error {
	keyID, err := pipeKeyWithScope(p.pipe.Args, ev, cfg, scope)
	if err != nil {
		return err
	}
	if p.unique.table == nil {
		p.unique.table = map[string]*uniqueCountBucket{}
	}
	bucket := p.unique.table[keyID]
	if bucket != nil && bucket.eofSeen {
		if eventHostTruthy(ev) {
			return finalizedHostsMutationError("add", bucket.hostsFieldPresent)
		}
		return finalizedHostsMutationError("update", bucket.hostsFieldPresent)
	}
	countedEvent, count, hosts := uniqueCountEventCopy(ev)
	if bucket == nil {
		bucket = &uniqueCountBucket{
			event: countedEvent,
			count: count,
			hosts: map[string]struct{}{},
		}
		p.unique.table[keyID] = bucket
		p.unique.order = append(p.unique.order, keyID)
	} else {
		bucket.count = addNumericValues(bucket.count, count)
	}
	for host := range hosts {
		bucket.hosts[host] = struct{}{}
	}
	bucket.event.Data["count"] = numericOutputValue(bucket.count)
	return nil
}

func (p *pipeRuntime) uniqueCountGroup(events []*Event, cfg ruleConfig, scope evalScope) error {
	keyID, err := pipeKeyGroupWithScope(p.pipe.Args, events, cfg, scope)
	if err != nil {
		return err
	}
	if p.unique.table == nil {
		p.unique.table = map[string]*uniqueCountBucket{}
	}
	first := firstGroupEvent(events)
	bucket := p.unique.table[keyID]
	if bucket != nil && bucket.eofSeen {
		if eventHostTruthy(first) {
			return finalizedHostsMutationError("add", bucket.hostsFieldPresent)
		}
		return finalizedHostsMutationError("update", bucket.hostsFieldPresent)
	}
	countedEvent, count, hosts := uniqueCountEventCopy(first)
	if bucket == nil {
		bucket = &uniqueCountBucket{
			event: countedEvent,
			count: count,
			hosts: map[string]struct{}{},
		}
		p.unique.table[keyID] = bucket
		p.unique.order = append(p.unique.order, keyID)
	} else {
		bucket.count = addNumericValues(bucket.count, count)
	}
	for host := range hosts {
		bucket.hosts[host] = struct{}{}
	}
	bucket.event.Data["count"] = numericOutputValue(bucket.count)
	return nil
}

func uniqueCountEventCopy(ev *Event) (*Event, numericValue, map[string]struct{}) {
	data := map[string]any{}
	if ev != nil && ev.Data != nil {
		for key, value := range ev.Data {
			data[key] = value
		}
	}
	hostsValue, hadHosts := data["hosts"]
	delete(data, "hosts")
	hostValue, hadHost := data[hostField]
	delete(data, hostField)
	count := numericValue{f: 1, i: 1, isInt: true}
	if raw, ok := data["count"]; ok {
		if n, ok := numericValueOf(raw); ok {
			count = n
		}
	}
	delete(data, "count")
	hosts := map[string]struct{}{}
	if hadHost {
		if host, ok := hostValue.(string); ok && host != "" {
			hosts[host] = struct{}{}
		}
	} else if hadHosts {
		addHostsFromValue(hosts, hostsValue)
	}
	data["count"] = numericOutputValue(count)
	out := &Event{Data: data}
	if ev != nil {
		out.Type = ev.Type
		out.Timestamp = ev.Timestamp
	}
	return out, count, hosts
}

func addHostsFromValue(hosts map[string]struct{}, value any) {
	switch values := value.(type) {
	case []string:
		for _, host := range values {
			if host != "" {
				hosts[host] = struct{}{}
			}
		}
	case []any:
		for _, item := range values {
			if host, ok := item.(string); ok && host != "" {
				hosts[host] = struct{}{}
			}
		}
	}
}

func (p *pipeRuntime) finalizeCount() ([]*Event, error) {
	if len(p.pipe.Args) == 0 {
		data := map[string]any{
			"key":   "totals",
			"count": p.count.total,
		}
		addHostSummary(data, p.count.hosts)
		return []*Event{{Type: EventTypeGeneric, Data: data}}, nil
	}
	buckets := make([]*countBucket, 0, len(p.count.order))
	for _, keyID := range p.count.order {
		if bucket := p.count.table[keyID]; bucket != nil {
			if bucket.eofSeen && !bucket.hostsFieldPresent {
				return nil, finalizedHostsMissingError()
			}
			buckets = append(buckets, bucket)
		}
	}
	if len(buckets) == 0 {
		return nil, nil
	}
	convertedKeys, err := convertedCountKeys(buckets, len(p.pipe.Args))
	if err != nil {
		return nil, err
	}
	total := int64(0)
	for _, bucket := range buckets {
		total += bucket.count
	}
	indexes := make([]int, len(buckets))
	for i := range indexes {
		indexes[i] = i
	}
	var sortErr error
	sort.SliceStable(indexes, func(i, j int) bool {
		if sortErr != nil {
			return false
		}
		left := buckets[indexes[i]]
		right := buckets[indexes[j]]
		if left.count != right.count {
			return left.count < right.count
		}
		cmp, err := compareSortKeys(asKeyParts(convertedKeys[indexes[i]]), asKeyParts(convertedKeys[indexes[j]]))
		if err != nil {
			sortErr = err
			return false
		}
		return cmp < 0
	})
	if sortErr != nil {
		return nil, sortErr
	}
	out := make([]*Event, 0, len(buckets))
	for _, index := range indexes {
		bucket := buckets[index]
		data := map[string]any{
			"count":   bucket.count,
			"key":     publicDataValue(convertedKeys[index]),
			"percent": percentValue(bucket.count, total),
		}
		addHostSummary(data, bucket.hosts)
		bucket.eofSeen = true
		bucket.hostsFieldPresent = len(bucket.hosts) > 0
		out = append(out, &Event{Type: EventTypeGeneric, Data: data})
	}
	return out, nil
}

func (p *pipeRuntime) finalizeUniqueCount() ([]*Event, error) {
	if len(p.unique.order) == 0 {
		return nil, nil
	}
	total := numericValue{isInt: true}
	for _, keyID := range p.unique.order {
		if bucket := p.unique.table[keyID]; bucket != nil {
			if bucket.eofSeen && !bucket.hostsFieldPresent {
				return nil, finalizedHostsMissingError()
			}
			total = addNumericValues(total, bucket.count)
		}
	}
	out := make([]*Event, 0, len(p.unique.order))
	for _, keyID := range p.unique.order {
		bucket := p.unique.table[keyID]
		if bucket == nil {
			continue
		}
		data := bucket.event.Data
		delete(data, "hosts")
		addHostSummary(data, bucket.hosts)
		data["count"] = numericOutputValue(bucket.count)
		data["percent"] = percentNumericValue(bucket.count, total)
		bucket.eofSeen = true
		bucket.hostsFieldPresent = len(bucket.hosts) > 0
		out = append(out, bucket.event)
	}
	return out, nil
}

func addHost(hosts map[string]struct{}, ev *Event) {
	if hosts == nil || ev == nil || ev.Data == nil {
		return
	}
	host, ok := ev.Data[hostField].(string)
	if !ok {
		return
	}
	hosts[host] = struct{}{}
}

func eventHasHostField(ev *Event) bool {
	if ev == nil || ev.Data == nil {
		return false
	}
	_, ok := ev.Data[hostField]
	return ok
}

func eventHostTruthy(ev *Event) bool {
	if ev == nil || ev.Data == nil {
		return false
	}
	value, ok := ev.Data[hostField]
	if !ok {
		return false
	}
	truth, isNull := truthy(value)
	return !isNull && truth
}

func finalizedHostsMutationError(method string, hostsFieldPresent bool) error {
	if hostsFieldPresent {
		return fmt.Errorf("AttributeError: 'list' object has no attribute '%s'", method)
	}
	return finalizedHostsMissingError()
}

func finalizedHostsMissingError() error {
	return fmt.Errorf("KeyError: 'hosts'")
}

func addHostSummary(data map[string]any, hosts map[string]struct{}) {
	if len(hosts) == 0 {
		return
	}
	values := make([]string, 0, len(hosts))
	for host := range hosts {
		values = append(values, host)
	}
	sort.Strings(values)
	data["hosts"] = values
	data["total_hosts"] = int64(len(values))
}

func percentValue(count int64, total int64) json.Number {
	return percentFloatValue(float64(count) / float64(total))
}

func percentNumericValue(count numericValue, total numericValue) json.Number {
	return percentFloatValue(count.f / total.f)
}

func percentFloatValue(percent float64) json.Number {
	text := strconv.FormatFloat(percent, 'g', -1, 64)
	if !strings.ContainsAny(text, ".eE") {
		text += ".0"
	}
	return json.Number(text)
}

func pipeKeyValue(values []any) any {
	if len(values) == 1 {
		return values[0]
	}
	return values
}

func normalizeCountKey(value any, caseInsensitive bool) any {
	switch v := value.(type) {
	case string:
		if !caseInsensitive {
			return v
		}
		return pythonLower(v)
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, normalizeCountKey(item, caseInsensitive))
		}
		return out
	default:
		return value
	}
}

func convertedCountKeys(buckets []*countBucket, keyLen int) ([]any, error) {
	keys := make([][]any, len(buckets))
	emptyValues := make([]any, keyLen)
	for i, bucket := range buckets {
		values := asKeyParts(bucket.key)
		keys[i] = values
		for pos, value := range values {
			if truthyForConverter(value) && emptyValues[pos] == nil {
				emptyValues[pos] = emptySortValue(value)
			}
		}
	}
	converted := make([]any, len(buckets))
	for i, values := range keys {
		out := make([]any, len(values))
		for pos, value := range values {
			if !truthyForConverter(value) && emptyValues[pos] != nil {
				value = emptyValues[pos]
			}
			out[pos] = value
		}
		converted[i] = pipeKeyValue(out)
	}
	return converted, nil
}

func asKeyParts(key any) []any {
	if values, ok := key.([]any); ok {
		return values
	}
	return []any{key}
}

func truthyForConverter(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		return v != ""
	case bool:
		return v
	case ast.Num:
		return !v.IsZero()
	case json.Number:
		n, ok := numericValueOf(v)
		return ok && n.f != 0
	default:
		if n, ok := numericValueOf(v); ok {
			return n.f != 0
		}
		return true
	}
}

func sortPipeEvents(events []*Event, args []ast.Expr, cfg ruleConfig) ([]*Event, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("sort expects at least 1 argument, got 0")
	}
	if len(events) <= 1 {
		return append([]*Event(nil), events...), nil
	}
	keys := make([][]any, len(events))
	emptyValues := make([]any, len(args))
	for i, ev := range events {
		values, err := pipeValues(args, ev, cfg, true)
		if err != nil {
			return nil, err
		}
		keys[i] = values
		for pos, value := range values {
			if value != nil && emptyValues[pos] == nil {
				emptyValues[pos] = emptySortValue(value)
			}
		}
	}
	if len(args) == 1 && emptyValues[0] == nil {
		return nil, fmt.Errorf("sort key values are not comparable")
	}
	for _, values := range keys {
		for pos, value := range values {
			if value == nil && emptyValues[pos] != nil {
				values[pos] = emptyValues[pos]
			}
		}
	}
	indexes := make([]int, len(events))
	for i := range indexes {
		indexes[i] = i
	}
	var sortErr error
	sort.SliceStable(indexes, func(i, j int) bool {
		if sortErr != nil {
			return false
		}
		cmp, err := compareSortKeys(keys[indexes[i]], keys[indexes[j]])
		if err != nil {
			sortErr = err
			return false
		}
		return cmp < 0
	})
	if sortErr != nil {
		return nil, sortErr
	}
	out := make([]*Event, 0, len(events))
	for _, index := range indexes {
		out = append(out, events[index])
	}
	return out, nil
}

func sortPipeGroups(groups [][]*Event, args []ast.Expr, cfg ruleConfig) ([][]*Event, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("sort expects at least 1 argument, got 0")
	}
	if len(groups) <= 1 {
		out := make([][]*Event, 0, len(groups))
		for _, group := range groups {
			out = append(out, copyEventGroup(group))
		}
		return out, nil
	}
	keys := make([][]any, len(groups))
	emptyValues := make([]any, len(args))
	for i, group := range groups {
		values, err := pipeValuesGroup(args, group, cfg, true)
		if err != nil {
			return nil, err
		}
		keys[i] = values
		for pos, value := range values {
			if value != nil && emptyValues[pos] == nil {
				emptyValues[pos] = emptySortValue(value)
			}
		}
	}
	if len(args) == 1 && emptyValues[0] == nil {
		return nil, fmt.Errorf("sort key values are not comparable")
	}
	for _, values := range keys {
		for pos, value := range values {
			if value == nil && emptyValues[pos] != nil {
				values[pos] = emptyValues[pos]
			}
		}
	}
	indexes := make([]int, len(groups))
	for i := range indexes {
		indexes[i] = i
	}
	var sortErr error
	sort.SliceStable(indexes, func(i, j int) bool {
		if sortErr != nil {
			return false
		}
		cmp, err := compareSortKeys(keys[indexes[i]], keys[indexes[j]])
		if err != nil {
			sortErr = err
			return false
		}
		return cmp < 0
	})
	if sortErr != nil {
		return nil, sortErr
	}
	out := make([][]*Event, 0, len(groups))
	for _, index := range indexes {
		out = append(out, copyEventGroup(groups[index]))
	}
	return out, nil
}

func pipeValues(args []ast.Expr, ev *Event, cfg ruleConfig, foldCase bool) ([]any, error) {
	return pipeValuesWithScope(args, ev, cfg, pipeScope(ev), foldCase)
}

func pipeValuesGroup(args []ast.Expr, events []*Event, cfg ruleConfig, foldCase bool) ([]any, error) {
	return pipeValuesWithScope(args, firstGroupEvent(events), cfg, groupScope(events), foldCase)
}

func pipeValuesWithScope(args []ast.Expr, ev *Event, cfg ruleConfig, scope evalScope, foldCase bool) ([]any, error) {
	values := make([]any, 0, len(args))
	for _, arg := range args {
		value, err := evalScoped(arg, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		if foldCase {
			value = normalizePipeKey(value, cfg.caseInsensitive)
		}
		values = append(values, value)
	}
	return values, nil
}

func emptySortValue(value any) any {
	switch v := value.(type) {
	case string:
		return ""
	case bool:
		return false
	case ast.Num:
		if v.IsInt {
			return ast.Int(0)
		}
		return ast.Float(0)
	case json.Number:
		return json.Number("0")
	case []any:
		return []any{}
	default:
		if _, ok := numericValueOf(value); ok {
			return ast.Int(0)
		}
		rv := reflect.ValueOf(value)
		if rv.IsValid() {
			return reflect.Zero(rv.Type()).Interface()
		}
		return nil
	}
}

func publicDataValue(value any) any {
	switch v := value.(type) {
	case ast.Num:
		if v.IsInt {
			return v.I
		}
		return v.F
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, publicDataValue(item))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = publicDataValue(item)
		}
		return out
	default:
		return value
	}
}

func compareSortKeys(left, right []any) (int, error) {
	for i := range left {
		cmp, err := compareSortValue(left[i], right[i])
		if err != nil || cmp != 0 {
			return cmp, err
		}
	}
	return 0, nil
}

func compareSortValue(left, right any) (int, error) {
	if left == nil && right == nil {
		return 0, nil
	}
	if left == nil || right == nil {
		return 0, fmt.Errorf("sort key values are not comparable")
	}
	if leftString, ok := left.(string); ok {
		rightString, ok := right.(string)
		if !ok {
			return 0, fmt.Errorf("sort key values are not comparable")
		}
		return compareOrderedValue(leftString, rightString), nil
	}
	if leftNum, ok := numericValueOf(left); ok {
		rightNum, ok := numericValueOf(right)
		if !ok {
			return 0, fmt.Errorf("sort key values are not comparable")
		}
		if leftNum.isInt && rightNum.isInt {
			return compareOrderedValue(leftNum.i, rightNum.i), nil
		}
		return compareOrderedValue(leftNum.f, rightNum.f), nil
	}
	if leftBool, ok := left.(bool); ok {
		rightBool, ok := right.(bool)
		if !ok {
			return 0, fmt.Errorf("sort key values are not comparable")
		}
		return compareBool(leftBool, rightBool), nil
	}
	leftArray, leftOK := arrayValues(left)
	rightArray, rightOK := arrayValues(right)
	if leftOK || rightOK {
		if !leftOK || !rightOK {
			return 0, fmt.Errorf("sort key values are not comparable")
		}
		return compareSortArrays(leftArray, rightArray)
	}
	if reflect.DeepEqual(left, right) {
		return 0, nil
	}
	return 0, fmt.Errorf("sort key values are not comparable")
}

func compareSortArrays(left, right []any) (int, error) {
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	for i := 0; i < limit; i++ {
		cmp, err := compareSortValue(left[i], right[i])
		if err != nil || cmp != 0 {
			return cmp, err
		}
	}
	return compareOrderedValue(len(left), len(right)), nil
}

func compareOrderedValue[T ordered](left, right T) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareBool(left, right bool) int {
	switch {
	case !left && right:
		return -1
	case left && !right:
		return 1
	default:
		return 0
	}
}

// Feed evaluates a normalized event and returns any matches.
func (e *Engine) Feed(ev *Event) ([]Match, error) {
	var matches []Match
	for _, runtime := range e.rules {
		if runtime == nil || runtime.rule == nil {
			continue
		}
		if err := runtime.updateNamedSubqueries(ev); err != nil {
			return nil, err
		}
		if runtime.rule.query != nil && len(runtime.rule.query.Sequence) > 0 {
			sequenceMatches, err := runtime.processSequence(ev)
			if err != nil {
				return nil, err
			}
			matches = append(matches, sequenceMatches...)
			continue
		}
		if runtime.rule.query != nil && len(runtime.rule.query.Sample) > 0 {
			sampleMatches, err := runtime.processSample(ev)
			if err != nil {
				return nil, err
			}
			matches = append(matches, sampleMatches...)
			continue
		}
		if runtime.rule.query != nil && len(runtime.rule.query.Join) > 0 {
			joinMatches, err := runtime.processJoin(ev)
			if err != nil {
				return nil, err
			}
			matches = append(matches, joinMatches...)
			continue
		}
		ok, err := runtime.matchEvent(ev)
		if err != nil {
			return nil, err
		}
		var events []*Event
		if ok {
			events = []*Event{ev}
		}
		if ok && len(runtime.pipes) > 0 {
			events, err = runtime.processPipes(ev)
			if err != nil {
				return nil, err
			}
		}
		for _, event := range events {
			matches = append(matches, Match{Events: []*Event{event}})
		}
	}
	return matches, nil
}

func (r *runtimeRule) processSequence(ev *Event) ([]Match, error) {
	parts := r.rule.query.Sequence
	if len(parts) < 2 {
		return nil, nil
	}
	r.expireSequencePending(ev)
	if err := r.closeSequenceUntil(ev); err != nil {
		return nil, err
	}
	if usesSequenceKeys(r.rule.query) {
		return r.processKeyedSequence(ev)
	}
	var matches []Match
	for stage := len(parts) - 1; stage >= 1; stage-- {
		advance, appendEvent, discardPending, err := r.sequenceStageTransition(parts[stage], ev)
		if err != nil {
			return nil, err
		}
		if discardPending {
			r.sequence.pending[stage-1] = nil
			continue
		}
		if !advance || r.sequence.pending[stage-1] == nil {
			continue
		}
		events := append([]*Event(nil), r.sequence.pending[stage-1]...)
		if appendEvent {
			events = append(events, ev)
		}
		if !parts[stage].Fork {
			r.sequence.pending[stage-1] = nil
		}
		if stage == len(parts)-1 {
			if len(r.pipes) > 0 {
				groups, err := r.processPipeGroups(events)
				if err != nil {
					return nil, err
				}
				for _, group := range groups {
					matches = append(matches, Match{Events: group})
				}
				continue
			}
			matches = append(matches, Match{Events: events})
			continue
		}
		r.sequence.pending[stage] = events
	}
	advance, appendEvent, _, err := r.sequenceStageTransition(parts[0], ev)
	if err != nil {
		return nil, err
	}
	if advance {
		events := []*Event{}
		if appendEvent {
			events = append(events, ev)
		}
		r.sequence.pending[0] = events
	}
	return matches, nil
}

func (r *runtimeRule) processSample(ev *Event) ([]Match, error) {
	if r == nil || r.rule == nil || r.rule.query == nil || len(r.rule.query.Sample) < 2 {
		return nil, nil
	}
	parts := r.rule.query.Sample
	var matches []Match
	for pos := len(parts) - 1; pos >= 0; pos-- {
		ok, err := r.matchSequencePart(parts[pos], ev)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		groups, err := r.appendSampleEvent(pos, ev)
		if err != nil {
			return nil, err
		}
		for _, group := range groups {
			if len(r.pipes) > 0 {
				piped, err := r.processPipeGroups(group)
				if err != nil {
					return nil, err
				}
				for _, out := range piped {
					matches = append(matches, Match{Events: out})
				}
				continue
			}
			matches = append(matches, Match{Events: group})
		}
	}
	return matches, nil
}

func (r *runtimeRule) appendSampleEvent(pos int, ev *Event) ([][]*Event, error) {
	size := len(r.rule.query.Sample)
	if usesSampleKeys(r.rule.query) {
		key, err := r.sampleKey(pos, ev)
		if err != nil {
			return nil, err
		}
		events := append(r.sample.groups[key], ev)
		if len(events) == size {
			delete(r.sample.groups, key)
			return [][]*Event{append([]*Event(nil), events...)}, nil
		}
		r.sample.groups[key] = events
		return nil, nil
	}
	r.sample.events = append(r.sample.events, ev)
	if len(r.sample.events) == size {
		out := append([]*Event(nil), r.sample.events...)
		r.sample.events = nil
		return [][]*Event{out}, nil
	}
	return nil, nil
}

func (r *runtimeRule) processJoin(ev *Event) ([]Match, error) {
	if r == nil || r.rule == nil || r.rule.query == nil || len(r.rule.query.Join) < 2 {
		return nil, nil
	}
	if err := r.closeJoinUntil(ev); err != nil {
		return nil, err
	}
	var matches []Match
	for pos, part := range r.rule.query.Join {
		ok, err := r.matchSequencePart(part, ev)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		key, err := r.joinKey(pos, ev)
		if err != nil {
			return nil, err
		}
		events := r.join.lookup[key]
		if events == nil {
			events = make([]*Event, len(r.rule.query.Join))
			r.join.lookup[key] = events
		}
		if events[pos] != nil {
			continue
		}
		events[pos] = ev
		if allJoinSlotsFilled(events) {
			out := append([]*Event(nil), events...)
			delete(r.join.lookup, key)
			if len(r.pipes) > 0 {
				groups, err := r.processPipeGroups(out)
				if err != nil {
					return nil, err
				}
				for _, group := range groups {
					matches = append(matches, Match{Events: group})
				}
				continue
			}
			matches = append(matches, Match{Events: out})
		}
	}
	return matches, nil
}

func (r *runtimeRule) closeJoinUntil(ev *Event) error {
	if r == nil || r.rule == nil || r.rule.query == nil || r.rule.query.JoinUntil == nil {
		return nil
	}
	ok, err := r.matchSequencePart(*r.rule.query.JoinUntil, ev)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	key, err := r.joinUntilKey(ev)
	if err != nil {
		return err
	}
	delete(r.join.lookup, key)
	return nil
}

func allJoinSlotsFilled(events []*Event) bool {
	for _, ev := range events {
		if ev == nil {
			return false
		}
	}
	return true
}

func (r *runtimeRule) processKeyedSequence(ev *Event) ([]Match, error) {
	parts := r.rule.query.Sequence
	var matches []Match
	for stage := len(parts) - 1; stage >= 1; stage-- {
		advance, appendEvent, discardPending, err := r.sequenceStageTransition(parts[stage], ev)
		if err != nil {
			return nil, err
		}
		if !advance && !discardPending {
			continue
		}
		key, err := r.sequenceKey(stage, ev)
		if err != nil {
			return nil, err
		}
		if discardPending {
			delete(r.sequence.pendingBy[stage-1], key)
			continue
		}
		pending, exists := r.sequence.pendingBy[stage-1][key]
		if !exists {
			continue
		}
		events := append([]*Event(nil), pending...)
		if appendEvent {
			events = append(events, ev)
		}
		if !parts[stage].Fork {
			delete(r.sequence.pendingBy[stage-1], key)
		}
		if stage == len(parts)-1 {
			if len(r.pipes) > 0 {
				groups, err := r.processPipeGroups(events)
				if err != nil {
					return nil, err
				}
				for _, group := range groups {
					matches = append(matches, Match{Events: group})
				}
				continue
			}
			matches = append(matches, Match{Events: events})
			continue
		}
		r.sequence.pendingBy[stage][key] = events
	}
	advance, appendEvent, _, err := r.sequenceStageTransition(parts[0], ev)
	if err != nil {
		return nil, err
	}
	if advance {
		key, err := r.sequenceKey(0, ev)
		if err != nil {
			return nil, err
		}
		events := []*Event{}
		if appendEvent {
			events = append(events, ev)
		}
		r.sequence.pendingBy[0][key] = events
	}
	return matches, nil
}

func (r *runtimeRule) expireSequencePending(ev *Event) {
	if r == nil || r.rule == nil || r.rule.query == nil || !r.rule.query.HasMaxSpan || ev == nil {
		return
	}
	if !r.sequencePartEventType(ev.Type) {
		return
	}
	if usesSequenceKeys(r.rule.query) {
		for stage := range r.sequence.pendingBy {
			for key, events := range r.sequence.pendingBy[stage] {
				if !r.sequenceWithinMaxSpan(events, ev) {
					delete(r.sequence.pendingBy[stage], key)
				}
			}
		}
		return
	}
	for stage, events := range r.sequence.pending {
		if !r.sequenceWithinMaxSpan(events, ev) {
			r.sequence.pending[stage] = nil
		}
	}
}

func (r *runtimeRule) sequenceWithinMaxSpan(events []*Event, ev *Event) bool {
	if r == nil || r.rule == nil || r.rule.query == nil || !r.rule.query.HasMaxSpan {
		return true
	}
	if len(events) == 0 || events[0] == nil || ev == nil {
		return true
	}
	start := sequenceTimestampValue(events[0])
	current := sequenceTimestampValue(ev)
	if start.isInt && current.isInt {
		if current.i <= start.i {
			return true
		}
		maxSpan := r.rule.query.MaxSpan
		if maxSpan < 0 {
			return false
		}
		if start.i > math.MaxInt64-maxSpan {
			return true
		}
		return current.i <= start.i+maxSpan
	}
	return current.f-start.f <= float64(r.rule.query.MaxSpan)
}

func (r *runtimeRule) sequencePartEventType(eventType string) bool {
	if r == nil || r.rule == nil || r.rule.query == nil {
		return false
	}
	for _, part := range r.rule.query.Sequence {
		if eventTypeMatches(part.EventType, eventType) {
			return true
		}
	}
	return false
}

func sequenceTimestampValue(ev *Event) numericValue {
	if ev == nil {
		return numericValue{}
	}
	if ev.Data != nil {
		if raw, ok := ev.Data["timestamp"]; ok {
			if value, ok := numericValueOf(raw); ok {
				return value
			}
		}
	}
	return numericValue{f: float64(ev.Timestamp), i: ev.Timestamp, isInt: true}
}

func (r *runtimeRule) closeSequenceUntil(ev *Event) error {
	if r == nil || r.rule == nil || r.rule.query == nil || r.rule.query.SequenceUntil == nil {
		return nil
	}
	ok, err := r.matchSequencePart(*r.rule.query.SequenceUntil, ev)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if usesSequenceKeys(r.rule.query) {
		key, err := r.sequenceUntilKey(ev)
		if err != nil {
			return err
		}
		for stage := range r.sequence.pendingBy {
			delete(r.sequence.pendingBy[stage], key)
		}
		return nil
	}
	for stage := range r.sequence.pending {
		r.sequence.pending[stage] = nil
	}
	return nil
}

func usesSequenceKeys(q *ast.Query) bool {
	if q == nil {
		return false
	}
	if len(q.SequenceBy) > 0 {
		return true
	}
	for _, part := range q.Sequence {
		if len(part.By) > 0 {
			return true
		}
	}
	return false
}

func usesSampleKeys(q *ast.Query) bool {
	if q == nil {
		return false
	}
	if len(q.SampleBy) > 0 {
		return true
	}
	for _, part := range q.Sample {
		if len(part.By) > 0 {
			return true
		}
	}
	return false
}

func (r *runtimeRule) sequenceKey(stage int, ev *Event) (string, error) {
	args := make([]ast.Expr, 0, len(r.rule.query.SequenceBy)+len(r.rule.query.Sequence[stage].By))
	args = append(args, r.rule.query.SequenceBy...)
	args = append(args, r.rule.query.Sequence[stage].By...)
	values, err := r.pipeValues(args, ev, true)
	if err != nil {
		return "", err
	}
	return marshalRuntimeKeyValues(values)
}

func (r *runtimeRule) sampleKey(stage int, ev *Event) (string, error) {
	args := make([]ast.Expr, 0, len(r.rule.query.SampleBy)+len(r.rule.query.Sample[stage].By))
	args = append(args, r.rule.query.SampleBy...)
	args = append(args, r.rule.query.Sample[stage].By...)
	values, err := r.pipeValues(args, ev, true)
	if err != nil {
		return "", err
	}
	return marshalRuntimeKeyValues(values)
}

func (r *runtimeRule) sequenceUntilKey(ev *Event) (string, error) {
	if r == nil || r.rule == nil || r.rule.query == nil || r.rule.query.SequenceUntil == nil {
		return "", nil
	}
	args := make([]ast.Expr, 0, len(r.rule.query.SequenceBy)+len(r.rule.query.SequenceUntil.By))
	args = append(args, r.rule.query.SequenceBy...)
	args = append(args, r.rule.query.SequenceUntil.By...)
	values, err := r.pipeValues(args, ev, true)
	if err != nil {
		return "", err
	}
	return marshalRuntimeKeyValues(values)
}

func (r *runtimeRule) joinKey(stage int, ev *Event) (string, error) {
	args := make([]ast.Expr, 0, len(r.rule.query.JoinBy)+len(r.rule.query.Join[stage].By))
	args = append(args, r.rule.query.JoinBy...)
	args = append(args, r.rule.query.Join[stage].By...)
	values, err := r.pipeValues(args, ev, true)
	if err != nil {
		return "", err
	}
	return marshalRuntimeKeyValues(values)
}

func (r *runtimeRule) joinUntilKey(ev *Event) (string, error) {
	if r == nil || r.rule == nil || r.rule.query == nil || r.rule.query.JoinUntil == nil {
		return "", nil
	}
	args := make([]ast.Expr, 0, len(r.rule.query.JoinBy)+len(r.rule.query.JoinUntil.By))
	args = append(args, r.rule.query.JoinBy...)
	args = append(args, r.rule.query.JoinUntil.By...)
	values, err := r.pipeValues(args, ev, true)
	if err != nil {
		return "", err
	}
	return marshalRuntimeKeyValues(values)
}

func (r *runtimeRule) matchSequencePart(part ast.EventQuery, ev *Event) (bool, error) {
	if ev == nil || !eventTypeMatches(part.EventType, ev.Type) {
		return false, nil
	}
	v, err := r.evalExpr(part.Expr, ev)
	if err != nil {
		return false, err
	}
	ok, isNull := truthy(v)
	return !isNull && ok, nil
}

func (r *runtimeRule) sequenceStageTransition(part ast.EventQuery, ev *Event) (bool, bool, bool, error) {
	matched, err := r.matchSequencePart(part, ev)
	if err != nil {
		return false, false, false, err
	}
	if part.Negated {
		if ev == nil || !eventTypeMatches(part.EventType, ev.Type) {
			return false, false, false, nil
		}
		return !matched, false, matched && !part.Fork, nil
	}
	return matched, true, false, nil
}

func (r *runtimeRule) matchEvent(ev *Event) (bool, error) {
	if ev == nil || r == nil || r.rule == nil || r.rule.query == nil {
		return false, nil
	}
	if !eventTypeMatches(r.rule.query.EventType, ev.Type) {
		return false, nil
	}
	v, err := r.evalExpr(r.rule.query.Expr, ev)
	if err != nil {
		return false, err
	}
	ok, isNull := truthy(v)
	return !isNull && ok, nil
}

// Finalize flushes buffered engine state.
func (e *Engine) Finalize() ([]Match, error) {
	var matches []Match
	for _, runtime := range e.rules {
		if runtime != nil && runtime.rule != nil && runtime.rule.query != nil &&
			(len(runtime.rule.query.Join) > 0 || len(runtime.rule.query.Sequence) > 0 || len(runtime.rule.query.Sample) > 0) && len(runtime.pipes) > 0 {
			groups, err := runtime.finalizePipeGroups()
			if err != nil {
				return nil, err
			}
			for _, group := range groups {
				matches = append(matches, Match{Events: group})
			}
			continue
		}
		events, err := runtime.finalizePipes()
		if err != nil {
			return nil, err
		}
		for _, event := range events {
			matches = append(matches, Match{Events: []*Event{event}})
		}
	}
	return matches, nil
}

// EvalExpression evaluates an internal expression against one event.
func EvalExpression(expr ast.Expr, ev *Event, opts ...RuleOption) (any, error) {
	cfg := defaultRuleConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return eval(expr, ev, cfg)
}

// Match evaluates one event against one rule.
func (r *Rule) Match(ev *Event) (bool, error) {
	if ev == nil || r.query == nil {
		return false, nil
	}
	if !eventTypeMatches(r.query.EventType, ev.Type) {
		return false, nil
	}
	v, err := eval(r.query.Expr, ev, r.config)
	if err != nil {
		return false, err
	}
	ok, isNull := truthy(v)
	return !isNull && ok, nil
}

func eventTypeMatches(queryType string, eventType string) bool {
	return queryType == EventTypeAny || queryType == eventType
}

// EventFromData normalizes a raw JSON-like event map.
func EventFromData(data map[string]any) *Event {
	return EventFromDataWithNormalizer(data, nil)
}

// EventFromDataWithNormalizer normalizes a raw event map with custom logic when provided.
func EventFromDataWithNormalizer(data map[string]any, normalizer EventNormalizer) *Event {
	if normalizer != nil {
		return normalizer(data)
	}
	if data == nil {
		data = map[string]any{}
	}
	normalized := data
	if buf, ok := normalized["data_buffer"].(map[string]any); ok {
		normalized = buf
	}

	ts := int64(0)
	if raw, ok := normalized["timestamp"]; ok {
		ts = toInt64(raw)
	}

	eventType := EventTypeGeneric
	if raw, ok := normalized["event_type"].(string); ok {
		eventType = raw
	} else if raw, ok := normalized["event_type_full"].(string); ok {
		eventType = raw
		eventType = strings.TrimSuffix(eventType, "_event")
	}

	return &Event{Type: eventType, Timestamp: ts, Data: normalized}
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case ast.Num:
		if x.IsInt {
			return x.I
		}
		return int64(x.F)
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		if f, err := x.Float64(); err == nil {
			return int64(f)
		}
	case int64:
		return x
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case float64:
		return int64(x)
	case float32:
		return int64(x)
	default:
		return 0
	}
	return 0
}

type evalScope map[string]any

const namedEventOfScopeKey = "\x00named_event_of"
const namedChildOfScopeKey = "\x00named_child_of"
const namedDescendantOfScopeKey = "\x00named_descendant_of"

func pipeScope(*Event) evalScope {
	return nil
}

func groupScope(events []*Event) evalScope {
	if len(events) == 0 {
		return nil
	}
	values := make([]any, 0, len(events))
	for _, ev := range events {
		if ev == nil {
			values = append(values, nil)
			continue
		}
		values = append(values, ev.Data)
	}
	return evalScope{"events": values}
}

func firstGroupEvent(events []*Event) *Event {
	if len(events) == 0 {
		return nil
	}
	return events[0]
}

func copyEventGroup(events []*Event) []*Event {
	return append([]*Event(nil), events...)
}

func eventGroupsFromEvents(events []*Event) [][]*Event {
	groups := make([][]*Event, 0, len(events))
	for _, ev := range events {
		groups = append(groups, []*Event{ev})
	}
	return groups
}

func (r *runtimeRule) evalExpr(expr ast.Expr, ev *Event) (any, error) {
	if r == nil || r.rule == nil {
		return nil, fmt.Errorf("missing runtime rule")
	}
	return evalScoped(expr, ev, r.rule.config, r.namedEvalScope(nil))
}

func (r *runtimeRule) pipeValues(args []ast.Expr, ev *Event, foldCase bool) ([]any, error) {
	if r == nil || r.rule == nil {
		return nil, fmt.Errorf("missing runtime rule")
	}
	return pipeValuesWithScope(args, ev, r.rule.config, r.pipeEvalScope(ev), foldCase)
}

func (r *runtimeRule) pipeEvalScope(ev *Event) evalScope {
	return r.namedEvalScope(pipeScope(ev))
}

func (r *runtimeRule) groupEvalScope(events []*Event) evalScope {
	return r.namedEvalScope(groupScope(events))
}

func (r *runtimeRule) namedEvalScope(base evalScope) evalScope {
	if r == nil || len(r.named.nodes) == 0 {
		return base
	}
	scope := make(evalScope, len(base)+3)
	for key, value := range base {
		scope[key] = value
	}
	if len(r.named.eventOfByNode) > 0 {
		scope[namedEventOfScopeKey] = r.named.eventOfByNode
	}
	if len(r.named.childOfByNode) > 0 {
		scope[namedChildOfScopeKey] = r.named.childOfByNode
	}
	if len(r.named.descendantOfByNode) > 0 {
		scope[namedDescendantOfScopeKey] = r.named.descendantOfByNode
	}
	return scope
}

func eventPIDKey(ev *Event, allowZero bool) (string, bool, error) {
	return eventFieldKey(ev, "pid", allowZero)
}

func eventFieldKey(ev *Event, field string, allowZero bool) (string, bool, error) {
	if ev == nil || ev.Data == nil {
		return "", false, nil
	}
	raw, ok := ev.Data[field]
	if !ok || raw == nil {
		return "", false, nil
	}
	if text, ok := raw.(string); ok && text == "" {
		return "", false, nil
	}
	if value, ok := raw.(bool); ok && !value {
		return "", false, nil
	}
	if !allowZero {
		if n, ok := numericValueOf(raw); ok && n.f == 0 {
			return "", false, nil
		}
	}
	key, err := marshalRuntimeKey(raw, false)
	if err != nil {
		return "", false, err
	}
	return key, true, nil
}

func processPIDIsFour(ev *Event) bool {
	if ev == nil || ev.Data == nil {
		return false
	}
	n, ok := numericValueOf(ev.Data["pid"])
	return ok && n.f == 4
}

// processCreateOrFork reports whether the process event signals creation or fork.
// ECS mode (dataSource == ""): checks subtype == "create" or "fork".
// Endgame mode (dataSource == "endgame"): checks opcode == 1, 3, or 9.
func processCreateOrFork(data map[string]any, dataSource string) bool {
	if dataSource == "endgame" {
		n, ok := integerValue(data["opcode"])
		return ok && (n == 1 || n == 3 || n == 9)
	}
	subtype, _ := data["subtype"].(string)
	return subtype == "create" || subtype == "fork"
}

// processTerminate reports whether the process event signals termination.
// ECS mode: checks subtype == "terminate".
// Endgame mode: checks opcode == 2 or 4.
func processTerminate(data map[string]any, dataSource string) bool {
	if dataSource == "endgame" {
		n, ok := integerValue(data["opcode"])
		return ok && (n == 2 || n == 4)
	}
	subtype, _ := data["subtype"].(string)
	return subtype == "terminate"
}

func literalInt(expr ast.Expr) (int64, bool) {
	literal, ok := expr.(*ast.Literal)
	if !ok || literal.Kind != ast.LiteralNumber {
		return 0, false
	}
	return integerValue(literal.Value)
}

func pipeKey(args []ast.Expr, ev *Event, cfg ruleConfig) (string, error) {
	values, err := pipeValues(args, ev, cfg, true)
	if err != nil {
		return "", err
	}
	return marshalRuntimeKeyValues(values)
}

func pipeKeyWithScope(args []ast.Expr, ev *Event, cfg ruleConfig, scope evalScope) (string, error) {
	values, err := pipeValuesWithScope(args, ev, cfg, scope, true)
	if err != nil {
		return "", err
	}
	return marshalRuntimeKeyValues(values)
}

func pipeKeyGroup(args []ast.Expr, events []*Event, cfg ruleConfig) (string, error) {
	values, err := pipeValuesGroup(args, events, cfg, true)
	if err != nil {
		return "", err
	}
	return marshalRuntimeKeyValues(values)
}

func pipeKeyGroupWithScope(args []ast.Expr, events []*Event, cfg ruleConfig, scope evalScope) (string, error) {
	values, err := pipeValuesWithScope(args, firstGroupEvent(events), cfg, scope, true)
	if err != nil {
		return "", err
	}
	return marshalRuntimeKeyValues(values)
}

func marshalRuntimeKeyValues(values []any) (string, error) {
	return marshalRuntimeKeyWithArrays(pipeKeyValue(values), len(values) != 1, true)
}

func marshalRuntimeKey(key any, tuple bool) (string, error) {
	return marshalRuntimeKeyWithArrays(key, tuple, false)
}

func marshalRuntimeKeyWithArrays(key any, tuple bool, allowArrays bool) (string, error) {
	if err := validateRuntimeKey(key, tuple, allowArrays); err != nil {
		return "", err
	}
	body, err := json.Marshal(key)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func validateRuntimeKey(key any, tuple bool, allowArrays bool) error {
	if key == nil {
		return nil
	}
	if _, ok := numericValueOf(key); ok {
		return nil
	}
	switch key.(type) {
	case string, bool:
		return nil
	}
	rv := reflect.ValueOf(key)
	switch rv.Kind() {
	case reflect.Map:
		return fmt.Errorf("unhashable type: 'dict'")
	case reflect.Slice, reflect.Array:
		if !tuple && !allowArrays {
			return fmt.Errorf("unhashable type: 'list'")
		}
		for i := 0; i < rv.Len(); i++ {
			if err := validateRuntimeKey(rv.Index(i).Interface(), false, allowArrays); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizePipeKey(value any, caseInsensitive bool) any {
	switch v := value.(type) {
	case string:
		if caseInsensitive {
			return pythonLower(v)
		}
		return v
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, normalizePipeKey(item, caseInsensitive))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = normalizePipeKey(item, caseInsensitive)
		}
		return out
	default:
		return value
	}
}

func eval(expr ast.Expr, ev *Event, cfg ruleConfig) (any, error) {
	return evalScoped(expr, ev, cfg, nil)
}

func evalScoped(expr ast.Expr, ev *Event, cfg ruleConfig, scope evalScope) (any, error) {
	switch n := expr.(type) {
	case *ast.Literal:
		switch n.Kind {
		case ast.LiteralNull:
			return nil, nil
		case ast.LiteralBool, ast.LiteralString, ast.LiteralNumber:
			return n.Value, nil
		default:
			return nil, nil
		}
	case *ast.Field:
		return evalField(n, ev, scope), nil
	case *ast.FunctionCall:
		return evalFunction(n, ev, cfg, scope)
	case *ast.NamedSubquery:
		return evalNamedSubquery(n, ev, scope)
	case *ast.MathOperation:
		left, err := evalScoped(n.Left, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		right, err := evalScoped(n.Right, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		return evalMath(left, right, n.Op)
	case *ast.Comparison:
		left, err := evalScoped(n.Left, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		right, err := evalScoped(n.Right, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		if v, ok, err := evalWildcardComparison(n, left, right, cfg); ok {
			return v, err
		}
		return compare(left, right, n.Op, shouldFoldComparison(n), cfg.caseInsensitive), nil
	case *ast.IsNull:
		v, err := evalScoped(n.Expr, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		return v == nil, nil
	case *ast.IsNotNull:
		v, err := evalScoped(n.Expr, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		return v != nil, nil
	case *ast.InSet:
		return evalInSet(n, ev, cfg, scope)
	case *ast.Not:
		v, err := evalScoped(n.Term, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		ok, isNull := truthy(v)
		if isNull {
			return nil, nil
		}
		return !ok, nil
	case *ast.Logical:
		if n.Op == "and" {
			return evalAnd(n.Terms, ev, cfg, scope)
		}
		return evalOr(n.Terms, ev, cfg, scope)
	default:
		return nil, fmt.Errorf("unsupported expression %T", expr)
	}
}

func evalNamedSubquery(n *ast.NamedSubquery, ev *Event, scope evalScope) (any, error) {
	switch n.QueryType {
	case "event":
		return evalEventOfSubquery(n, ev, scope)
	case "child":
		return evalChildOfSubquery(n, ev, scope)
	case "descendant":
		return evalDescendantOfSubquery(n, ev, scope)
	default:
		return nil, fmt.Errorf("%s of is not supported in current feature set", n.QueryType)
	}
}

func evalEventOfSubquery(n *ast.NamedSubquery, ev *Event, scope evalScope) (any, error) {
	states, ok := scope[namedEventOfScopeKey].(map[*ast.NamedSubquery]*eventOfRuntime)
	if !ok {
		return nil, fmt.Errorf("named subquery requires streaming runtime state")
	}
	state := states[n]
	if state == nil {
		return nil, fmt.Errorf("named subquery state is missing")
	}
	key, ok, err := eventPIDKey(ev, false)
	if err != nil || !ok {
		return false, err
	}
	_, matched := state.pids[key]
	return matched, nil
}

func evalChildOfSubquery(n *ast.NamedSubquery, ev *Event, scope evalScope) (any, error) {
	states, ok := scope[namedChildOfScopeKey].(map[*ast.NamedSubquery]*childOfRuntime)
	if !ok {
		return nil, fmt.Errorf("named subquery requires streaming runtime state")
	}
	state := states[n]
	if state == nil {
		return nil, fmt.Errorf("named subquery state is missing")
	}
	key, ok, err := eventPIDKey(ev, true)
	if err != nil || !ok {
		return false, err
	}
	_, matched := state.children[key]
	return matched, nil
}

func evalDescendantOfSubquery(n *ast.NamedSubquery, ev *Event, scope evalScope) (any, error) {
	states, ok := scope[namedDescendantOfScopeKey].(map[*ast.NamedSubquery]*descendantOfRuntime)
	if !ok {
		return nil, fmt.Errorf("named subquery requires streaming runtime state")
	}
	state := states[n]
	if state == nil {
		return nil, fmt.Errorf("named subquery state is missing")
	}
	key, ok, err := eventPIDKey(ev, true)
	if err != nil || !ok {
		return false, err
	}
	_, matched := state.descendants[key]
	return matched, nil
}

func evalFunction(call *ast.FunctionCall, ev *Event, cfg ruleConfig, scope evalScope) (any, error) {
	switch call.Name {
	case "safe":
		return evalSafe(call, ev, cfg, scope)
	case "arraySearch":
		return evalArraySearch(call, ev, cfg, scope)
	case "arrayCount":
		return evalArrayCount(call, ev, cfg, scope)
	}
	args, err := evalArgs(call.Args, ev, cfg, scope)
	if err != nil {
		return nil, err
	}
	switch call.Name {
	case "length":
		return fnLength(args)
	case "wildcard":
		return fnWildcard(args, cfg)
	case "startsWith":
		return fnStartsWith(args, cfg)
	case "endsWith":
		return fnEndsWith(args, cfg)
	case "stringContains":
		return fnStringContains(args, cfg)
	case "match", "matchLite":
		return fnMatch(args, cfg)
	case "string":
		return fnString(args)
	case "number":
		return fnNumber(args)
	case "concat":
		return fnConcat(args)
	case "add", "subtract", "multiply", "divide", "modulo":
		return fnMath(args, call.Name)
	case "arrayContains":
		return fnArrayContains(args, cfg)
	case "indexOf":
		return fnIndexOf(args, cfg)
	case "substring":
		return fnSubstring(args)
	case "between":
		return fnBetween(args, cfg)
	case "cidrMatch":
		return fnCidrMatch(args)
	default:
		return nil, fmt.Errorf("unknown function %s", call.Name)
	}
}

func evalArgs(exprs []ast.Expr, ev *Event, cfg ruleConfig, scope evalScope) ([]any, error) {
	args := make([]any, 0, len(exprs))
	for _, expr := range exprs {
		value, err := evalScoped(expr, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		args = append(args, value)
	}
	return args, nil
}

func fnLength(args []any) (any, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("length expects 1 argument, got %d", len(args))
	}
	switch value := args[0].(type) {
	case string:
		return ast.Int(int64(len([]rune(value)))), nil
	case []any:
		return ast.Int(int64(len(value))), nil
	case map[string]any:
		return ast.Int(int64(len(value))), nil
	default:
		return nil, nil
	}
}

func fnWildcard(args []any, cfg ruleConfig) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("wildcard expects at least 2 arguments, got %d", len(args))
	}
	source, ok := args[0].(string)
	if !ok {
		return nil, nil
	}
	for _, rawPattern := range args[1:] {
		pattern, ok := rawPattern.(string)
		if !ok {
			continue
		}
		matched, err := wildcardMatch(source, pattern, cfg.caseInsensitive)
		if err != nil {
			return nil, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func fnStartsWith(args []any, cfg ruleConfig) (any, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("startsWith expects 2 arguments, got %d", len(args))
	}
	source, ok := args[0].(string)
	if !ok {
		return nil, nil
	}
	prefix, ok := args[1].(string)
	if !ok {
		return nil, nil
	}
	source, prefix = foldPair(source, prefix, cfg.caseInsensitive)
	return strings.HasPrefix(source, prefix), nil
}

func fnEndsWith(args []any, cfg ruleConfig) (any, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("endsWith expects 2 arguments, got %d", len(args))
	}
	source, ok := args[0].(string)
	if !ok {
		return nil, nil
	}
	suffix, ok := args[1].(string)
	if !ok {
		return nil, nil
	}
	source, suffix = foldPair(source, suffix, cfg.caseInsensitive)
	return strings.HasSuffix(source, suffix), nil
}

func fnStringContains(args []any, cfg ruleConfig) (any, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("stringContains expects 2 arguments, got %d", len(args))
	}
	source, ok := args[0].(string)
	if !ok {
		return false, nil
	}
	substring, ok := args[1].(string)
	if !ok {
		return false, nil
	}
	source, substring = foldPair(source, substring, cfg.caseInsensitive)
	return strings.Contains(source, substring), nil
}

func fnMatch(args []any, cfg ruleConfig) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("match expects at least 2 arguments, got %d", len(args))
	}
	source, ok := args[0].(string)
	if !ok {
		return nil, nil
	}
	var patterns []string
	for _, arg := range args[1:] {
		pattern, ok := arg.(string)
		if !ok {
			continue
		}
		patterns = append(patterns, pattern)
	}
	if len(patterns) == 0 {
		return false, nil
	}
	re, err := pycompat.CompileRegex(matchRegexPattern(patterns), cfg.caseInsensitive)
	if err != nil {
		return nil, err
	}
	match, err := re.FindStringMatchStartingAt(source, 0)
	if err != nil {
		return nil, err
	}
	return match != nil && match.Index == 0, nil
}

func matchRegexPattern(patterns []string) string {
	if len(patterns) == 1 {
		return patterns[0]
	}
	return "(?:" + strings.Join(patterns, "|") + ")"
}

func fnString(args []any) (any, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("string expects 1 argument, got %d", len(args))
	}
	return stringValue(args[0]), nil
}

func fnNumber(args []any) (any, error) {
	if len(args) != 1 && len(args) != 2 {
		return nil, fmt.Errorf("number expects 1 or 2 arguments, got %d", len(args))
	}
	source, ok := args[0].(string)
	if !ok {
		return nil, nil
	}
	base := int64(10)
	explicitBase := false
	if len(args) == 2 {
		if args[1] != nil {
			n, err := requiredIntegerArg("number", "base", args[1])
			if err != nil {
				return nil, err
			}
			base = n
			explicitBase = true
		}
	}
	return parseNumberFunction(source, base, explicitBase)
}

func fnConcat(args []any) (any, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("concat expects at least 1 argument, got 0")
	}
	var b strings.Builder
	for _, arg := range args {
		value := stringValue(arg)
		if value == nil {
			return nil, nil
		}
		b.WriteString(value.(string))
	}
	return b.String(), nil
}

func fnMath(args []any, name string) (any, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("%s expects 2 arguments, got %d", name, len(args))
	}
	left, ok := numericValueOf(args[0])
	if !ok {
		return nil, nil
	}
	right, ok := numericValueOf(args[1])
	if !ok {
		return nil, nil
	}
	return evalMathValues(left, right, name)
}

func evalMath(left, right any, op string) (any, error) {
	leftValue, ok := numericValueOf(left)
	if !ok {
		return nil, nil
	}
	rightValue, ok := numericValueOf(right)
	if !ok {
		return nil, nil
	}
	return evalMathValues(leftValue, rightValue, mathName(op))
}

func mathName(op string) string {
	switch op {
	case "+":
		return "add"
	case "-":
		return "subtract"
	case "*":
		return "multiply"
	case "/":
		return "divide"
	case "%":
		return "modulo"
	default:
		return op
	}
}

func evalMathValues(left, right numericValue, name string) (any, error) {
	switch name {
	case "add":
		if left.isInt && right.isInt {
			return ast.Int(left.i + right.i), nil
		}
		return ast.Float(left.f + right.f), nil
	case "subtract":
		if left.isInt && right.isInt {
			return ast.Int(left.i - right.i), nil
		}
		return ast.Float(left.f - right.f), nil
	case "multiply":
		if left.isInt && right.isInt {
			return ast.Int(left.i * right.i), nil
		}
		return ast.Float(left.f * right.f), nil
	case "divide":
		if right.f == 0 {
			return nil, nil
		}
		if left.isInt && right.isInt {
			return ast.Int(floorDiv(left.i, right.i)), nil
		}
		return ast.Float(left.f / right.f), nil
	case "modulo":
		if right.f == 0 {
			return nil, fmt.Errorf("integer division or modulo by zero")
		}
		if left.isInt && right.isInt {
			return ast.Int(floorMod(left.i, right.i)), nil
		}
		return ast.Float(floatMod(left.f, right.f)), nil
	default:
		return nil, fmt.Errorf("unknown math function %s", name)
	}
}

func floorDiv(left, right int64) int64 {
	q := left / right
	r := left % right
	if r != 0 && ((r > 0) != (right > 0)) {
		q--
	}
	return q
}

func floorMod(left, right int64) int64 {
	return left - floorDiv(left, right)*right
}

func floatMod(left, right float64) float64 {
	return left - math.Floor(left/right)*right
}

func fnArrayContains(args []any, cfg ruleConfig) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("arrayContains expects at least 2 arguments, got %d", len(args))
	}
	array, ok, err := arrayContainsValues(args[0])
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	for _, item := range array {
		for _, value := range args[1:] {
			if arrayValuesEqual(item, value, cfg) {
				return true, nil
			}
		}
	}
	return false, nil
}

func arrayContainsValues(v any) ([]any, bool, error) {
	if v == nil {
		return nil, false, nil
	}
	if s, ok := v.(string); ok {
		values := make([]any, 0, len([]rune(s)))
		for _, r := range s {
			values = append(values, string(r))
		}
		return values, true, nil
	}
	if m, ok := v.(map[string]any); ok {
		values := make([]any, 0, len(m))
		for key := range m {
			values = append(values, key)
		}
		return values, true, nil
	}
	values, ok := arrayValues(v)
	if ok {
		return values, true, nil
	}
	return nil, false, fmt.Errorf("%T object is not iterable", v)
}

func arrayValues(v any) ([]any, bool) {
	if v == nil {
		return nil, false
	}
	if values, ok := v.([]any); ok {
		return values, true
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, false
	}
	values := make([]any, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		values = append(values, rv.Index(i).Interface())
	}
	return values, true
}

func arrayValuesEqual(a, b any, cfg ruleConfig) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return compare(a, b, "==", true, cfg.caseInsensitive) == true
}

func evalSafe(call *ast.FunctionCall, ev *Event, cfg ruleConfig, scope evalScope) (any, error) {
	if len(call.Args) != 1 {
		return nil, fmt.Errorf("safe expects 1 argument, got %d", len(call.Args))
	}
	value, err := evalScoped(call.Args[0], ev, cfg, scope)
	if err != nil {
		return nil, nil
	}
	return value, nil
}

func evalArraySearch(call *ast.FunctionCall, ev *Event, cfg ruleConfig, scope evalScope) (any, error) {
	array, name, body, ok, err := dynamicArrayArgs(call, ev, cfg, scope)
	if err != nil || !ok {
		return false, err
	}
	for _, item := range array {
		value, err := evalScoped(body, ev, cfg, withScopedValue(scope, name, item))
		if err != nil {
			return nil, err
		}
		matched, isNull := truthy(value)
		if !isNull && matched {
			return true, nil
		}
	}
	return false, nil
}

func evalArrayCount(call *ast.FunctionCall, ev *Event, cfg ruleConfig, scope evalScope) (any, error) {
	array, name, body, ok, err := dynamicArrayArgs(call, ev, cfg, scope)
	if err != nil || !ok {
		return ast.Int(0), err
	}
	count := int64(0)
	for _, item := range array {
		value, err := evalScoped(body, ev, cfg, withScopedValue(scope, name, item))
		if err != nil {
			return nil, err
		}
		matched, isNull := truthy(value)
		if !isNull && matched {
			count++
		}
	}
	return ast.Int(count), nil
}

func dynamicArrayArgs(call *ast.FunctionCall, ev *Event, cfg ruleConfig, scope evalScope) ([]any, string, ast.Expr, bool, error) {
	if len(call.Args) != 3 {
		return nil, "", nil, false, fmt.Errorf("%s expects 3 arguments, got %d", call.Name, len(call.Args))
	}
	name, ok := variableName(call.Args[1])
	if !ok {
		return nil, "", nil, false, fmt.Errorf("%s expects variable name as second argument", call.Name)
	}
	rawArray, err := evalScoped(call.Args[0], ev, cfg, scope)
	if err != nil {
		return nil, "", nil, false, err
	}
	array, ok := arrayValues(rawArray)
	if !ok {
		return nil, name, call.Args[2], false, nil
	}
	return array, name, call.Args[2], true, nil
}

func variableName(expr ast.Expr) (string, bool) {
	field, ok := expr.(*ast.Field)
	if !ok || len(field.Path) != 0 || field.Base == "" {
		return "", false
	}
	return field.Base, true
}

func withScopedValue(scope evalScope, name string, value any) evalScope {
	next := make(evalScope, len(scope)+1)
	for k, v := range scope {
		next[k] = v
	}
	next[name] = value
	return next
}

func fnIndexOf(args []any, cfg ruleConfig) (any, error) {
	if len(args) != 2 && len(args) != 3 {
		return nil, fmt.Errorf("indexOf expects 2 or 3 arguments, got %d", len(args))
	}
	source, ok := args[0].(string)
	if !ok {
		return nil, nil
	}
	substring, ok := args[1].(string)
	if !ok {
		return nil, nil
	}
	start := int64(0)
	if len(args) == 3 {
		if args[2] != nil {
			value, err := requiredIntegerArg("indexOf", "start", args[2])
			if err != nil {
				return nil, err
			}
			start = value
		}
	}
	source, substring = foldPair(source, substring, cfg.caseInsensitive)
	sourceRunes := []rune(source)
	if substring == "" && start > int64(len(sourceRunes)) {
		return nil, fmt.Errorf("substring not found")
	}
	index := indexOfRunes(sourceRunes, []rune(substring), normalizeSliceIndex(start, len(sourceRunes)))
	if index < 0 {
		return nil, nil
	}
	return ast.Int(int64(index)), nil
}

func fnSubstring(args []any) (any, error) {
	if len(args) != 2 && len(args) != 3 {
		return nil, fmt.Errorf("substring expects 2 or 3 arguments, got %d", len(args))
	}
	source, ok := args[0].(string)
	if !ok {
		return nil, nil
	}
	runes := []rune(source)
	start := int64(0)
	if args[1] != nil {
		value, err := requiredIntegerArg("substring", "start", args[1])
		if err != nil {
			return nil, err
		}
		start = value
	}
	startIndex := normalizeSliceIndex(start, len(runes))
	endIndex := len(runes)
	if len(args) == 3 {
		if args[2] != nil {
			end, err := requiredIntegerArg("substring", "end", args[2])
			if err != nil {
				return nil, err
			}
			endIndex = normalizeSliceIndex(end, len(runes))
		}
	}
	if endIndex < startIndex {
		endIndex = startIndex
	}
	return string(runes[startIndex:endIndex]), nil
}

func fnBetween(args []any, cfg ruleConfig) (any, error) {
	if len(args) != 3 && len(args) != 4 {
		return nil, fmt.Errorf("between expects 3 or 4 arguments, got %d", len(args))
	}
	source, ok := args[0].(string)
	if !ok {
		return nil, nil
	}
	first, ok := args[1].(string)
	if !ok {
		return nil, nil
	}
	second, ok := args[2].(string)
	if !ok {
		return nil, nil
	}
	greedy := false
	if len(args) == 4 {
		value, isNull := truthy(args[3])
		if !isNull {
			greedy = value
		}
	}
	matchSource, matchFirst := foldPair(source, first, cfg.caseInsensitive)
	matchSource, matchSecond := foldPair(matchSource, second, cfg.caseInsensitive)
	sourceRunes := []rune(source)
	matchRunes := []rune(matchSource)
	firstRunes := []rune(matchFirst)
	secondRunes := []rune(matchSecond)
	left := indexOfRunes(matchRunes, firstRunes, 0)
	if left < 0 {
		return nil, nil
	}
	start := left + len(firstRunes)
	right := indexOfRunes(matchRunes, secondRunes, start)
	if greedy {
		right = lastIndexOfRunes(matchRunes, secondRunes, start)
	}
	if right < 0 {
		return nil, nil
	}
	return string(sourceRunes[start:right]), nil
}

func fnCidrMatch(args []any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("cidrMatch expects at least 2 arguments, got %d", len(args))
	}
	source, ok := args[0].(string)
	if !ok {
		return false, nil
	}
	addr, err := netip.ParseAddr(source)
	if err != nil {
		return nil, err
	}
	for _, arg := range args[1:] {
		cidr, ok := arg.(string)
		if !ok {
			continue
		}
		prefix, err := parseCIDRPrefix(cidr)
		if err != nil {
			return nil, err
		}
		if prefix.Contains(addr) {
			return true, nil
		}
	}
	return false, nil
}

func parseCIDRPrefix(cidr string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return netip.Prefix{}, err
	}
	return prefix.Masked(), nil
}

func integerValue(v any) (int64, bool) {
	n, ok := numericValueOf(v)
	if !ok || !n.isInt {
		return 0, false
	}
	return n.i, true
}

func requiredIntegerArg(functionName string, argName string, value any) (int64, error) {
	integer, ok := integerValue(value)
	if !ok {
		return 0, fmt.Errorf("%s %s must be an integer", functionName, argName)
	}
	return integer, nil
}

func normalizeSliceIndex(index int64, length int) int {
	normalized := index
	if normalized < 0 {
		normalized += int64(length)
	}
	if normalized < 0 {
		return 0
	}
	if normalized > int64(length) {
		return length
	}
	return int(normalized)
}

func indexOfRunes(source []rune, target []rune, start int) int {
	if len(target) == 0 {
		return start
	}
	if start > len(source)-len(target) {
		return -1
	}
	for i := start; i <= len(source)-len(target); i++ {
		if runesEqual(source[i:i+len(target)], target) {
			return i
		}
	}
	return -1
}

func lastIndexOfRunes(source []rune, target []rune, start int) int {
	if len(target) == 0 {
		return len(source)
	}
	for i := len(source) - len(target); i >= start; i-- {
		if runesEqual(source[i:i+len(target)], target) {
			return i
		}
	}
	return -1
}

func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case ast.Num:
		if x.IsInt {
			return strconv.FormatInt(x.I, 10)
		}
		return pythonFloatString(x.F, 64)
	case json.Number:
		return pythonJSONNumberString(x)
	case []any:
		return pythonRepr(x)
	case map[string]any:
		return pythonRepr(x)
	case int:
		return strconv.FormatInt(int64(x), 10)
	case int8:
		return strconv.FormatInt(int64(x), 10)
	case int16:
		return strconv.FormatInt(int64(x), 10)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint:
		return strconv.FormatUint(uint64(x), 10)
	case uint8:
		return strconv.FormatUint(uint64(x), 10)
	case uint16:
		return strconv.FormatUint(uint64(x), 10)
	case uint32:
		return strconv.FormatUint(uint64(x), 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case float32:
		return pythonFloatString(float64(x), 32)
	case float64:
		return pythonFloatString(x, 64)
	default:
		return fmt.Sprint(x)
	}
}

func pythonJSONNumberString(value json.Number) string {
	text := value.String()
	if !strings.ContainsAny(text, ".eE") {
		return text
	}
	if f, err := value.Float64(); err == nil {
		return pythonFloatString(f, 64)
	}
	return text
}

func pythonFloatString(value float64, bitSize int) string {
	if math.IsNaN(value) {
		return "nan"
	}
	if math.IsInf(value, 1) {
		return "inf"
	}
	if math.IsInf(value, -1) {
		return "-inf"
	}
	text := strconv.FormatFloat(value, 'g', -1, bitSize)
	if strings.ContainsAny(text, "eE") {
		parts := strings.FieldsFunc(text, func(r rune) bool { return r == 'e' || r == 'E' })
		if len(parts) == 2 {
			if exp, err := strconv.Atoi(parts[1]); err == nil && exp >= -4 && exp < 16 {
				text = strconv.FormatFloat(value, 'f', -1, bitSize)
			}
		}
	}
	if !strings.ContainsAny(text, ".eE") {
		text += ".0"
	}
	return text
}

func pythonRepr(value any) string {
	switch v := value.(type) {
	case nil:
		return "None"
	case string:
		return pythonStringRepr(v)
	case bool:
		if v {
			return "True"
		}
		return "False"
	case ast.Num:
		if v.IsInt {
			return strconv.FormatInt(v.I, 10)
		}
		return pythonFloatString(v.F, 64)
	case json.Number:
		return pythonJSONNumberString(v)
	case int:
		return strconv.FormatInt(int64(v), 10)
	case int8:
		return strconv.FormatInt(int64(v), 10)
	case int16:
		return strconv.FormatInt(int64(v), 10)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	case uint8:
		return strconv.FormatUint(uint64(v), 10)
	case uint16:
		return strconv.FormatUint(uint64(v), 10)
	case uint32:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float32:
		return pythonFloatString(float64(v), 32)
	case float64:
		return pythonFloatString(v, 64)
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, pythonRepr(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, pythonStringRepr(key)+": "+pythonRepr(v[key]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return fmt.Sprint(v)
	}
}

func pythonStringRepr(value string) string {
	quote := '\''
	if strings.ContainsRune(value, '\'') && !strings.ContainsRune(value, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteRune(quote)
	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r == quote {
				b.WriteRune('\\')
			}
			b.WriteRune(r)
		}
	}
	b.WriteRune(quote)
	return b.String()
}

func parseNumberFunction(source string, base int64, explicitBase bool) (any, error) {
	parseBase := base
	if parseBase == 0 {
		parseBase = 10
	}
	if strings.Count(source, ".") == 1 && (!explicitBase || base == 10) {
		value, err := strconv.ParseFloat(source, 64)
		if err != nil {
			return nil, err
		}
		return ast.Float(value), nil
	}
	if strings.HasPrefix(source, "0x") && (!explicitBase || base == 16) {
		value, err := strconv.ParseInt(source[2:], 16, 64)
		if err != nil {
			return nil, err
		}
		return ast.Int(value), nil
	}
	if isSignedDigits(source) {
		if base < 0 || base == 1 || base > 36 {
			return nil, fmt.Errorf("number base must be >= 2 and <= 36, or 0")
		}
		value, err := strconv.ParseInt(source, int(parseBase), 64)
		if err != nil {
			return nil, err
		}
		return ast.Int(value), nil
	}
	return nil, nil
}

func isSignedDigits(source string) bool {
	digits := strings.TrimLeft(source, "-+")
	if digits == "" {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type numericValue struct {
	f     float64
	i     int64
	isInt bool
}

func numericValueOf(v any) (numericValue, bool) {
	switch x := v.(type) {
	case ast.Num:
		if x.IsInt {
			return numericValue{f: float64(x.I), i: x.I, isInt: true}, true
		}
		return numericValue{f: x.F}, true
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return numericValue{f: float64(i), i: i, isInt: true}, true
		}
		if f, err := x.Float64(); err == nil {
			return numericValue{f: f}, true
		}
	case int:
		return numericValue{f: float64(x), i: int64(x), isInt: true}, true
	case int8:
		return numericValue{f: float64(x), i: int64(x), isInt: true}, true
	case int16:
		return numericValue{f: float64(x), i: int64(x), isInt: true}, true
	case int32:
		return numericValue{f: float64(x), i: int64(x), isInt: true}, true
	case int64:
		return numericValue{f: float64(x), i: x, isInt: true}, true
	case uint:
		if uint64(x) > math.MaxInt64 {
			return numericValue{f: float64(x)}, true
		}
		return numericValue{f: float64(x), i: int64(x), isInt: true}, true
	case uint8:
		return numericValue{f: float64(x), i: int64(x), isInt: true}, true
	case uint16:
		return numericValue{f: float64(x), i: int64(x), isInt: true}, true
	case uint32:
		return numericValue{f: float64(x), i: int64(x), isInt: true}, true
	case uint64:
		if x > math.MaxInt64 {
			return numericValue{f: float64(x)}, true
		}
		return numericValue{f: float64(x), i: int64(x), isInt: true}, true
	case float32:
		return numericValue{f: float64(x)}, true
	case float64:
		return numericValue{f: x}, true
	}
	return numericValue{}, false
}

func addNumericValues(left numericValue, right numericValue) numericValue {
	out := numericValue{
		f:     left.f + right.f,
		isInt: left.isInt && right.isInt,
	}
	if out.isInt {
		out.i = left.i + right.i
	}
	return out
}

func numericOutputValue(value numericValue) any {
	if value.isInt {
		return value.i
	}
	return value.f
}

func evalInSet(set *ast.InSet, ev *Event, cfg ruleConfig, scope evalScope) (any, error) {
	left, err := evalScoped(set.Expr, ev, cfg, scope)
	if err != nil {
		return nil, err
	}
	if left == nil && !isNullLiteral(set.Expr) {
		return nil, nil
	}
	allValuesLiteral := allInSetValuesLiterals(set.Values)
	sawNull := false
	for _, item := range set.Values {
		right, err := evalScoped(item, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		if right == nil {
			if isNullLiteral(set.Expr) && isNullLiteral(item) {
				return true, nil
			}
			if !allValuesLiteral {
				sawNull = true
			}
			continue
		}
		if left == nil {
			continue
		}
		cmp := compare(left, right, "==", shouldFoldInSet(set.Expr, item), cfg.caseInsensitive)
		if cmp == true {
			return true, nil
		}
		if cmp == nil && !allValuesLiteral {
			sawNull = true
		}
	}
	if sawNull {
		return nil, nil
	}
	return false, nil
}

func allInSetValuesLiterals(values []ast.Expr) bool {
	for _, value := range values {
		if _, ok := value.(*ast.Literal); !ok {
			return false
		}
	}
	return true
}

func isNullLiteral(e ast.Expr) bool {
	l, ok := e.(*ast.Literal)
	return ok && l.Kind == ast.LiteralNull
}

func evalWildcardComparison(c *ast.Comparison, left, right any, cfg ruleConfig) (any, bool, error) {
	if cfg.elasticsearchSyntax {
		return nil, false, nil
	}
	if c.Op != "==" && c.Op != "!=" {
		return nil, false, nil
	}
	if pattern, ok := wildcardLiteral(c.Left); ok {
		result, err := wildcardCompareValue(right, pattern, c.Op, cfg.caseInsensitive)
		return result, true, err
	}
	if pattern, ok := wildcardLiteral(c.Right); ok {
		result, err := wildcardCompareValue(left, pattern, c.Op, cfg.caseInsensitive)
		return result, true, err
	}
	return nil, false, nil
}

func wildcardLiteral(expr ast.Expr) (string, bool) {
	literal, ok := expr.(*ast.Literal)
	if !ok || literal.Kind != ast.LiteralString {
		return "", false
	}
	value, ok := literal.Value.(string)
	return value, ok && strings.Contains(value, "*")
}

func wildcardCompareValue(source any, pattern string, op string, caseInsensitive bool) (any, error) {
	sourceString, ok := source.(string)
	if !ok {
		return nil, nil
	}
	matched, err := wildcardMatch(sourceString, pattern, caseInsensitive)
	if err != nil {
		return nil, err
	}
	if op == "!=" {
		return !matched, nil
	}
	return matched, nil
}

func evalAnd(terms []ast.Expr, ev *Event, cfg ruleConfig, scope evalScope) (any, error) {
	aggregate := any(true)
	for i, term := range terms {
		v, err := evalScoped(term, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		ok, isNull := truthy(v)
		if !isNull && !ok {
			return false, nil
		}
		if i == 0 {
			aggregate = v
		}
		if isNull {
			aggregate = nil
		}
	}
	return aggregate, nil
}

func evalOr(terms []ast.Expr, ev *Event, cfg ruleConfig, scope evalScope) (any, error) {
	aggregate := any(false)
	for i, term := range terms {
		v, err := evalScoped(term, ev, cfg, scope)
		if err != nil {
			return nil, err
		}
		ok, isNull := truthy(v)
		if !isNull && ok {
			return true, nil
		}
		if i == 0 {
			aggregate = v
		}
		if isNull {
			aggregate = nil
		}
	}
	return aggregate, nil
}

func evalField(f *ast.Field, ev *Event, scope evalScope) any {
	if ev == nil {
		return nil
	}
	var value any
	if scoped, ok := scope[f.Base]; ok {
		value = scoped
	} else {
		value = ev.Data[f.Base]
	}
	for _, part := range f.Path {
		if value == nil {
			return nil
		}
		if part.IsIdx {
			arr, ok := value.([]any)
			if !ok || part.Index < 0 || part.Index >= len(arr) {
				return nil
			}
			value = arr[part.Index]
			continue
		}
		switch cur := value.(type) {
		case map[string]any:
			value = cur[part.Name]
		case string:
			value = cur == part.Name
		default:
			return nil
		}
	}
	return value
}

func shouldFoldComparison(c *ast.Comparison) bool {
	return foldableStringExpr(c.Left) && foldableStringExpr(c.Right)
}

func shouldFoldInSet(left ast.Expr, right ast.Expr) bool {
	return foldableStringExpr(left) && foldableStringExpr(right)
}

func foldableStringExpr(e ast.Expr) bool {
	switch e.(type) {
	case *ast.Field:
		return true
	case *ast.FunctionCall:
		return true
	case *ast.Literal:
		return e.(*ast.Literal).Kind == ast.LiteralString
	default:
		return false
	}
}

func compare(a, b any, op string, foldStrings, caseInsensitive bool) any {
	if a == nil || b == nil {
		return nil
	}
	if as, ok := a.(string); ok {
		bs, ok := b.(string)
		if !ok {
			return nil
		}
		if foldStrings && caseInsensitive {
			as = pythonLower(as)
			bs = pythonLower(bs)
		}
		return compareOrdered(as, bs, op)
	}
	if ai, ok := integerValue(a); ok {
		bi, ok := integerValue(b)
		if ok {
			return compareOrdered(ai, bi, op)
		}
	}
	if an, ok := numberFloat(a); ok {
		bn, ok := numberFloat(b)
		if !ok {
			return nil
		}
		return compareOrdered(an, bn, op)
	}
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return nil
	}
	switch op {
	case "==":
		return reflect.DeepEqual(a, b)
	case "!=":
		return !reflect.DeepEqual(a, b)
	default:
		return nil
	}
}

func wildcardMatch(source string, pattern string, caseInsensitive bool) (bool, error) {
	if caseInsensitive {
		source = pythonLower(source)
		pattern = pythonLower(pattern)
	}
	re, err := regexp.Compile(wildcardRegex(pattern))
	if err != nil {
		return false, err
	}
	return re.MatchString(source), nil
}

func wildcardRegex(pattern string) string {
	parts := strings.Split(pattern, "*")
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	regex := "(?s)^" + strings.Join(parts, ".*?") + "$"
	if strings.HasSuffix(regex, ".*?$") {
		regex = strings.TrimSuffix(regex, ".*?$")
	}
	return regex
}

func foldPair(a, b string, caseInsensitive bool) (string, string) {
	if !caseInsensitive {
		return a, b
	}
	return pythonLower(a), pythonLower(b)
}

func pythonLower(value string) string {
	return pycompat.Lower(value)
}

func numberFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case ast.Num:
		return x.Float64(), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case int:
		return float64(x), true
	case int8:
		return float64(x), true
	case int16:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint:
		return float64(x), true
	case uint8:
		return float64(x), true
	case uint16:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float32:
		return float64(x), true
	case float64:
		return x, true
	default:
		return 0, false
	}
}

type ordered interface {
	~string | ~float64 | ~int | ~int64
}

func compareOrdered[T ordered](a, b T, op string) any {
	switch op {
	case "==":
		return a == b
	case "!=":
		return a != b
	case "<":
		return a < b
	case "<=":
		return a <= b
	case ">":
		return a > b
	case ">=":
		return a >= b
	default:
		return nil
	}
}

func truthy(v any) (bool, bool) {
	if v == nil {
		return false, true
	}
	switch x := v.(type) {
	case bool:
		return x, false
	case string:
		return x != "", false
	case ast.Num:
		return !x.IsZero(), false
	case json.Number:
		n, ok := numberFloat(x)
		if !ok {
			return false, true
		}
		return n != 0, false
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		n, _ := numberFloat(x)
		return n != 0, false
	case []any:
		return len(x) != 0, false
	case map[string]any:
		return len(x) != 0, false
	default:
		return true, false
	}
}
