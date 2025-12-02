package parser

import (
	"bufio"
	"bytes"
	"io"
	"regexp"
	"slices"
	"strings"
)

type Match struct {
	Text    string
	Parts   []string
	Matches []string
	Idx     int
}

type Rule[S any] struct {
	fn func(idx int, line string) (matched bool, matches []string)
	do func(*S, Match)
}

type Program[S any] struct {
	state   *S
	fs      string
	rs      []byte
	beginFn func(*S)
	endFn   func(*S)
	rules   []Rule[S]
}

func NewProgram[S any](opts ...Option[S]) (p *Program[S]) {
	var state S
	p = &Program[S]{
		state: &state,
		fs:    " ",
		rs:    []byte{'\n'},
	}

	for _, opt := range opts {
		opt(p)
	}

	return
}

func (p *Program[S]) regex(pattern string, do func(*S, Match)) {
	re := regexp.MustCompile(pattern)
	p.rules = append(p.rules, Rule[S]{
		fn: func(_ int, line string) (matched bool, matches []string) {
			sub := re.FindStringSubmatch(line)
			if sub != nil {
				return true, sub[1:]
			}
			return false, nil
		},
		do: do,
	})
}

func (p *Program[S]) when(fn func(line string) bool, do func(*S, Match)) {
	p.rules = append(p.rules, Rule[S]{fn: func(_ int, line string) (matched bool, _ []string) {
		matched = fn(line)
		return
	}, do: do})
}

func (p *Program[S]) always(do func(*S, Match)) {
	p.rules = append(p.rules, Rule[S]{fn: func(int, string) (bool, []string) { return true, nil }, do: do})
}

func (p *Program[S]) lt(lineNum int, do func(*S, Match)) {
	p.rules = append(p.rules, Rule[S]{fn: func(idx int, line string) (matched bool, _ []string) {
		matched = lineNum < idx
		return
	}, do: do})
}

func (p *Program[S]) gt(lineNum int, do func(*S, Match)) {
	p.rules = append(p.rules, Rule[S]{fn: func(idx int, line string) (matched bool, _ []string) {
		matched = lineNum > idx
		return
	}, do: do})
}

func (p *Program[S]) ge(lineNum int, do func(*S, Match)) {
	p.rules = append(p.rules, Rule[S]{fn: func(idx int, line string) (matched bool, _ []string) {
		matched = lineNum >= idx
		return
	}, do: do})
}

func (p *Program[S]) le(lineNum int, do func(*S, Match)) {
	p.rules = append(p.rules, Rule[S]{fn: func(idx int, line string) (matched bool, _ []string) {
		matched = lineNum <= idx
		return
	}, do: do})
}

func (p *Program[S]) ne(lineNum int, do func(*S, Match)) {
	p.rules = append(p.rules, Rule[S]{fn: func(idx int, line string) (matched bool, _ []string) {
		matched = lineNum != idx
		return
	}, do: do})
}

func (p *Program[S]) eq(lineNum int, do func(*S, Match)) {
	p.rules = append(p.rules, Rule[S]{fn: func(idx int, line string) (matched bool, _ []string) {
		matched = lineNum == idx
		return
	}, do: do})
}

func (p *Program[S]) Run(r io.Reader) (state *S, err error) {
	if p.beginFn != nil {
		p.beginFn(p.state)
	}

	scanner := bufio.NewScanner(r)

	if !slices.Equal(p.rs, []byte{'\n'}) {
		scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			if atEOF && len(data) > 0 {
				advance, token = len(data), data
				return
			}

			if i := bytes.Index(data, p.rs); i >= 0 {
				return i + len(p.rs), data[:i], nil
			}

			return
		})
	}

	for idx := 0; scanner.Scan(); idx++ {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		for _, rule := range p.rules {
			if matched, matches := rule.fn(idx, line); matched {
				rule.do(p.state, Match{
					Text:    line,
					Parts:   strings.Split(line, p.fs),
					Matches: matches,
					Idx:     idx,
				})
			}
		}
	}

	if p.endFn != nil {
		p.endFn(p.state)
	}

	err = scanner.Err()
	if err != nil {
		return
	}

	state = p.state
	return
}

type Option[S any] func(*Program[S])

func FS[S any](fs string) Option[S] {
	return func(p *Program[S]) {
		p.fs = fs
	}
}

func RS[S any](rs string) Option[S] {
	return func(p *Program[S]) {
		p.rs = []byte(rs)
	}
}

func Begin[S any](fn func(*S)) Option[S] {
	return func(p *Program[S]) {
		p.beginFn = fn
	}
}

func End[S any](fn func(*S)) Option[S] {
	return func(p *Program[S]) {
		p.endFn = fn
	}
}

func Regex[S any](pattern string, do func(*S, Match)) Option[S] {
	return func(p *Program[S]) {
		p.regex(pattern, do)
	}
}

func When[S any](fn func(line string) bool, do func(*S, Match)) Option[S] {
	return func(p *Program[S]) {
		p.when(fn, do)
	}
}

func Always[S any](do func(*S, Match)) Option[S] {
	return func(p *Program[S]) {
		p.always(do)
	}
}

func Lt[S any](lineNum int, do func(*S, Match)) Option[S] {
	return func(p *Program[S]) {
		p.lt(lineNum, do)
	}
}

func Le[S any](lineNum int, do func(*S, Match)) Option[S] {
	return func(p *Program[S]) {
		p.le(lineNum, do)
	}
}

func Gt[S any](lineNum int, do func(*S, Match)) Option[S] {
	return func(p *Program[S]) {
		p.gt(lineNum, do)
	}
}

func Ge[S any](lineNum int, do func(*S, Match)) Option[S] {
	return func(p *Program[S]) {
		p.ge(lineNum, do)
	}
}

func Eq[S any](lineNum int, do func(*S, Match)) Option[S] {
	return func(p *Program[S]) {
		p.eq(lineNum, do)
	}
}

func Ne[S any](lineNum int, do func(*S, Match)) Option[S] {
	return func(p *Program[S]) {
		p.ne(lineNum, do)
	}
}
