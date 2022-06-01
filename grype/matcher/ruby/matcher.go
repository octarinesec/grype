package ruby

import (
	"github.com/octarinesec/grype/grype/distro"
	"github.com/octarinesec/grype/grype/match"
	"github.com/octarinesec/grype/grype/pkg"
	"github.com/octarinesec/grype/grype/search"
	"github.com/octarinesec/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.GemPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.RubyGemMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	return search.ByCriteria(store, d, p, m.Type(), search.CommonCriteria...)
}
