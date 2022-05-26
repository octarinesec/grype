package matcher

import (
	"github.com/octarinesec/grype/grype/distro"
	"github.com/octarinesec/grype/grype/match"
	"github.com/octarinesec/grype/grype/pkg"
	"github.com/octarinesec/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher interface {
	PackageTypes() []syftPkg.Type
	Type() match.MatcherType
	Match(vulnerability.Provider, *distro.Distro, pkg.Package) ([]match.Match, error)
}
