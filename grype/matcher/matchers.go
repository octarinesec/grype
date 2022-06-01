package matcher

import (
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/octarinesec/grype/grype/distro"
	"github.com/octarinesec/grype/grype/event"
	"github.com/octarinesec/grype/grype/match"
	"github.com/octarinesec/grype/grype/matcher/apk"
	"github.com/octarinesec/grype/grype/matcher/dotnet"
	"github.com/octarinesec/grype/grype/matcher/dpkg"
	"github.com/octarinesec/grype/grype/matcher/java"
	"github.com/octarinesec/grype/grype/matcher/javascript"
	"github.com/octarinesec/grype/grype/matcher/msrc"
	"github.com/octarinesec/grype/grype/matcher/python"
	"github.com/octarinesec/grype/grype/matcher/rpmdb"
	"github.com/octarinesec/grype/grype/matcher/ruby"
	"github.com/octarinesec/grype/grype/matcher/stock"
	"github.com/octarinesec/grype/grype/pkg"
	"github.com/octarinesec/grype/grype/vulnerability"
	"github.com/octarinesec/grype/internal/bus"
	"github.com/octarinesec/grype/internal/log"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Monitor struct {
	PackagesProcessed         progress.Monitorable
	VulnerabilitiesDiscovered progress.Monitorable
}

// Config contains values used by individual matcher structs for advanced configuration
type Config struct {
	Java java.MatcherConfig
}

func NewDefaultMatchers(mc Config) []Matcher {
	return []Matcher{
		&dpkg.Matcher{},
		&ruby.Matcher{},
		&python.Matcher{},
		&dotnet.Matcher{},
		&rpmdb.Matcher{},
		java.NewJavaMatcher(mc.Java),
		&javascript.Matcher{},
		&apk.Matcher{},
		&msrc.Matcher{},
	}
}

func trackMatcher() (*progress.Manual, *progress.Manual) {
	packagesProcessed := progress.Manual{}
	vulnerabilitiesDiscovered := progress.Manual{}

	bus.Publish(partybus.Event{
		Type: event.VulnerabilityScanningStarted,
		Value: Monitor{
			PackagesProcessed:         progress.Monitorable(&packagesProcessed),
			VulnerabilitiesDiscovered: progress.Monitorable(&vulnerabilitiesDiscovered),
		},
	})
	return &packagesProcessed, &vulnerabilitiesDiscovered
}

func newMatcherIndex(matchers []Matcher) map[syftPkg.Type][]Matcher {
	matcherIndex := make(map[syftPkg.Type][]Matcher)
	for _, m := range matchers {
		for _, t := range m.PackageTypes() {
			if _, ok := matcherIndex[t]; !ok {
				matcherIndex[t] = make([]Matcher, 0)
			}

			matcherIndex[t] = append(matcherIndex[t], m)
			log.Debugf("adding matcher: %+v", t)
		}
	}

	return matcherIndex
}

func FindMatches(provider vulnerability.Provider, release *linux.Release, matchers []Matcher, packages []pkg.Package) match.Matches {
	var err error
	res := match.NewMatches()
	matcherIndex := newMatcherIndex(matchers)

	var d *distro.Distro
	if release != nil {
		d, err = distro.NewFromRelease(*release)
		if err != nil {
			log.Warnf("unable to determine linux distribution: %+v", err)
		}
	}

	packagesProcessed, vulnerabilitiesDiscovered := trackMatcher()

	defaultMatcher := &stock.Matcher{}
	for _, p := range packages {
		packagesProcessed.N++
		log.Debugf("searching for vulnerability matches for pkg=%s", p)

		matchers, ok := matcherIndex[p.Type]
		if !ok {
			matchers = []Matcher{defaultMatcher}
		}
		for _, m := range matchers {
			matches, err := m.Match(provider, d, p)
			if err != nil {
				log.Warnf("matcher failed for pkg=%s: %+v", p, err)
			} else {
				logMatches(p, matches)
				res.Add(matches...)
				vulnerabilitiesDiscovered.N += int64(len(matches))
			}
		}
	}

	packagesProcessed.SetCompleted()
	vulnerabilitiesDiscovered.SetCompleted()

	res = match.ApplyExplicitIgnoreRules(res)

	return res
}

func logMatches(p pkg.Package, matches []match.Match) {
	if len(matches) > 0 {
		log.Debugf("found %d vulnerabilities for pkg=%s", len(matches), p)
		for idx, m := range matches {
			var branch = "├──"
			if idx == len(matches)-1 {
				branch = "└──"
			}
			log.Debugf("  %s %s", branch, m.Summary())
		}
	}
}
