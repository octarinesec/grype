package match

import "github.com/octarinesec/grype/internal/log"

var explicitIgnoreRules []IgnoreRule

func init() {
	type ignoreValues struct {
		typ             string
		vulnerabilities []string
		packages        []string
	}

	var explicitIgnores = []ignoreValues{
		// Based on https://github.com/anchore/grype/issues/552, which includes a reference to the
		// https://github.com/mergebase/log4j-samples collection, we want to filter these explicitly:
		{"java-archive",
			[]string{"CVE-2021-44228", "CVE-2021-45046", "GHSA-jfh8-c2jp-5v3q", "GHSA-7rjr-3q55-vv33"},
			[]string{"log4j-api", "log4j-slf4j-impl", "log4j-to-slf4j", "log4j-1.2-api", "log4j-detector", "log4j-over-slf4j", "slf4j-log4j12"},
		},
	}

	for _, ignore := range explicitIgnores {
		for _, vulnerability := range ignore.vulnerabilities {
			for _, packageName := range ignore.packages {
				explicitIgnoreRules = append(explicitIgnoreRules, IgnoreRule{
					Vulnerability: vulnerability,
					Package: IgnoreRulePackage{
						Name: packageName,
						Type: ignore.typ,
					},
				})
			}
		}
	}
}

// ApplyExplicitIgnoreRules This will filter out matches that are defined above, in the
// explicitIgnores list
func ApplyExplicitIgnoreRules(matches Matches) Matches {
	matches, ignored := ApplyIgnoreRules(matches, explicitIgnoreRules)

	if len(ignored) > 0 {
		log.Debugf("Removed %d explicit vulnerability matches:", len(ignored))
		for idx, i := range ignored {
			branch := "├──"
			if idx == len(ignored)-1 {
				branch = "└──"
			}
			log.Debugf("  %s %s : %s", branch, i.Match.Vulnerability.ID, i.Package.PURL)
		}
	}

	return matches
}
