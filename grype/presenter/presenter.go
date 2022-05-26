package presenter

import (
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/octarinesec/grype/grype/match"
	"github.com/octarinesec/grype/grype/pkg"
	"github.com/octarinesec/grype/grype/presenter/cyclonedx"
	"github.com/octarinesec/grype/grype/presenter/cyclonedxvex"
	"github.com/octarinesec/grype/grype/presenter/json"
	"github.com/octarinesec/grype/grype/presenter/sarif"
	"github.com/octarinesec/grype/grype/presenter/table"
	"github.com/octarinesec/grype/grype/presenter/template"
	"github.com/octarinesec/grype/grype/vulnerability"
)

// Presenter is the main interface other Presenters need to implement
type Presenter interface {
	Present(io.Writer) error
}

// GetPresenter retrieves a Presenter that matches a CLI option
func GetPresenter(presenterConfig Config, matches match.Matches, ignoredMatches []match.IgnoredMatch, packages []pkg.Package, context pkg.Context, metadataProvider vulnerability.MetadataProvider, appConfig interface{}, dbStatus interface{}) Presenter {
	switch presenterConfig.format {
	case jsonFormat:
		return json.NewPresenter(matches, ignoredMatches, packages, context, metadataProvider, appConfig, dbStatus)
	case tableFormat:
		return table.NewPresenter(matches, packages, metadataProvider)
	case cycloneDXFormat:
		return cyclonedx.NewPresenter(matches, packages, context.Source, metadataProvider)
	case embeddedVEXJSON:
		return cyclonedxvex.NewPresenter(matches, packages, context.Source, metadataProvider, true, cdx.BOMFileFormatJSON)
	case embeddedVEXXML:
		return cyclonedxvex.NewPresenter(matches, packages, context.Source, metadataProvider, true, cdx.BOMFileFormatXML)
	case sarifFormat:
		return sarif.NewPresenter(matches, packages, context.Source, metadataProvider)
	case templateFormat:
		return template.NewPresenter(matches, ignoredMatches, packages, context, metadataProvider, appConfig, dbStatus, presenterConfig.templateFilePath)
	default:
		return nil
	}
}
