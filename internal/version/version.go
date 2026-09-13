package version

// Version is the current semantic version of Funnel.
// Can be set at compile time via:
// -ldflags="-X github.com/AhmadShamli/Funnel/internal/version.Version=x.y.z"
var Version = "0.4.3"

const (
	// AppName is the official display name of the application.
	AppName = "Funnel by ExciteCreation"

	// Author is the organization/author name.
	Author = "ExciteCreation"

	// RepositoryURL is the official GitHub repository link.
	RepositoryURL = "https://github.com/AhmadShamli/Funnel"
)

// FullVersionString returns the full formatted version with branding and repo link.
func FullVersionString() string {
	return AppName + " v" + Version + " (" + RepositoryURL + ")"
}
