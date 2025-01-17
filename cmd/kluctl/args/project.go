package args

type ProjectFlags struct {
	ProjectUrl string `group:"project" short:"p" help:"Git url of the kluctl project. If not specified, the current directory will be used instead of a remote Git project"`
	ProjectRef string `group:"project" short:"b" help:"Git ref of the kluctl project. Only used when --project-url was given."`

	ProjectConfig       string `group:"project" short:"c" help:"Location of the .kluctl.yml config file. Defaults to $PROJECT/.kluctl.yml" type:"existingfile"`
	LocalClusters       string `group:"project" help:"Local clusters directory. Overrides the project from .kluctl.yml" type:"existingdir"`
	LocalDeployment     string `group:"project" help:"Local deployment directory. Overrides the project from .kluctl.yml" type:"existingdir"`
	LocalSealedSecrets  string `group:"project" help:"Local sealed-secrets directory. Overrides the project from .kluctl.yml" type:"existingdir"`
	FromArchive         string `group:"project" help:"Load project (.kluctl.yml, cluster, ...) from archive. Given path can either be an archive file or a directory with the extracted contents." type:"existingfile"`
	FromArchiveMetadata string `group:"project" help:"Specify where to load metadata (targets, ...) from. If not specified, metadata is assumed to be part of the archive." type:"existingfile"`
	Cluster             string `group:"project" help:"Specify/Override cluster"`
}

type ArgsFlags struct {
	Arg []string `group:"project" short:"a" help:"Template argument in the form name=value"`
}

type TargetFlags struct {
	Target string `group:"project" short:"t" help:"Target name to run command for. Target must exist in .kluctl.yml."`
}
