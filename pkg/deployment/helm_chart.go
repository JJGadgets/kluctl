package deployment

import (
	"fmt"
	"github.com/kluctl/kluctl/pkg/k8s"
	"github.com/kluctl/kluctl/pkg/types"
	"github.com/kluctl/kluctl/pkg/utils"
	"github.com/kluctl/kluctl/pkg/utils/uo"
	"github.com/kluctl/kluctl/pkg/utils/versions"
	"github.com/kluctl/kluctl/pkg/yaml"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type helmChart struct {
	configFile string
	Config     *types.HelmChartConfig
}

func NewHelmChart(configFile string) (*helmChart, error) {
	var config types.HelmChartConfig
	err := yaml.ReadYamlFile(configFile, &config)
	if err != nil {
		return nil, err
	}

	hc := &helmChart{
		configFile: configFile,
		Config:     &config,
	}
	return hc, nil
}

func (c *helmChart) withRepoContext(cb func(repoName string) error) error {
	needRepo := false
	repoName := "stable"

	if c.Config.Repo != nil && *c.Config.Repo != "stable" {
		needRepo = true
		repoName = fmt.Sprintf("kluctl-%s", utils.Sha256String(*c.Config.Repo))[:16]
	}

	if needRepo {
		_, _ = c.doHelm([]string{"repo", "remove", repoName}, true)
		_, err := c.doHelm([]string{"repo", "add", repoName, *c.Config.Repo}, false)
		if err != nil {
			return err
		}
		defer func() {
			_, _ = c.doHelm([]string{"repo", "remove", repoName}, true)
		}()
	} else {
		_, err := c.doHelm([]string{"repo", "update"}, false)
		if err != nil {
			return err
		}
	}
	return cb(repoName)
}

func (c *helmChart) GetChartName() (string, error) {
	if c.Config.Repo != nil && strings.HasPrefix(*c.Config.Repo, "oci://") {
		s := strings.Split(*c.Config.Repo, "/")
		chartName := s[len(s)-1]
		if m, _ := regexp.MatchString(`[a-zA-Z_-]+`, chartName); !m {
			return "", fmt.Errorf("invalid oci chart url: %s", *c.Config.Repo)
		}
		return chartName, nil
	}
	if c.Config.ChartName == nil {
		return "", fmt.Errorf("chartName is missing in helm-chart.yml")
	}
	return *c.Config.ChartName, nil
}

func (c *helmChart) Pull() error {
	chartName, err := c.GetChartName()
	if err != nil {
		return err
	}

	dir := filepath.Dir(c.configFile)
	targetDir := filepath.Join(dir, "charts")
	rmDir := filepath.Join(targetDir, chartName)
	_ = os.RemoveAll(rmDir)

	var args []string
	if c.Config.Repo != nil && strings.HasPrefix(*c.Config.Repo, "oci://") {
		args = []string{"pull", *c.Config.Repo, "--destination", targetDir, "--untar"}
		args = append(args, "--version")
		args = append(args, *c.Config.ChartVersion)
		_, err = c.doHelm(args, false)
		return err
	} else {
		return c.withRepoContext(func(repoName string) error {
			args = []string{"pull", fmt.Sprintf("%s/%s", repoName, chartName), "--destination", targetDir, "--untar"}
			args = append(args, "--version", *c.Config.ChartVersion)
			_, err = c.doHelm(args, false)
			return err
		})
	}
}

func (c *helmChart) CheckUpdate() (string, bool, error) {
	if c.Config.Repo != nil && strings.HasPrefix(*c.Config.Repo, "oci://") {
		return "", false, nil
	}
	chartName, err := c.GetChartName()
	if err != nil {
		return "", false, err
	}
	var latestVersion string
	err = c.withRepoContext(func(repoName string) error {
		chartName := fmt.Sprintf("%s/%s", repoName, chartName)
		args := []string{"search", "repo", chartName, "-oyaml", "-l"}
		stdout, err := c.doHelm(args, false)
		if err != nil {
			return err
		}
		// ensure we didn't get partial matches
		var lm []map[string]string
		var ls versions.LooseVersionSlice
		err = yaml.ReadYamlBytes(stdout, &lm)
		if err != nil {
			return err
		}
		for _, x := range lm {
			if n, ok := x["name"]; ok && n == chartName {
				if v, ok := x["version"]; ok {
					ls = append(ls, versions.LooseVersion(v))
				}
			}
		}
		if len(ls) == 0 {
			return fmt.Errorf("helm chart %s not found in repository", chartName)
		}
		sort.Sort(ls)
		latestVersion = string(ls[len(ls)-1])
		return nil
	})
	if err != nil {
		return "", false, err
	}
	updated := latestVersion != *c.Config.ChartVersion
	return latestVersion, updated, nil
}

func (c *helmChart) Render(k *k8s.K8sCluster) error {
	chartName, err := c.GetChartName()
	if err != nil {
		return err
	}
	dir := filepath.Dir(c.configFile)
	chartDir := filepath.Join(dir, "charts", chartName)
	valuesPath := yaml.FixPathExt(filepath.Join(dir, "helm-values.yml"))
	outputPath := filepath.Join(dir, c.Config.Output)

	args := []string{"template", c.Config.ReleaseName, chartDir}

	namespace := "default"
	if c.Config.Namespace != nil {
		namespace = *c.Config.Namespace
	}

	if utils.Exists(valuesPath) {
		args = append(args, "-f", valuesPath)
	}
	args = append(args, "-n", namespace)

	if c.Config.SkipCRDs != nil && *c.Config.SkipCRDs {
		args = append(args, "--skip-crds")
	} else {
		args = append(args, "--include-crds")
	}
	args = append(args, "--skip-tests")

	gvs, err := k.GetAllGroupVersions()
	if err != nil {
		return err
	}
	for _, gv := range gvs {
		args = append(args, fmt.Sprintf("--api-versions=%s", gv))
	}
	args = append(args, fmt.Sprintf("--kube-version=%s", k.ServerVersion.String()))

	rendered, err := c.doHelm(args, false)
	if err != nil {
		return err
	}

	parsed, err := yaml.ReadYamlAllBytes(rendered)

	for _, o := range parsed {
		m, ok := o.(map[string]interface{})
		if !ok {
			return fmt.Errorf("object is not a map")
		}
		o := uo.FromMap(m)

		// "helm install" will deploy resources to the given namespace automatically, but "helm template" does not
		// add the necessary namespace in the rendered resources
		err = k8s.UnwrapListItems(o, true, func(o *uo.UnstructuredObject) error {
			k.FixNamespace(o, namespace)
			return nil
		})
		if err != nil {
			return err
		}
	}
	rendered, err = yaml.WriteYamlAllBytes(parsed)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(outputPath, rendered, 0o600)
	if err != nil {
		return err
	}
	return nil
}

func (c *helmChart) doHelm(args []string, ignoreStdErr bool) ([]byte, error) {
	cmd := exec.Command("helm", args...)
	cmd.Env = append(os.Environ(), "HELM_EXPERIMENTAL_OCI=true")

	if ignoreStdErr {
		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			return nil, err
		}
		go func() {
			buf := make([]byte, 1024)
			for true {
				n, err := stderrPipe.Read(buf)
				if err != nil || n == 0 {
					return
				}
			}
		}()
	} else {
		cmd.Stderr = os.Stderr
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	defer cmd.Process.Kill()

	stdout, err := ioutil.ReadAll(stdoutPipe)
	if err != nil {
		return nil, err
	}
	ps, err := cmd.Process.Wait()
	if err != nil {
		return nil, err
	}
	if ps.ExitCode() != 0 {
		return nil, fmt.Errorf("helm returned non-zero exit code %d", ps.ExitCode())
	}
	return stdout, nil
}

func (c *helmChart) Save() error {
	return yaml.WriteYamlFile(c.configFile, c.Config)
}
