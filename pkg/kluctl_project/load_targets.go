package kluctl_project

import (
	"fmt"
	git_url "github.com/kluctl/kluctl/pkg/git/git-url"
	"github.com/kluctl/kluctl/pkg/jinja2"
	"github.com/kluctl/kluctl/pkg/types"
	"github.com/kluctl/kluctl/pkg/utils"
	"github.com/kluctl/kluctl/pkg/utils/uo"
	"github.com/kluctl/kluctl/pkg/yaml"
	log "github.com/sirupsen/logrus"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
)

type dynamicTargetInfo struct {
	baseTarget    *types.Target
	dir           string
	gitProject    *types.GitProject
	ref           *string
	refPattern    *string
	defaultBranch string
}

func (c *KluctlProjectContext) loadTargets() error {
	targetNames := make(map[string]bool)
	c.DynamicTargets = nil

	var targetInfos []*dynamicTargetInfo
	for _, baseTarget := range c.Config.Targets {
		l, err := c.prepareDynamicTargets(baseTarget)
		if err != nil {
			return err
		}
		targetInfos = append(targetInfos, l...)
	}

	err := c.cloneDynamicTargets(targetInfos)
	if err != nil {
		return err
	}

	for _, targetInfo := range targetInfos {
		target, err := c.buildDynamicTarget(targetInfo)
		if err != nil {
			// Only fail if non-dynamic targets fail to load
			if targetInfo.refPattern == nil {
				return err
			}
			log.Warningf("Failed to load dynamic target config for project: %v", err)
			continue
		}

		target, err = c.renderTarget(target)
		if err != nil {
			return err
		}

		if _, ok := targetNames[target.Name]; ok {
			log.Warningf("Duplicate target %s", target.Name)
		} else {
			targetNames[target.Name] = true
			c.DynamicTargets = append(c.DynamicTargets, &types.DynamicTarget{
				Target:         target,
				BaseTargetName: targetInfo.baseTarget.Name,
			})
		}
	}
	return nil
}

func (c *KluctlProjectContext) renderTarget(target *types.Target) (*types.Target, error) {
	// Try rendering the target multiple times, until all values can be rendered successfully. This allows the target
	// to reference itself in complex ways. We'll also try loading the cluster vars in each iteration.

	var errors []error
	curTarget := target
	for i := 0; i < 10; i++ {
		varsCtx := jinja2.NewVarsCtx(c.J2)
		err := varsCtx.UpdateChildFromStruct("target", curTarget)
		if err != nil {
			return nil, err
		}

		cc, err := types.LoadClusterConfig(c.ClustersDir, target.Cluster)
		if err == nil {
			err = varsCtx.UpdateChildFromStruct("cluster", cc.Cluster)
			if err != nil {
				return nil, err
			}
		}

		var newTarget types.Target
		err = c.J2.RenderStruct(&newTarget, curTarget, varsCtx.Vars)
		if err == nil && reflect.DeepEqual(curTarget, &newTarget) {
			return curTarget, nil
		}
		curTarget = &newTarget
	}
	if len(errors) != 0 {
		return nil, errors[0]
	}
	return curTarget, nil
}

func (c *KluctlProjectContext) prepareDynamicTargets(baseTarget *types.Target) ([]*dynamicTargetInfo, error) {
	if baseTarget.TargetConfig != nil && baseTarget.TargetConfig.Project != nil {
		return c.prepareDynamicTargetsExternal(baseTarget)
	} else {
		return c.prepareDynamicTargetsSimple(baseTarget)
	}
}

func (c *KluctlProjectContext) prepareDynamicTargetsSimple(baseTarget *types.Target) ([]*dynamicTargetInfo, error) {
	if baseTarget.TargetConfig != nil {
		if baseTarget.TargetConfig.Ref != nil || baseTarget.TargetConfig.RefPattern != nil {
			return nil, fmt.Errorf("'ref' and/or 'refPattern' are not allowed for non-external dynamic targets")
		}
	}
	dynamicTargets := []*dynamicTargetInfo{
		{
			baseTarget: baseTarget,
			dir:        c.ProjectDir,
		},
	}
	return dynamicTargets, nil
}

func (c *KluctlProjectContext) prepareDynamicTargetsExternal(baseTarget *types.Target) ([]*dynamicTargetInfo, error) {
	mr, ok := c.mirroredRepos[baseTarget.TargetConfig.Project.Url.NormalizedRepoKey()]
	if !ok {
		return nil, fmt.Errorf("repo not found in mirroredRepos, this is unexpected and probably a bug")
	}

	if baseTarget.TargetConfig.Ref != nil && baseTarget.TargetConfig.RefPattern != nil {
		return nil, fmt.Errorf("'refPattern' and 'ref' can't be specified together")
	}

	targetConfigRef := baseTarget.TargetConfig.Ref
	refPattern := baseTarget.TargetConfig.RefPattern

	defaultBranch := mr.DefaultRef()
	if defaultBranch == nil {
		return nil, fmt.Errorf("git project %v seems to have no default branch", baseTarget.TargetConfig.Project.Url.String())
	}

	if baseTarget.TargetConfig.Ref == nil && baseTarget.TargetConfig.RefPattern == nil {
		// use default branch of repo
		targetConfigRef = defaultBranch
	}

	refs := mr.RemoteRefHashesMap()

	if targetConfigRef != nil {
		if _, ok := refs[fmt.Sprintf("refs/heads/%s", *targetConfigRef)]; !ok {
			return nil, fmt.Errorf("git project %s has no ref %s", baseTarget.TargetConfig.Project.Url.String(), *targetConfigRef)
		}
		refPattern = targetConfigRef
	}

	var dynamicTargets []*dynamicTargetInfo
	for ref := range refs {
		m, refShortName, err := c.matchRef(ref, *refPattern)
		if err != nil {
			return nil, err
		}
		if !m {
			continue
		}

		cloneDir, err := c.buildCloneDir(baseTarget.TargetConfig.Project.Url, refShortName)
		if err != nil {
			return nil, err
		}

		dynamicTargets = append(dynamicTargets, &dynamicTargetInfo{
			baseTarget:    baseTarget,
			dir:           cloneDir,
			gitProject:    baseTarget.TargetConfig.Project,
			ref:           &refShortName,
			refPattern:    refPattern,
			defaultBranch: *defaultBranch,
		})
	}
	return dynamicTargets, nil
}

func (c *KluctlProjectContext) matchRef(s string, pattern string) (bool, string, error) {
	if strings.HasPrefix(pattern, "refs/") {
		p, err := regexp.Compile(fmt.Sprintf("^%s$", pattern))
		if err != nil {
			return false, "", err
		}
		return p.MatchString(s), s, nil
	}
	p1, err := regexp.Compile(fmt.Sprintf("^refs/heads/%s$", pattern))
	if err != nil {
		return false, "", err
	}
	p2, err := regexp.Compile(fmt.Sprintf("^refs/tags/%s$", pattern))
	if err != nil {
		return false, "", err
	}
	if p1.MatchString(s) {
		return true, s[len("refs/heads/"):], nil
	} else if p2.MatchString(s) {
		return true, s[len("refs/tags/"):], nil
	} else {
		return false, "", nil
	}
}

func (c *KluctlProjectContext) cloneDynamicTargets(dynamicTargets []*dynamicTargetInfo) error {
	wp := utils.NewDebuggerAwareWorkerPool(8)
	defer wp.StopWait(false)

	// lock all involved repos first
	for _, mr := range c.mirroredRepos {
		err := mr.Lock()
		if err != nil {
			return err
		}
		defer mr.Unlock()
	}

	uniqueClones := make(map[string]interface{})
	var mutex sync.Mutex

	for _, targetInfo_ := range dynamicTargets {
		targetInfo := targetInfo_

		if targetInfo.gitProject == nil {
			continue
		}
		if _, ok := uniqueClones[targetInfo.dir]; ok {
			continue
		}
		uniqueClones[targetInfo.dir] = nil

		wp.Submit(func() error {
			gitProject := *targetInfo.gitProject
			gitProject.Ref = *targetInfo.ref
			ep := types.ExternalProject{Project: &gitProject}

			gi, err := c.cloneGitProject(ep, "", false, false)
			mutex.Lock()
			defer mutex.Unlock()
			if err != nil {
				uniqueClones[targetInfo.dir] = err
			} else {
				uniqueClones[targetInfo.dir] = &gi
			}
			return nil
		})
	}
	err := wp.StopWait(false)
	if err != nil {
		return err
	}

	refsByUrlAndPattern := make(map[string]map[string]map[string]string)
	for _, targetInfo := range dynamicTargets {
		if targetInfo.gitProject == nil {
			continue
		}
		o, ok := uniqueClones[targetInfo.dir]
		if !ok {
			return fmt.Errorf("%s not in uniqueClones. This is probably a bug", targetInfo.dir)
		}
		err, ok := o.(error)
		if ok {
			return err
		}
		info := o.(*gitProjectInfo)
		normalizedUrl := info.url.Normalize().String()
		if _, ok := refsByUrlAndPattern[normalizedUrl]; !ok {
			refsByUrlAndPattern[normalizedUrl] = make(map[string]map[string]string)
		}
		if _, ok := refsByUrlAndPattern[normalizedUrl][*targetInfo.refPattern]; !ok {
			refsByUrlAndPattern[normalizedUrl][*targetInfo.refPattern] = make(map[string]string)
		}
		refsByUrlAndPattern[normalizedUrl][*targetInfo.refPattern][info.ref] = info.commit
	}

	for url, refPatterns := range refsByUrlAndPattern {
		for refPattern, refs := range refPatterns {
			u, err := git_url.Parse(url)
			if err != nil {
				return err
			}
			c.addInvolvedRepo(*u, refPattern, refs)
		}
	}

	return nil
}

func (c *KluctlProjectContext) buildDynamicTarget(targetInfo *dynamicTargetInfo) (*types.Target, error) {
	var target types.Target
	err := utils.DeepCopy(&target, targetInfo.baseTarget)
	if err != nil {
		return nil, err
	}
	if targetInfo.baseTarget.TargetConfig == nil {
		return &target, nil
	}

	configFile := yaml.FixNameExt(targetInfo.dir, "target-config.yml")
	if targetInfo.baseTarget.TargetConfig.File != nil {
		configFile = *targetInfo.baseTarget.TargetConfig.File
	}
	configPath := filepath.Join(targetInfo.dir, configFile)
	if !utils.IsFile(configPath) {
		return nil, fmt.Errorf("no target config file with name %s found in target", configFile)
	}

	var targetConfig types.TargetConfig
	err = yaml.ReadYamlFile(configPath, &targetConfig)
	if err != nil {
		return nil, err
	}

	// check and merge args
	if targetConfig.Args != nil {
		err = targetConfig.Args.NewIterator().IterateLeafs(func(it *uo.ObjectIterator) error {
			strValue := fmt.Sprintf("%v", it.Value())
			err := c.CheckDynamicArg(&target, it.JsonPath(), strValue)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		target.Args.Merge(targetConfig.Args)
	}
	// We prepend the dynamic images to ensure they get higher priority later
	target.Images = append(targetConfig.Images, target.Images...)

	if targetInfo.ref != nil {
		target.TargetConfig.Ref = targetInfo.ref
	}

	return &target, nil
}
