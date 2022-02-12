package deployment

import (
	"fmt"
	"github.com/codablock/kluctl/pkg/diff"
	"github.com/codablock/kluctl/pkg/k8s"
	"github.com/codablock/kluctl/pkg/types"
	"github.com/codablock/kluctl/pkg/utils"
	"github.com/codablock/kluctl/pkg/validation"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type DeploymentCollection struct {
	project   *DeploymentProject
	images    *Images
	inclusion *utils.Inclusion
	RenderDir string
	forSeal   bool

	deployments   []*deploymentItem
	remoteObjects map[types.ObjectRef]*unstructured.Unstructured

	errors   map[types.DeploymentError]bool
	warnings map[types.DeploymentError]bool
}

func NewDeploymentCollection(project *DeploymentProject, images *Images, inclusion *utils.Inclusion, renderDir string, forSeal bool) (*DeploymentCollection, error) {
	dc := &DeploymentCollection{
		project:       project,
		images:        images,
		inclusion:     inclusion,
		RenderDir:     renderDir,
		forSeal:       forSeal,
		remoteObjects: map[types.ObjectRef]*unstructured.Unstructured{},
		errors:        map[types.DeploymentError]bool{},
		warnings:      map[types.DeploymentError]bool{},
	}

	indexes := make(map[string]int)
	deployments, err := dc.collectDeployments(project, indexes)
	if err != nil {
		return nil, err
	}
	dc.deployments = deployments
	return dc, nil
}

func (c *DeploymentCollection) collectDeployments(project *DeploymentProject, indexes map[string]int) ([]*deploymentItem, error) {
	var ret []*deploymentItem

	for _, diConfig := range project.config.DeploymentItems {
		var dir2 *string
		index := 0
		if diConfig.Path != nil {
			dir := path.Join(project.dir, *diConfig.Path)
			dir, err := filepath.Abs(dir)
			if err != nil {
				return nil, err
			}
			if !strings.HasPrefix(dir, project.getRootProject().dir) {
				return nil, fmt.Errorf("kustomizeDir path is not part of root deployment project: %s", *diConfig.Path)
			}
			if _, ok := indexes[dir]; !ok {
				indexes[dir] = 0
			}
			index, _ = indexes[dir]
			indexes[dir] = index + 1
			dir2 = &dir
		}
		di, err := NewDeploymentItem(project, c, diConfig, dir2, index)
		if err != nil {
			return nil, err
		}
		ret = append(ret, di)
	}

	for i, incConf := range project.config.Includes {
		if incConf.Barrier != nil && *incConf.Barrier {
			tmpDiConfig := &types.DeploymentItemConfig{
				BaseItemConfig: incConf.BaseItemConfig,
			}
			di, err := NewDeploymentItem(project, c, tmpDiConfig, nil, 0)
			if err != nil {
				return nil, err
			}
			ret = append(ret, di)
		}

		if includedProject, ok := project.includes[i]; ok {
			ret2, err := c.collectDeployments(includedProject, indexes)
			if err != nil {
				return nil, err
			}
			ret = append(ret, ret2...)
		}
	}

	return ret, nil
}

func (c *DeploymentCollection) renderDeployments(k *k8s.K8sCluster) error {
	log.Infof("Rendering templates and Helm charts")

	wp := utils.NewDebuggerAwareWorkerPool(16)
	defer wp.StopWait(false)

	for _, d := range c.deployments {
		err := d.render(k, wp)
		if err != nil {
			return err
		}
	}
	err := wp.StopWait(true)
	if err != nil {
		return err
	}

	for _, d := range c.deployments {
		err := d.renderHelmCharts(k, wp)
		if err != nil {
			return err
		}
	}
	err = wp.StopWait(false)
	if err != nil {
		return err
	}

	return nil
}

func (c *DeploymentCollection) resolveSealedSecrets() error {
	if c.forSeal {
		return nil
	}

	for _, d := range c.deployments {
		err := d.resolveSealedSecrets()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *DeploymentCollection) buildKustomizeObjects(k *k8s.K8sCluster) error {
	log.Infof("Building kustomize objects")

	wp := utils.NewDebuggerAwareWorkerPool(8)
	defer wp.StopWait(false)

	for _, d_ := range c.deployments {
		d := d_
		wp.Submit(func() error {
			err := d.buildKustomize()
			if err != nil {
				return fmt.Errorf("building kustomize objects for %s failed. %w", *d.dir, err)
			}
			err = d.postprocessAndLoadObjects(k)
			if err != nil {
				return fmt.Errorf("postprocessing kustomize objects for %s failed. %w", *d.dir, err)
			}
			return nil
		})
	}
	err := wp.StopWait(false)
	if err != nil {
		return err
	}

	return nil
}

func (c *DeploymentCollection) updateRemoteObjects(k *k8s.K8sCluster) error {
	if k == nil {
		return nil
	}

	notFoundRefsMap := make(map[types.ObjectRef]bool)
	var notFoundRefsList []types.ObjectRef
	for ref := range c.localObjectsByRef() {
		if _, ok := c.remoteObjects[ref]; !ok {
			if _, ok = notFoundRefsMap[ref]; !ok {
				notFoundRefsMap[ref] = true
				notFoundRefsList = append(notFoundRefsList, ref)
			}
		}
	}

	log.Infof("Updating %d remote objects", len(notFoundRefsList))

	r, err := k.GetObjectsByRefs(notFoundRefsList)
	if err != nil {
		return err
	}
	for _, o := range r {
		c.remoteObjects[types.RefFromObject(o)] = o
	}
	return nil
}

func (c *DeploymentCollection) ForgetRemoteObject(ref types.ObjectRef) {
	delete(c.remoteObjects, ref)
}

func (c *DeploymentCollection) localObjectsByRef() map[types.ObjectRef]bool {
	ret := make(map[types.ObjectRef]bool)
	for _, d := range c.deployments {
		for _, o := range d.objects {
			ret[types.RefFromObject(o)] = true
		}
	}
	return ret
}

func (c *DeploymentCollection) localObjectRefs() []types.ObjectRef {
	var ret []types.ObjectRef
	for ref := range c.localObjectsByRef() {
		ret = append(ret, ref)
	}
	return ret
}

func (c *DeploymentCollection) Prepare(k *k8s.K8sCluster) error {
	err := c.renderDeployments(k)
	if err != nil {
		return err
	}
	err = c.resolveSealedSecrets()
	if err != nil {
		return err
	}
	err = c.buildKustomizeObjects(k)
	if err != nil {
		return err
	}
	err = c.updateRemoteObjects(k)
	if err != nil {
		return err
	}
	return nil
}

func (c *DeploymentCollection) Deploy(k *k8s.K8sCluster, forceApply bool, replaceOnError bool, forceReplaceOnError, abortOnError bool, hookTimeout time.Duration) (*types.CommandResult, error) {
	c.clearErrorsAndWarnings()
	o := applyUtilOptions{
		forceApply:          forceApply,
		replaceOnError:      replaceOnError,
		forceReplaceOnError: forceReplaceOnError,
		dryRun:              k.DryRun,
		abortOnError:        abortOnError,
		hookTimeout:         hookTimeout,
	}
	appliedObjects, appliedHookObjects, err := c.doApply(k, o)
	if err != nil {
		return nil, err
	}
	var appliedHookObjectsList []*unstructured.Unstructured
	for _, o := range appliedHookObjects {
		appliedHookObjectsList = append(appliedHookObjectsList, o)
	}
	newObjects, changedObjects, err := c.doDiff(k, appliedObjects, false, false, false)
	if err != nil {
		return nil, err
	}
	orphanObjects, err := c.FindOrphanObjects(k)
	if err != nil {
		return nil, err
	}
	return &types.CommandResult{
		NewObjects:     newObjects,
		ChangedObjects: changedObjects,
		HookObjects:    appliedHookObjectsList,
		OrphanObjects:  orphanObjects,
		Errors:         c.errorsList(),
		Warnings:       c.warningsList(),
	}, nil
}

func (c *DeploymentCollection) Diff(k *k8s.K8sCluster, forceApply bool, replaceOnError bool, forceReplaceOnError bool, ignoreTags bool, ignoreLabels bool, ignoreAnnotations bool) (*types.CommandResult, error) {
	c.clearErrorsAndWarnings()
	o := applyUtilOptions{
		forceApply:          forceApply,
		replaceOnError:      replaceOnError,
		forceReplaceOnError: forceReplaceOnError,
		dryRun:              true,
		abortOnError:        false,
		hookTimeout:         0,
	}
	appliedObjects, appliedHookObjects, err := c.doApply(k, o)
	if err != nil {
		return nil, err
	}
	var appliedHookObjectsList []*unstructured.Unstructured
	for _, o := range appliedHookObjects {
		appliedHookObjectsList = append(appliedHookObjectsList, o)
	}
	newObjects, changedObjects, err := c.doDiff(k, appliedObjects, ignoreTags, ignoreLabels, ignoreAnnotations)
	if err != nil {
		return nil, err
	}
	orphanObjects, err := c.FindOrphanObjects(k)
	if err != nil {
		return nil, err
	}
	return &types.CommandResult{
		NewObjects:     newObjects,
		ChangedObjects: changedObjects,
		HookObjects:    appliedHookObjectsList,
		OrphanObjects:  orphanObjects,
		Errors:         c.errorsList(),
		Warnings:       c.warningsList(),
	}, nil
}

func (c *DeploymentCollection) Validate() *types.ValidateResult {
	c.clearErrorsAndWarnings()

	var result types.ValidateResult

	for e := range c.warnings {
		result.Warnings = append(result.Warnings, e)
	}
	for e := range c.errors {
		result.Errors = append(result.Errors, e)
	}

	for _, d := range c.deployments {
		if !d.checkInclusionForDeploy() {
			continue
		}
		for _, o := range d.objects {
			ref := types.RefFromObject(o)
			remoteObject := c.getRemoteObject(ref)
			if remoteObject == nil {
				result.Errors = append(result.Errors, types.DeploymentError{Ref: ref, Error: "object not found"})
				continue
			}
			r := validation.ValidateObject(o, true)
			result.Errors = append(result.Errors, r.Errors...)
			result.Warnings = append(result.Warnings, r.Warnings...)
			result.Results = append(result.Results, r.Results...)
		}
	}

	return &result
}

func (c *DeploymentCollection) FindDeleteObjects(k *k8s.K8sCluster) ([]types.ObjectRef, error) {
	labels := c.project.getDeleteByLabels()
	return k8s.FindObjectsForDelete(k, labels, c.inclusion, nil)
}

func (c *DeploymentCollection) FindOrphanObjects(k *k8s.K8sCluster) ([]types.ObjectRef, error) {
	log.Infof("Searching for orphan objects")
	labels := c.project.getDeleteByLabels()
	return k8s.FindObjectsForDelete(k, labels, c.inclusion, c.localObjectRefs())
}

func (c *DeploymentCollection) doApply(k *k8s.K8sCluster, o applyUtilOptions) (map[types.ObjectRef]*unstructured.Unstructured, map[types.ObjectRef]*unstructured.Unstructured, error) {
	au := newApplyUtil(c, k, o)
	au.applyDeployments()
	return au.appliedObjects, au.appliedHookObjects, nil
}

func (c *DeploymentCollection) doDiff(k *k8s.K8sCluster, appliedObjects map[types.ObjectRef]*unstructured.Unstructured, ignoreTags bool, ignoreLabels bool, ignoreAnnotations bool) ([]*unstructured.Unstructured, []*types.ChangedObject, error) {
	diffObjects := make(map[types.ObjectRef]*unstructured.Unstructured)
	normalizedDiffObjects := make(map[types.ObjectRef]*unstructured.Unstructured)
	normalizedRemoteObjects := make(map[types.ObjectRef]*unstructured.Unstructured)

	for _, d := range c.deployments {
		if !d.checkInclusionForDeploy() {
			continue
		}

		ignoreForDiffs := d.project.getIgnoreForDiffs(ignoreTags, ignoreLabels, ignoreAnnotations)
		for _, o := range d.objects {
			ref := types.RefFromObject(o)
			if _, ok := appliedObjects[ref]; !ok {
				continue
			}
			diffObjects[ref] = appliedObjects[ref]
			normalizedDiffObjects[ref] = diff.NormalizeObject(k, diffObjects[ref], ignoreForDiffs, diffObjects[ref])
			if r, ok := c.remoteObjects[ref]; ok {
				normalizedRemoteObjects[ref] = diff.NormalizeObject(k, r, ignoreForDiffs, diffObjects[ref])
			}
		}
	}

	wp := utils.NewDebuggerAwareWorkerPool(8)
	defer wp.StopWait(false)

	var newObjects []*unstructured.Unstructured
	var changedObjects []*types.ChangedObject
	var mutex sync.Mutex

	for ref, o_ := range diffObjects {
		o := o_
		normalizedRemoteObject, ok := normalizedRemoteObjects[ref]
		if !ok {
			newObjects = append(newObjects, o)
			continue
		}
		normalizedDiffObject, _ := normalizedDiffObjects[ref]
		remoteObject, _ := c.remoteObjects[ref]
		wp.Submit(func() error {
			changes, err := diff.Diff(normalizedRemoteObject, normalizedDiffObject)
			if err != nil {
				return err
			}
			if len(changes) == 0 {
				return nil
			}
			mutex.Lock()
			defer mutex.Unlock()
			changedObjects = append(changedObjects, &types.ChangedObject{
				NewObject: o,
				OldObject: remoteObject,
				Changes:   changes,
			})
			return nil
		})
	}

	err := wp.StopWait(false)
	if err != nil {
		return nil, nil, err
	}

	return newObjects, changedObjects, nil
}

func (c *DeploymentCollection) addWarnings(ref types.ObjectRef, warnings []error) {
	for _, w := range warnings {
		de := types.DeploymentError{
			Ref:   ref,
			Error: w.Error(),
		}
		c.warnings[de] = true
	}
}

func (c *DeploymentCollection) addError(ref types.ObjectRef, err error) {
	de := types.DeploymentError{
		Ref:   ref,
		Error: err.Error(),
	}
	c.errors[de] = true
}

func (c *DeploymentCollection) errorsList() []types.DeploymentError {
	var l []types.DeploymentError
	for de := range c.errors {
		l = append(l, de)
	}
	return l
}

func (c *DeploymentCollection) warningsList() []types.DeploymentError {
	var l []types.DeploymentError
	for de := range c.warnings {
		l = append(l, de)
	}
	return l
}

func (c *DeploymentCollection) clearErrorsAndWarnings() {
	c.warnings = map[types.DeploymentError]bool{}
	c.errors = map[types.DeploymentError]bool{}
}

func (c *DeploymentCollection) getRemoteObject(ref types.ObjectRef) *unstructured.Unstructured {
	o, _ := c.remoteObjects[ref]
	return o
}