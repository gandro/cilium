package lib

import (
	"context"
	"fmt"
	"maps"
)

type Property string

const (
	ContainerInterface Property = "CiliumContainerInterfaceName"
)

type PropertyMap map[Property]any

func GetPropertyChecked[T any](m PropertyMap, key Property) (T, bool) {
	var zero T
	raw, ok := m[key]
	if !ok {
		return zero, false
	}

	value, ok := raw.(T)
	return value, ok
}

func GetProperty[T any](m PropertyMap, key Property) T {
	value, _ := GetPropertyChecked[T](m, key)
	return value
}

type AttachmentProperties struct {
	CNIContext
	PodProperties       PropertyMap
	InterfaceProperties PropertyMap
}

type ContainerInterfaceGetter interface {
	GetContainerInterfaces() []string
}

type PodProperties interface {
	PodProperties(ctx context.Context, cniContext CNIContext) (PropertyMap, error)
}

func CollectPodProperties(ctx context.Context, cniContext CNIContext, podPropertyGetter []PodProperties) (PropertyMap, error) {
	allProperties := make(PropertyMap)
	for _, p := range podPropertyGetter {
		prop, err := p.PodProperties(ctx, cniContext)
		if err != nil {
			return nil, fmt.Errorf("failed to collect pod properties %T: %w", p, err)
		}
		maps.Copy(allProperties, prop)
	}
	return allProperties, nil
}

type ContainerInterfaceProperties interface {
	ContainerInterfaceProperties(ctx context.Context, cniContext CNIContext, podProperties PropertyMap, ifName string) (PropertyMap, error)
}

func CollectContainerInterfaceProperties(ctx context.Context, cniContext CNIContext, podProperties PropertyMap, ifName string, ifPropertyGetter []ContainerInterfaceProperties) (PropertyMap, error) {
	allProperties := make(PropertyMap)
	for _, p := range ifPropertyGetter {
		prop, err := p.ContainerInterfaceProperties(ctx, cniContext, podProperties, ifName)
		if err != nil {
			return nil, fmt.Errorf("failed to collect container interface properties %T: %w", p, err)
		}
		maps.Copy(allProperties, prop)
	}
	return allProperties, nil
}
