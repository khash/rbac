package rbac

import "strings"

type Resource struct {
	Id string `json:"id"`
	e  *Engine
}

func (e *Engine) NewResource(id string) *Resource {
	if strings.Contains(id, ":") || id == "" {
		panic("invalid id. Id cannot be empty or contain ':'")
	}

	resource := &Resource{
		Id: id,
		e:  e,
	}

	e.resources[id] = resource

	return resource
}

func (r *Resource) String() string {
	return r.Id
}
