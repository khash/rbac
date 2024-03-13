package rbac

import "strings"

type Resource struct {
	Id string `json:"id"`
}

func NewResource(id string) *Resource {
	if strings.Contains(id, ":") || id == "" {
		panic("invalid id. Id cannot be empty or contain ':'")
	}

	return &Resource{
		Id: id,
	}
}

func (r *Resource) String() string {
	return r.Id
}
