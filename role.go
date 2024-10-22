package rbac

import (
	"fmt"
	"strings"
)

type Role struct {
	Id     string `json:"id"`
	Parent *Role  `json:"parent"`

	permissions map[string]bool
	engine      *Engine
}

func (e *Engine) NewRole(id string) *Role {
	if strings.Contains(id, ":") || id == "" {
		panic("invalid id. Id cannot be empty or contain ':'")
	}

	return &Role{
		Id:          id,
		permissions: make(map[string]bool),
		engine:      e,
	}
}

func (e *Engine) NewRoleWithParent(id string, parent *Role) *Role {
	role := e.NewRole(id)
	role.Parent = parent

	return role
}

func (r *Role) RegisterPermission(resource *Resource, actions ...*Action) error {
	for _, action := range actions {
		err := r.registerPermission(resource, action)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *Role) HasPermission(resource *Resource, action *Action) bool {
	return r.hasPermission(resource, action)
}

func (r *Role) hasPermission(resource *Resource, action *Action) bool {
	aKey := r.key(resource, action)
	// check if the permission exists
	if _, ok := r.permissions[aKey]; ok {
		return true
	}

	// check if the parent has the permission
	if r.Parent != nil {
		return r.Parent.hasPermission(resource, action)
	}

	return false
}

func (r *Role) registerPermission(resource *Resource, action *Action) error {
	aKey := r.key(resource, action)
	// check if the permission already exists
	if _, ok := r.permissions[aKey]; ok {
		return fmt.Errorf("permission %s already exists for %s", aKey, r)
	}

	// add the permission
	r.permissions[aKey] = true

	return nil
}

func (r *Role) String() string {
	return r.Id
}

func (r *Role) key(resource *Resource, action *Action) string {
	return fmt.Sprintf("%s:%s", resource, action)
}
