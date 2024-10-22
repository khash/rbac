package rbac

import "strings"

type Action struct {
	Id string `json:"id"`
	e  *Engine
}

func (e *Engine) NewAction(id string) *Action {
	if strings.Contains(id, ":") || id == "" {
		panic("invalid id. Id cannot be empty or contain ':'")
	}

	action := &Action{
		Id: id,
		e:  e,
	}

	e.actions[id] = action

	return action
}

func (a *Action) String() string {
	return a.Id
}
