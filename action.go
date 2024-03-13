package rbac

import "strings"

type Action struct {
	Id string `json:"id"`
}

func NewAction(id string) *Action {
	if strings.Contains(id, ":") || id == "" {
		panic("invalid id. Id cannot be empty or contain ':'")
	}

	return &Action{
		Id: id,
	}
}

func (a *Action) String() string {
	return a.Id
}
