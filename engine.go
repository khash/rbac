package rbac

type Engine struct {
	roles     map[string]*Role
	actions   map[string]*Action
	resources map[string]*Resource
}

func NewEngine() *Engine {
	e := &Engine{
		roles:     make(map[string]*Role),
		actions:   make(map[string]*Action),
		resources: make(map[string]*Resource),
	}

	return e
}
