package rbac

import (
	"testing"
)

func TestNewRole(t *testing.T) {
	e := NewEngine()
	id := "member"
	role := e.NewRole(id)

	if role.Id != id {
		t.Errorf("Expected role Id to be %s, but got %s", id, role.Id)
	}

	if len(role.permissions) != 0 {
		t.Errorf("Expected role permissions to be empty, but got %v", role.permissions)
	}
}

func TestRoleKey(t *testing.T) {
	e := NewEngine()
	role := e.NewRole("member")
	resource := e.NewResource("door")
	action := e.NewAction("open")

	key := role.key(resource, action)
	expectedKey := "door:open"

	if key != expectedKey {
		t.Errorf("Expected key to be %s, but got %s", expectedKey, key)
	}
}

func TestRegisterPermissionSingle(t *testing.T) {
	e := NewEngine()
	member := e.NewRole("member")
	door := e.NewResource("door")
	open := e.NewAction("open")

	err := member.RegisterPermission(door, open)

	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	ok := member.HasPermission(door, open)
	if !ok {
		t.Errorf("Expected permission to exist, but it doesn't")
	}

	close := e.NewAction("close")
	ok = member.HasPermission(door, close)
	if ok {
		t.Errorf("Expected permission NOT to exist, but it does")
	}
}

func TestRegisterPermissionsInherited(t *testing.T) {
	e := NewEngine()
	member := e.NewRole("member")
	door := e.NewResource("door")
	open := e.NewAction("open")
	err := member.RegisterPermission(door, open)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	owner := e.NewRoleWithParent("owner", member)
	close := e.NewAction("close")
	err = owner.RegisterPermission(door, close)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	// check if the self permissions were added
	ok := owner.HasPermission(door, open)
	if !ok {
		t.Errorf("Expected permission to exist, but it doesn't")
	}

	// check if the parent permissions were added
	ok = member.HasPermission(door, close)
	if ok {
		t.Errorf("Expected permission NOT to exist, but it does")
	}

	// check if the parent permissions were added
	ok = owner.HasPermission(door, open)
	if !ok {
		t.Errorf("Expected permission to exist, but it doesn't")
	}

	// check if the parent permissions were added
	ok = owner.HasPermission(door, close)
	if !ok {
		t.Errorf("Expected permission to exist, but it doesn't")
	}
}

func TestPermissionsWithGrandparent(t *testing.T) {
	e := NewEngine()
	grandparent := e.NewRole("grandparent")
	parent := e.NewRoleWithParent("parent", grandparent)
	child := e.NewRoleWithParent("child", parent)

	door := e.NewResource("door")
	openAct := e.NewAction("open")

	// grandparent has permission to open the door
	err := grandparent.RegisterPermission(door, openAct)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	// child should have permission to open the door
	ok := child.HasPermission(door, openAct)
	if !ok {
		t.Errorf("Expected permission to exist, but it doesn't")
	}

	// parent should have permission to open the door
	ok = parent.HasPermission(door, openAct)
	if !ok {
		t.Errorf("Expected permission to exist, but it doesn't")
	}

	// grandparent should have permission to open the door
	ok = grandparent.HasPermission(door, openAct)
	if !ok {
		t.Errorf("Expected permission to exist, but it doesn't")
	}

	// parent should have permission to close the door
	closeAct := e.NewAction("close")
	err = parent.RegisterPermission(door, closeAct)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	// child should have permission to close the door
	ok = child.HasPermission(door, closeAct)
	if !ok {
		t.Errorf("Expected permission to exist, but it doesn't")
	}

	// parent should have permission to close the door
	ok = parent.HasPermission(door, closeAct)
	if !ok {
		t.Errorf("Expected permission to exist, but it doesn't")
	}

	// grandparent shouldn't have permission to close the door
	ok = grandparent.HasPermission(door, closeAct)
	if ok {
		t.Errorf("Expected permission NOT to exist, but it does")
	}
}

func TestString(t *testing.T) {
	e := NewEngine()
	role := e.NewRole("member")

	if role.String() != "member" {
		t.Errorf("Expected role string to be testRole, but got %s", role.String())
	}
}

func TestReRegisterPermission(t *testing.T) {
	e := NewEngine()
	member := e.NewRole("member")
	door := e.NewResource("door")
	open := e.NewAction("open")
	err := member.RegisterPermission(door, open)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	err = member.RegisterPermission(door, open)
	if err == nil {
		t.Errorf("Expected error, but got nil")
	}
}
