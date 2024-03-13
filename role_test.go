package rbac

import (
	"testing"
)

func TestNewRole(t *testing.T) {
	id := "member"
	role := NewRole(id)

	if role.Id != id {
		t.Errorf("Expected role Id to be %s, but got %s", id, role.Id)
	}

	if len(role.permissions) != 0 {
		t.Errorf("Expected role permissions to be empty, but got %v", role.permissions)
	}
}

func TestRoleKey(t *testing.T) {
	role := NewRole("member")
	resource := NewResource("door")
	action := NewAction("open")

	key := role.key(resource, action)
	expectedKey := "door:open"

	if key != expectedKey {
		t.Errorf("Expected key to be %s, but got %s", expectedKey, key)
	}
}

func TestRegisterPermissionSingle(t *testing.T) {
	member := NewRole("member")
	door := NewResource("door")
	open := NewAction("open")

	err := member.RegisterPermission(door, open)

	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	ok := member.HasPermission(door, open)
	if !ok {
		t.Errorf("Expected permission to exist, but it doesn't")
	}

	close := NewAction("close")
	ok = member.HasPermission(door, close)
	if ok {
		t.Errorf("Expected permission NOT to exist, but it does")
	}
}

func TestRegisterPermissionsInherited(t *testing.T) {
	member := NewRole("member")
	door := NewResource("door")
	open := NewAction("open")
	err := member.RegisterPermission(door, open)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	owner := NewRoleWithParent("owner", member)
	close := NewAction("close")
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

func TestString(t *testing.T) {
	role := NewRole("member")

	if role.String() != "member" {
		t.Errorf("Expected role string to be testRole, but got %s", role.String())
	}
}

func TestReRegisterPermission(t *testing.T) {
	member := NewRole("member")
	door := NewResource("door")
	open := NewAction("open")
	err := member.RegisterPermission(door, open)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	err = member.RegisterPermission(door, open)
	if err == nil {
		t.Errorf("Expected error, but got nil")
	}
}
