// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	pb "github.com/casbin/casbin-server/proto"
	"github.com/casbin/casbin/v2/util"
	"github.com/stretchr/testify/assert"
)

// sort2D returns a copy of the policy sorted rule-by-rule, so comparisons do
// not depend on the enforcer's internal rule ordering.
func sort2D(policy [][]string) [][]string {
	res := make([][]string, len(policy))
	copy(res, policy)
	sort.Slice(res, func(i, j int) bool {
		return strings.Join(res[i], "\x00") < strings.Join(res[j], "\x00")
	})
	return res
}

func testGetRolesInDomain(t *testing.T, e *testEngine, name string, res []string, domain ...string) {
	t.Helper()
	reply, err := e.s.GetRolesForUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: name, Domain: domain})
	assert.NoError(t, err)

	t.Log("Roles for ", name, " in ", domain, ": ", reply.Array)

	if !util.SetEquals(res, reply.Array) {
		t.Error("Roles for ", name, " in ", domain, ": ", reply.Array, ", supposed to be ", res)
	}
}

func testGetPermissionsInDomain(t *testing.T, e *testEngine, name string, res [][]string, domain ...string) {
	t.Helper()
	reply, err := e.s.GetPermissionsForUser(e.ctx, &pb.PermissionRequest{EnforcerHandler: e.h, User: name, Domain: domain})
	assert.NoError(t, err)

	myRes := extractFromArray2DReply(reply)
	t.Log("Permissions for ", name, " in ", domain, ": ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Permissions for ", name, " in ", domain, ": ", myRes, ", supposed to be ", res)
	}
}

func testGetImplicitPermissionsInDomain(t *testing.T, e *testEngine, name string, res [][]string, domain ...string) {
	t.Helper()
	reply, err := e.s.GetImplicitPermissionsForUser(e.ctx, &pb.PermissionRequest{EnforcerHandler: e.h, User: name, Domain: domain})
	assert.NoError(t, err)

	myRes := extractFromArray2DReply(reply)
	t.Log("Implicit permissions for ", name, " in ", domain, ": ", myRes)

	if !util.Array2DEquals(sort2D(res), sort2D(myRes)) {
		t.Error("Implicit permissions for ", name, " in ", domain, ": ", myRes, ", supposed to be ", res)
	}
}

// TestManagementRoleForUser covers the role-assignment convenience APIs:
// idempotent re-add, deletion of a non-existent relation and empty users.
func TestManagementRoleForUser(t *testing.T) {
	e := newTestEngine(t, "file", "testdata/policy.csv", "testdata/model.conf")

	// Adding a new role assignment reports affected=true.
	reply, err := e.s.AddRoleForUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: "alice", Role: "data1_admin"})
	assert.NoError(t, err)
	assert.True(t, reply.Res, "first AddRoleForUser should report the rule as added")

	// Re-adding the same assignment is idempotent: no error, affected=false.
	reply, err = e.s.AddRoleForUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: "alice", Role: "data1_admin"})
	assert.NoError(t, err)
	assert.False(t, reply.Res, "duplicate AddRoleForUser should report not affected")

	testHasRole(t, e, "alice", "data1_admin", true)
	testGetRoles(t, e, "alice", []string{"data1_admin", "data2_admin"})

	// Deleting an existing relation reports affected=true.
	delReply, err := e.s.DeleteRoleForUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: "alice", Role: "data1_admin"})
	assert.NoError(t, err)
	assert.True(t, delReply.Res)

	// Deleting a relation that no longer exists reports affected=false, no error.
	delReply, err = e.s.DeleteRoleForUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: "alice", Role: "data1_admin"})
	assert.NoError(t, err)
	assert.False(t, delReply.Res, "deleting a non-existent relation should report not affected")

	// Deleting a relation for a user that has none at all.
	delReply, err = e.s.DeleteRoleForUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: "nobody", Role: "data1_admin"})
	assert.NoError(t, err)
	assert.False(t, delReply.Res)

	// Empty user queries return empty results instead of errors or panics.
	testGetRoles(t, e, "", []string{})
	testGetUsers(t, e, "", []string{})
	testHasRole(t, e, "", "data1_admin", false)

	// Destructive filtered deletes reject an empty user instead of wiping
	// the whole policy (empty field values are wildcards in casbin filters).
	_, err = e.s.DeleteRolesForUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: ""})
	assert.Error(t, err)
	_, err = e.s.DeleteUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: ""})
	assert.Error(t, err)
	// The grouping policy is untouched by the rejected deletes.
	testGetGroupingPolicy(t, e, [][]string{
		{"alice", "data2_admin"},
		{"george", "data3_admin"},
		{"data3_admin", "data4_admin"}})
}

// TestManagementPermissionsForUser covers direct vs. implicit permission
// queries and the permission mutation APIs, including empty users.
func TestManagementPermissionsForUser(t *testing.T) {
	e := newTestEngine(t, "file", "testdata/policy.csv", "testdata/model.conf")

	// GetPermissionsForUser returns direct permissions only.
	testGetPermissions(t, e, "alice", [][]string{{"alice", "data1", "read"}})
	// Inherited permissions show up via GetImplicitPermissionsForUser.
	testGetImplicitPermissions(t, e, "alice", [][]string{
		{"alice", "data1", "read"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"}})

	// Empty and unknown users have no permissions, without error.
	testGetPermissions(t, e, "", [][]string{})
	testGetPermissions(t, e, "nobody", [][]string{})
	testGetImplicitPermissions(t, e, "", [][]string{})

	// Add a permission, then re-add it idempotently.
	addReply, err := e.s.AddPermissionForUser(e.ctx, &pb.PermissionRequest{EnforcerHandler: e.h, User: "eve", Permissions: []string{"data3", "read"}})
	assert.NoError(t, err)
	assert.True(t, addReply.Res)

	addReply, err = e.s.AddPermissionForUser(e.ctx, &pb.PermissionRequest{EnforcerHandler: e.h, User: "eve", Permissions: []string{"data3", "read"}})
	assert.NoError(t, err)
	assert.False(t, addReply.Res, "duplicate AddPermissionForUser should report not affected")

	testHasPermission(t, e, "eve", []string{"data3", "read"}, true)
	testGetPermissions(t, e, "eve", [][]string{{"eve", "data3", "read"}})

	// Delete it, then delete the now-missing permission again.
	delReply, err := e.s.DeletePermissionForUser(e.ctx, &pb.PermissionRequest{EnforcerHandler: e.h, User: "eve", Permissions: []string{"data3", "read"}})
	assert.NoError(t, err)
	assert.True(t, delReply.Res)

	delReply, err = e.s.DeletePermissionForUser(e.ctx, &pb.PermissionRequest{EnforcerHandler: e.h, User: "eve", Permissions: []string{"data3", "read"}})
	assert.NoError(t, err)
	assert.False(t, delReply.Res, "deleting a non-existent permission should report not affected")

	testHasPermission(t, e, "eve", []string{"data3", "read"}, false)

	// DeletePermissionsForUser with an empty user is rejected, not treated
	// as "delete everything".
	_, err = e.s.DeletePermissionsForUser(e.ctx, &pb.PermissionRequest{EnforcerHandler: e.h, User: ""})
	assert.Error(t, err)
	testGetPermissions(t, e, "alice", [][]string{{"alice", "data1", "read"}})
}

// TestManagementDomain covers the domain-scoped overloads against a
// rbac_with_domains model.
func TestManagementDomain(t *testing.T) {
	e := newTestEngine(t, "file", "testdata/domain_policy.csv", "testdata/domain_model.conf")

	testGetRolesInDomain(t, e, "alice", []string{"admin"}, "domain1")
	testGetRolesInDomain(t, e, "alice", []string{}, "domain2")

	// Direct permissions are domain-filtered; alice has her own rule in domain1.
	testGetPermissionsInDomain(t, e, "alice", [][]string{{"alice", "domain1", "data9", "read"}}, "domain1")
	testGetPermissionsInDomain(t, e, "alice", [][]string{}, "domain2")
	// Implicit permissions pick up the admin role's rules within the domain.
	testGetImplicitPermissionsInDomain(t, e, "alice", [][]string{
		{"alice", "domain1", "data9", "read"},
		{"admin", "domain1", "data1", "read"},
		{"admin", "domain1", "data1", "write"}}, "domain1")

	// Assign the admin role to alice in domain2 only.
	addReply, err := e.s.AddRoleForUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: "alice", Role: "admin", Domain: []string{"domain2"}})
	assert.NoError(t, err)
	assert.True(t, addReply.Res)

	// Idempotent re-add within the same domain.
	addReply, err = e.s.AddRoleForUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: "alice", Role: "admin", Domain: []string{"domain2"}})
	assert.NoError(t, err)
	assert.False(t, addReply.Res)

	testGetRolesInDomain(t, e, "alice", []string{"admin"}, "domain2")
	// The domain1 assignment is untouched.
	testGetRolesInDomain(t, e, "alice", []string{"admin"}, "domain1")

	// Deleting in domain2 does not leak into domain1.
	delReply, err := e.s.DeleteRoleForUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: "alice", Role: "admin", Domain: []string{"domain2"}})
	assert.NoError(t, err)
	assert.True(t, delReply.Res)

	testGetRolesInDomain(t, e, "alice", []string{}, "domain2")
	testGetRolesInDomain(t, e, "alice", []string{"admin"}, "domain1")

	// Deleting the same domain-scoped relation again reports not affected.
	delReply, err = e.s.DeleteRoleForUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: "alice", Role: "admin", Domain: []string{"domain2"}})
	assert.NoError(t, err)
	assert.False(t, delReply.Res)
}

// TestManagementEnforcerNotFound ensures unknown handles produce a clear
// error instead of a panic.
func TestManagementEnforcerNotFound(t *testing.T) {
	s := NewServer()
	ctx := context.Background()

	_, err := s.AddRoleForUser(ctx, &pb.UserRoleRequest{EnforcerHandler: 99, User: "alice", Role: "admin"})
	assert.Error(t, err)

	_, err = s.GetPermissionsForUser(ctx, &pb.PermissionRequest{EnforcerHandler: 99, User: "alice"})
	assert.Error(t, err)

	_, err = s.GetRolesForUser(ctx, &pb.UserRoleRequest{EnforcerHandler: 99, User: "alice"})
	assert.Error(t, err)

	_, err = s.DeleteRoleForUser(ctx, &pb.UserRoleRequest{EnforcerHandler: 99, User: "alice", Role: "admin"})
	assert.Error(t, err)
}

// TestManagementPersistenceRoundTrip verifies that mutations made through the
// convenience APIs land on disk via SavePolicy and can be read back by a
// freshly created enforcer over the same file.
func TestManagementPersistenceRoundTrip(t *testing.T) {
	// Work on a temp copy so the shared testdata stays pristine.
	src, err := os.ReadFile("testdata/policy.csv")
	assert.NoError(t, err)
	tmpPolicy := filepath.Join(t.TempDir(), "policy.csv")
	assert.NoError(t, os.WriteFile(tmpPolicy, src, 0o644))

	e := newTestEngine(t, "file", tmpPolicy, "testdata/model.conf")

	addReply, err := e.s.AddRoleForUser(e.ctx, &pb.UserRoleRequest{EnforcerHandler: e.h, User: "carol", Role: "data2_admin"})
	assert.NoError(t, err)
	assert.True(t, addReply.Res)

	permReply, err := e.s.AddPermissionForUser(e.ctx, &pb.PermissionRequest{EnforcerHandler: e.h, User: "carol", Permissions: []string{"data5", "read"}})
	assert.NoError(t, err)
	assert.True(t, permReply.Res)

	_, err = e.s.SavePolicy(e.ctx, &pb.EmptyRequest{Handler: e.h})
	assert.NoError(t, err)

	// A brand-new server/enforcer over the same file sees the changes.
	e2 := newTestEngine(t, "file", tmpPolicy, "testdata/model.conf")
	testGetRoles(t, e2, "carol", []string{"data2_admin"})
	testGetPermissions(t, e2, "carol", [][]string{{"carol", "data5", "read"}})
	testHasPermission(t, e2, "carol", []string{"data5", "read"}, true)
}
