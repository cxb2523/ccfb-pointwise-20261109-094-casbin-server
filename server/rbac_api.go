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
	"errors"
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/rbac"
	pb "github.com/casbin/casbin-server/proto"
)

// errEmptyUser is returned by destructive filtered-delete APIs when the
// subject is empty: casbin treats an empty field value as "match anything",
// so an empty user would wipe the whole (grouping) policy instead of nothing.
var errEmptyUser = errors.New("user must not be empty")

// getRoleManager returns the role manager of the default "g" assertion, or a
// descriptive error when the model has no role definition. Accessing the RM
// field of a missing assertion would otherwise panic with a nil dereference.
func getRoleManager(e *casbin.Enforcer) (rbac.RoleManager, error) {
	ast := e.GetModel()["g"]["g"]
	if ast == nil || ast.RM == nil {
		return nil, errors.New("model has no role definition (g) or the role manager is not initialized")
	}

	return ast.RM, nil
}

// applyPolicyChange runs a mutating enforcer call and handles persistence
// failures explicitly. casbin updates the in-memory model around the adapter
// call, so when the adapter reports an error the in-memory state may already
// be dirty. We never swallow that: the error is returned to the caller, and
// we best-effort reload the policy from the adapter to resync memory with
// the store. If the reload also fails, both errors are reported.
func applyPolicyChange(e *casbin.Enforcer, change func() (bool, error)) (bool, error) {
	affected, err := change()
	if err == nil {
		return affected, nil
	}

	if e.GetAdapter() != nil {
		if rerr := e.LoadPolicy(); rerr != nil {
			return false, fmt.Errorf("%w (in-memory policy may be inconsistent: rollback reload failed: %v)", err, rerr)
		}
	}

	return false, err
}

// GetDomains gets the domains that a user has.
func (s *Server) GetDomains(ctx context.Context, in *pb.UserRoleRequest) (*pb.ArrayReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.ArrayReply{}, err
	}

	rm, err := getRoleManager(e)
	if err != nil {
		return &pb.ArrayReply{}, err
	}

	res, _ := rm.GetDomains(in.User)

	return &pb.ArrayReply{Array: res}, nil
}

// GetRolesForUser gets the roles that a user has.
func (s *Server) GetRolesForUser(ctx context.Context, in *pb.UserRoleRequest) (*pb.ArrayReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.ArrayReply{}, err
	}

	rm, err := getRoleManager(e)
	if err != nil {
		return &pb.ArrayReply{}, err
	}

	res, _ := rm.GetRoles(in.User, in.Domain...)

	return &pb.ArrayReply{Array: res}, nil
}

// GetImplicitRolesForUser gets implicit roles that a user has.
func (s *Server) GetImplicitRolesForUser(ctx context.Context, in *pb.UserRoleRequest) (*pb.ArrayReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.ArrayReply{}, err
	}
	res, err := e.GetImplicitRolesForUser(in.User, in.Domain...)
	return &pb.ArrayReply{Array: res}, err
}

// GetUsersForRole gets the users that have a role.
func (s *Server) GetUsersForRole(ctx context.Context, in *pb.UserRoleRequest) (*pb.ArrayReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.ArrayReply{}, err
	}

	rm, err := getRoleManager(e)
	if err != nil {
		return &pb.ArrayReply{}, err
	}

	res, _ := rm.GetUsers(in.Role, in.Domain...)

	return &pb.ArrayReply{Array: res}, nil
}

// HasRoleForUser determines whether a user has a role.
func (s *Server) HasRoleForUser(ctx context.Context, in *pb.UserRoleRequest) (*pb.BoolReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.BoolReply{}, err
	}

	rm, err := getRoleManager(e)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	roles, _ := rm.GetRoles(in.User, in.Domain...)
	for _, r := range roles {
		if r == in.Role {
			return &pb.BoolReply{Res: true}, nil
		}
	}

	return &pb.BoolReply{}, nil
}

// AddRoleForUser adds a role for a user.
// Returns false if the user already has the role (aka not affected).
// If a domain is supplied, the grouping policy is added for that domain.
func (s *Server) AddRoleForUser(ctx context.Context, in *pb.UserRoleRequest) (*pb.BoolReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.BoolReply{}, err
	}

	// AddRoleForUser routes through AddGroupingPolicy, so AutoSave and
	// persistence take the same single path as the raw policy APIs.
	// casbin v2.100 reports affected=true when the rule already exists, so
	// check first to give callers a truthful idempotent answer.
	args := append([]string{in.User, in.Role}, in.Domain...)
	has, err := e.HasGroupingPolicy(args)
	if err != nil {
		return &pb.BoolReply{}, err
	}
	if has {
		return &pb.BoolReply{Res: false}, nil
	}

	ruleAdded, err := applyPolicyChange(e, func() (bool, error) {
		return e.AddGroupingPolicy(args)
	})
	return &pb.BoolReply{Res: ruleAdded}, err
}

// DeleteRoleForUser deletes a role for a user.
// Returns false if the user does not have the role (aka not affected).
func (s *Server) DeleteRoleForUser(ctx context.Context, in *pb.UserRoleRequest) (*pb.BoolReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.BoolReply{}, err
	}

	ruleRemoved, err := applyPolicyChange(e, func() (bool, error) {
		return e.DeleteRoleForUser(in.User, in.Role, in.Domain...)
	})
	return &pb.BoolReply{Res: ruleRemoved}, err
}

// DeleteRolesForUser deletes all roles for a user.
// Returns false if the user does not have any roles (aka not affected).
func (s *Server) DeleteRolesForUser(ctx context.Context, in *pb.UserRoleRequest) (*pb.BoolReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.BoolReply{}, err
	}
	if in.User == "" {
		return &pb.BoolReply{}, errEmptyUser
	}

	ruleRemoved, err := applyPolicyChange(e, func() (bool, error) {
		return e.DeleteRolesForUser(in.User, in.Domain...)
	})
	return &pb.BoolReply{Res: ruleRemoved}, err
}

// DeleteUser deletes a user.
// Returns false if the user does not exist (aka not affected).
// Note: this only removes the user's role assignments (g rules); the user's
// own permissions (p rules) are left to DeletePermissionsForUser.
func (s *Server) DeleteUser(ctx context.Context, in *pb.UserRoleRequest) (*pb.BoolReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.BoolReply{}, err
	}
	if in.User == "" {
		return &pb.BoolReply{}, errEmptyUser
	}

	ruleRemoved, err := applyPolicyChange(e, func() (bool, error) {
		// Domain-scoped variant: g rules are (user, role, domain), so the ""
		// placeholder keeps the role field unconstrained.
		fieldValues := append([]string{in.User}, in.Domain...)
		if len(in.Domain) > 0 {
			fieldValues = append([]string{in.User, ""}, in.Domain...)
		}
		return e.RemoveFilteredGroupingPolicy(0, fieldValues...)
	})
	return &pb.BoolReply{Res: ruleRemoved}, err
}

// DeleteRole deletes a role.
func (s *Server) DeleteRole(ctx context.Context, in *pb.UserRoleRequest) (*pb.EmptyReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.EmptyReply{}, err
	}

	_, err = applyPolicyChange(e, func() (bool, error) {
		return e.DeleteRole(in.Role)
	})
	return &pb.EmptyReply{}, err
}

// DeletePermission deletes a permission.
// Returns false if the permission does not exist (aka not affected).
func (s *Server) DeletePermission(ctx context.Context, in *pb.PermissionRequest) (*pb.BoolReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.BoolReply{}, err
	}

	ruleRemoved, err := applyPolicyChange(e, func() (bool, error) {
		return e.RemoveFilteredPolicy(1, in.Permissions...)
	})
	return &pb.BoolReply{Res: ruleRemoved}, err
}

// AddPermissionForUser adds a permission for a user or role.
// Returns false if the user or role already has the permission (aka not affected).
func (s *Server) AddPermissionForUser(ctx context.Context, in *pb.PermissionRequest) (*pb.BoolReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.BoolReply{}, err
	}

	// Same duplicate-reporting workaround as AddRoleForUser.
	rule := s.convertPermissions(in.User, in.Domain, in.Permissions...)
	has, err := e.HasPolicy(rule...)
	if err != nil {
		return &pb.BoolReply{}, err
	}
	if has {
		return &pb.BoolReply{Res: false}, nil
	}

	ruleAdded, err := applyPolicyChange(e, func() (bool, error) {
		return e.AddPolicy(rule...)
	})
	return &pb.BoolReply{Res: ruleAdded}, err
}

// DeletePermissionForUser deletes a permission for a user or role.
// Returns false if the user or role does not have the permission (aka not affected).
func (s *Server) DeletePermissionForUser(ctx context.Context, in *pb.PermissionRequest) (*pb.BoolReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.BoolReply{}, err
	}

	ruleRemoved, err := applyPolicyChange(e, func() (bool, error) {
		return e.RemovePolicy(s.convertPermissions(in.User, in.Domain, in.Permissions...)...)
	})
	return &pb.BoolReply{Res: ruleRemoved}, err
}

// DeletePermissionsForUser deletes permissions for a user or role.
// Returns false if the user or role does not have any permissions (aka not affected).
func (s *Server) DeletePermissionsForUser(ctx context.Context, in *pb.PermissionRequest) (*pb.BoolReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.BoolReply{}, err
	}
	if in.User == "" {
		return &pb.BoolReply{}, errEmptyUser
	}

	ruleRemoved, err := applyPolicyChange(e, func() (bool, error) {
		return e.RemoveFilteredPolicy(0, append([]string{in.User}, in.Domain...)...)
	})
	return &pb.BoolReply{Res: ruleRemoved}, err
}

// GetPermissionsForUser gets permissions for a user or role.
// Only permissions granted directly to the user are returned; permissions
// inherited through the role hierarchy are left to GetImplicitPermissionsForUser.
func (s *Server) GetPermissionsForUser(ctx context.Context, in *pb.PermissionRequest) (*pb.Array2DReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.Array2DReply{}, err
	}
	// An empty user would act as a wildcard in GetFilteredPolicy and return
	// every rule in the policy; an unknown subject owns no permissions.
	if in.User == "" {
		return &pb.Array2DReply{}, nil
	}

	filteredPolicy, err := e.GetPermissionsForUser(in.User, in.Domain...)
	if err != nil {
		return &pb.Array2DReply{}, err
	}

	return s.wrapPlainPolicy(filteredPolicy), nil
}

// GetImplicitPermissionsForUser gets all permissions(including children) for a user or role.
func (s *Server) GetImplicitPermissionsForUser(ctx context.Context, in *pb.PermissionRequest) (*pb.Array2DReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.Array2DReply{}, err
	}
	resp, err := e.GetImplicitPermissionsForUser(in.User, in.Domain...)
	return s.wrapPlainPolicy(resp), err
}

// HasPermissionForUser determines whether a user has a permission.
func (s *Server) HasPermissionForUser(ctx context.Context, in *pb.PermissionRequest) (*pb.BoolReply, error) {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return &pb.BoolReply{}, err
	}

	hasPolicy, err := e.HasPolicy(s.convertPermissions(in.User, in.Domain, in.Permissions...)...)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return &pb.BoolReply{Res: hasPolicy}, nil
}

// convertPermissions builds a policy rule of the form
// (user, domain..., permission...). The domain segment stays empty for
// domain-less models, so both model shapes share this one code path.
func (s *Server) convertPermissions(user string, domains []string, permissions ...string) []interface{} {
	params := make([]interface{}, 0, len(domains)+len(permissions)+1)
	params = append(params, user)
	for _, domain := range domains {
		params = append(params, domain)
	}
	for _, perm := range permissions {
		params = append(params, perm)
	}

	return params
}
