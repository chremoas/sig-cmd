package command

import (
	"fmt"
	proto "github.com/chremoas/chremoas/proto"
	permsrv "github.com/chremoas/perms-srv/proto"
	rclient "github.com/chremoas/role-srv/client"
	rolesrv "github.com/chremoas/role-srv/proto"
	"github.com/chremoas/services-common/args"
	common "github.com/chremoas/services-common/command"
	"golang.org/x/net/context"
	"strings"
)

type ClientFactory interface {
	NewPermsClient() permsrv.PermissionsClient
	NewRoleClient() rolesrv.RolesClient
}

var cmdName = "sig"
var clientFactory ClientFactory
var role rclient.Roles

type Command struct {
	//Store anything you need the Help or Exec functions to have access to here
	name    string
	factory ClientFactory
}

func (c *Command) Help(ctx context.Context, req *proto.HelpRequest, rsp *proto.HelpResponse) error {
	rsp.Usage = c.name
	rsp.Description = "Administrate Special Interest Groups"
	return nil
}

func (c *Command) Exec(ctx context.Context, req *proto.ExecRequest, rsp *proto.ExecResponse) error {
	cmd := args.NewArg(cmdName)
	cmd.Add("list", &args.Command{listSigs, "List all SIGs"})
	cmd.Add("create", &args.Command{addSigs, "Add SIGs"})
	cmd.Add("destroy", &args.Command{removeSigs, "Delete SIGs"})
	cmd.Add("info", &args.Command{sigInfo, "Get SIG info"})
	cmd.Add("join", &args.Command{joinSig, "Join SIG"})
	cmd.Add("leave", &args.Command{leaveSig, "Leave SIG"})
	// TODO: Add a command for the user to get a list of what SIGs they are members of.
	err := cmd.Exec(ctx, req, rsp)

	//I don't 100% love this, but it'll do for now. -brian
	if err != nil {
		rsp.Result = []byte(common.SendError(err.Error()))
	}
	return nil
}

func addSigs(ctx context.Context, req *proto.ExecRequest) string {
	var joinable = false
	if len(req.Args) < 6 {
		return common.SendError("Usage: !sig create <name> <filter> joinable <sig_description>")
	}

	name := req.Args[2]
	filter := fmt.Sprintf("sig_%s", name)

	role.AddFilter(ctx, req.Sender, filter, fmt.Sprintf("Auto-generated filter for %s", name))

	if req.Args[4] == "joinable" {
		joinable = true
	}
	return role.AddRole(ctx,
		req.Sender,
		name,                            // shortName
		"discord",                       // roleType
		req.Args[3],                     // filterA
		filter,                          // filterB
		joinable,                        // Is this SIG joinable?
		strings.Join(req.Args[5:], " "), // roleName
		true, // Is this a SIG?
	)
}

func listSigs(ctx context.Context, req *proto.ExecRequest) string {
	var all = false
	if len(req.Args) == 3 {
		if req.Args[2] == "all" {
			all = true
		}
	}

	return role.ListRoles(ctx, all, true)
}

func removeSigs(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !sig destroy <special_interest_group>")
	}

	name := req.Args[2]
	filter := fmt.Sprintf("sig_%s", name)

	role.RemoveAllMembers(ctx, filter)
	role.RemoveFilter(ctx, req.Sender, filter)

	return role.RemoveRole(ctx, req.Sender, req.Args[2], true)
}

func sigInfo(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !sig info <special_interest_group>")
	}

	return role.RoleInfo(ctx, req.Sender, req.Args[2], true)
}

func joinSig(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !sig join <special_interest_group>")
	}

	return role.JoinSIG(ctx, req.Sender, req.Args[2])
}

func leaveSig(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !sig leave <special_interest_group>")
	}

	return role.LeaveSIG(ctx, req.Sender, req.Args[2])
}

func NewCommand(name string, factory ClientFactory) *Command {
	clientFactory = factory
	role = rclient.Roles{
		RoleClient:  clientFactory.NewRoleClient(),
		PermsClient: clientFactory.NewPermsClient(),
		Permissions: common.Permissions{Client: clientFactory.NewPermsClient(), PermissionsList: []string{"sig_admins"}},
	}

	return &Command{name: name, factory: factory}
}
