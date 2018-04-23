package command

import (
	proto "github.com/chremoas/chremoas/proto"
	permsrv "github.com/chremoas/perms-srv/proto"
	rolesrv "github.com/chremoas/role-srv/proto"
	common "github.com/chremoas/services-common/command"
	rclient "github.com/chremoas/role-srv/client"
	"github.com/chremoas/services-common/args"
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
	cmd.Add("info", &args.Command{SigInfo, "Get SIG info"})
	cmd.Add("add", &args.Command{addSigs, "Add SIGs"})
	cmd.Add("remove", &args.Command{removeSigs, "Delete SIGs"})
	err := cmd.Exec(ctx, req, rsp)

	// I don't 100% love this, but it'll do for now. -brian
	if err != nil {
		rsp.Result = []byte(common.SendError(err.Error()))
	}
	return nil
}

func addSigs(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 7 {
		return common.SendError("Usage: !sig add <name> <role_type> <filterA> <filterB> <sig_description>")
	}

	return role.AddRole(ctx,
		req.Sender,
		req.Args[2],                     // shortName
		req.Args[3],                     // roleType
		req.Args[4],                     // filterA
		req.Args[5],                     // filterB
		strings.Join(req.Args[6:], " "), // roleName
		true, // Is this a SIG?
	)
}

func listSigs(ctx context.Context, req *proto.ExecRequest) string {
	return role.ListRoles(ctx, true)
}

func removeSigs(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !sig remove <role_name>")
	}

	return role.RemoveRole(ctx, req.Sender, req.Args[2], true)
}

func SigInfo(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !sig info <role_name>")
	}

	return role.RoleInfo(ctx, req.Sender, req.Args[2], true)
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
