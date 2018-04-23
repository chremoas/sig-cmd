package command

import (
	"fmt"
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

type command struct {
	funcptr func(ctx context.Context, request *proto.ExecRequest) string
	help    string
}

var cmdName = "sig"
//var commandList = map[string]command{
//	"list":       {listSigs, "List all SIGs"},
//	"add":        {addSigs, "Add SIG"},
//	"remove":     {removeSigs, "Delete SIG"},
//	"info":       {SigInfo, "Get SIG Info"},
//	"notDefined": {notDefined, ""},
//}

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
	cmd.Add("notDefined", &args.Command{notDefined, ""})
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

	canPerform, err := role.Permissions.CanPerform(ctx, req.Sender, []string{"sig_admins"})
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	roleClient := clientFactory.NewRoleClient()

	// Need to check if it's a sig or not
	_, err = roleClient.RemoveRole(ctx, &rolesrv.Role{ShortName: req.Args[2]})
	if err != nil {
		return common.SendFatal(err.Error())
	}

	return common.SendSuccess(fmt.Sprintf("Removed: %s\n", req.Args[2]))
}

func SigInfo(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !sig info <role_name>")
	}

	canPerform, err := role.Permissions.CanPerform(ctx, req.Sender, []string{"sig_admins"})
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	roleClient := clientFactory.NewRoleClient()

	info, err := roleClient.GetRole(ctx, &rolesrv.Role{ShortName: req.Args[2]})
	if err != nil {
		return common.SendFatal(err.Error())
	}

	return fmt.Sprintf("```ShortName: %s\nType: %s\nFilterA: %s\nFilterB: %s\nName: %s\nColor: %d\nHoist: %t\nPosition: %d\nPermissions: %d\nManaged: %t\nMentionable: %t\nJoinable: %t\n```",
		info.ShortName,
		info.Type,
		info.FilterA,
		info.FilterB,
		info.Name,
		info.Color,
		info.Hoist,
		info.Position,
		info.Permissions,
		info.Managed,
		info.Mentionable,
		info.Joinable,
	)
}

func notDefined(ctx context.Context, req *proto.ExecRequest) string {
	return "This command hasn't been defined yet"
}

func NewCommand(name string, factory ClientFactory) *Command {
	clientFactory = factory
	role = rclient.Roles{
		RoleClient:  clientFactory.NewRoleClient(),
		PermsClient: clientFactory.NewPermsClient(),
		Permissions: common.Permissions{Client: clientFactory.NewPermsClient()},
	}
	newCommand := Command{name: name, factory: factory}
	return &newCommand
}
