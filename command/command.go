package command

import (
	"bytes"
	"fmt"
	proto "github.com/chremoas/chremoas/proto"
	permsrv "github.com/chremoas/perms-srv/proto"
	rolesrv "github.com/chremoas/role-srv/proto"
	"strings"
	common "github.com/chremoas/services-common/command"
	"golang.org/x/net/context"
	role "github.com/chremoas/services-common/roles"
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
var commandList = map[string]command{
	"list":       {listSigs, "List all SIGs"},
	"add":        {addSigs, "Add SIG"},
	"remove":     {removeSigs, "Delete SIG"},
	"info":       {SigInfo, "Get SIG Info"},
	"notDefined": {notDefined, ""},
}

var clientFactory ClientFactory
var permissions common.Permissions

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
	var response string

	if req.Args[1] == "help" {
		response = help()
	} else {
		f, ok := commandList[req.Args[1]]
		if ok {
			response = f.funcptr(ctx, req)
		} else {
			response = common.SendError(fmt.Sprintf("Not a valid subcommand: %s", req.Args[1]))
		}
	}

	rsp.Result = []byte(response)
	return nil
}

func help() string {
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("Usage: !%s <subcommand> <arguments>\n", cmdName))
	buffer.WriteString("\nSubcommands:\n")

	for cmd := range commandList {
		if commandList[cmd].help != "" {
			buffer.WriteString(fmt.Sprintf("\t%s: %s\n", cmd, commandList[cmd].help))
		}
	}

	return fmt.Sprintf("```%s```", buffer.String())
}

func addSigs(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 7 {
		return common.SendError("Usage: !sig add <name> <role_type> <filterA> <filterB> <sig_description>")
	}

	roleShortName := req.Args[2]
	roleType := req.Args[3]
	filterA := req.Args[4]
	filterB := req.Args[5]
	roleName := strings.Join(req.Args[6:], " ")

	if len(roleName) > 0 && roleName[0] == '"' {
		roleName = roleName[1:]
	}

	if len(roleName) > 0 && roleName[len(roleName)-1] == '"' {
		roleName = roleName[:len(roleName)-1]
	}

	canPerform, err := permissions.CanPerform(ctx, req.Sender, []string{"sig_admins"})
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	roleClient := clientFactory.NewRoleClient()
	_, err = roleClient.AddRole(ctx,
		&rolesrv.Role{
			Sig:       true,
			ShortName: roleShortName,
			Type:      roleType,
			Name:      roleName,
			FilterA:   filterA,
			FilterB:   filterB,
		})

	if err != nil {
		return common.SendFatal(err.Error())
	}

	return common.SendSuccess(fmt.Sprintf("Added: %s\n", roleShortName))
}

func listSigs(ctx context.Context, req *proto.ExecRequest) string {
	return role.ListRoles(ctx, clientFactory.NewRoleClient(), true)
}

func removeSigs(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !sig remove <role_name>")
	}

	canPerform, err := permissions.CanPerform(ctx, req.Sender, []string{"sig_admins"})
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

	canPerform, err := permissions.CanPerform(ctx, req.Sender, []string{"sig_admins"})
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
	permissions = common.Permissions{Client: clientFactory.NewPermsClient()}
	newCommand := Command{name: name, factory: factory}
	return &newCommand
}
