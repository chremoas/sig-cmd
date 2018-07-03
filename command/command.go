package command

import (
	"fmt"
	proto "github.com/chremoas/chremoas/proto"
	discordsrv "github.com/chremoas/discord-gateway/proto"
	permsrv "github.com/chremoas/perms-srv/proto"
	rclient "github.com/chremoas/role-srv/client"
	rolesrv "github.com/chremoas/role-srv/proto"
	"github.com/chremoas/services-common/args"
	common "github.com/chremoas/services-common/command"
	"golang.org/x/net/context"
	"strings"
)

type ClientFactory interface {
	NewPermsClient() permsrv.PermissionsService
	NewRoleClient() rolesrv.RolesService
	NewDiscordClient() discordsrv.DiscordGatewayService
}

var (
	serviceName    string
	serviceType    string
	serviceVersion string
	clientFactory  ClientFactory
	role           rclient.Roles
)

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
	cmd := args.NewArg(serviceName, serviceType, serviceVersion, role.DiscordClient)
	cmd.Add("list", &args.Command{listSigs, "List all SIGs"})
	cmd.Add("create", &args.Command{createSigs, "Add SIGs"})
	cmd.Add("destroy", &args.Command{destroySigs, "Delete SIGs"})
	cmd.Add("add", &args.Command{addSig, "Add user to SIG"})
	cmd.Add("remove", &args.Command{removeSig, "Remove user from SIG"})
	cmd.Add("info", &args.Command{sigInfo, "Get SIG info"})
	cmd.Add("join", &args.Command{joinSig, "Join SIG"})
	cmd.Add("leave", &args.Command{leaveSig, "Leave SIG"})
	cmd.Add("set", &args.Command{setSig, "Set sig key"})
	cmd.Add("list_members", &args.Command{getMembers, "List SIG members"})
	cmd.Add("list_sigs", &args.Command{listUserSigs, "List user SIGs"})
	// TODO: Add a command for the user to get a list of what SIGs they are members of.
	embed, err := cmd.Exec(ctx, req, rsp)

	//I don't 100% love this, but it'll do for now. -brian
	if err != nil {
		rsp.Result = []byte(common.SendError(err.Error()))
	}

	if embed != nil {
		role.SendEmbed(ctx, embed)
	}

	return nil
}

func createSigs(ctx context.Context, req *proto.ExecRequest) string {
	var joinable = false
	if len(req.Args) < 6 {
		return common.SendError("Usage: !sig create <name> <filter> <joinable> <sig_description>")
	}

	canPerform, err := role.Permissions.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	name := req.Args[2]
	filter := fmt.Sprintf("sig_%s", name)

	role.AddFilter(ctx, req.Sender, filter, fmt.Sprintf("Auto-generated filter for %s", name))

	if req.Args[4] == "yes" || req.Args[4] == "true" {
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

	sender := strings.Split(req.Sender, ":")
	return role.ListRoles(ctx, sender[0], all, true)
}

func destroySigs(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !sig destroy <special_interest_group>")
	}

	canPerform, err := role.Permissions.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	name := req.Args[2]
	filter := fmt.Sprintf("sig_%s", name)

	role.RemoveAllMembers(ctx, filter, req.Sender)
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

func addSig(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 4 {
		return common.SendError("Usage: !sig add <user> <special_interest_group>")
	}

	canPerform, err := role.Permissions.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	if !common.IsDiscordUser(req.Args[2]) {
		return common.SendError("Second argument must be a discord user")
	}

	userId := common.ExtractUserId(req.Args[2])
	channelId := strings.Split(req.Sender, ":")[0]

	return role.AddSIG(ctx, fmt.Sprintf("%s:%s", channelId, userId), req.Args[3])
}

func leaveSig(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !sig leave <special_interest_group>")
	}

	return role.LeaveSIG(ctx, req.Sender, req.Args[2])
}

func removeSig(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 4 {
		return common.SendError("Usage: !sig remove <user> <special_interest_group>")
	}

	canPerform, err := role.Permissions.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	fmt.Printf("Checking is DiscordUser: %s\n", req.Args[2])
	if !common.IsDiscordUser(req.Args[2]) {
		return common.SendError("Second argument must be a discord user")
	}

	userId := common.ExtractUserId(req.Args[2])
	channelId := strings.Split(req.Sender, ":")[0]

	return role.RemoveSIG(ctx, fmt.Sprintf("%s:%s", channelId, userId), req.Args[3])
}

func setSig(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 5 {
		return common.SendError("Usage: !sig set <sig_name> <key> <value>")
	}

	canPerform, err := role.Permissions.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	return role.Set(ctx, req.Sender, req.Args[2], req.Args[3], req.Args[4])
}

func getMembers(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !sig list_members <sig_name>")
	}

	return role.GetMembers(ctx, req.Args[2])
}

func listUserSigs(ctx context.Context, request *proto.ExecRequest) string {
	s := strings.Split(request.Sender, ":")
	return role.ListUserRoles(ctx, s[1], true)
}

func NewCommand(name, sType, version string, factory ClientFactory) *Command {
	serviceName = name
	serviceType = sType
	serviceVersion = version
	clientFactory = factory
	role = rclient.Roles{
		RoleClient:    clientFactory.NewRoleClient(),
		PermsClient:   clientFactory.NewPermsClient(),
		DiscordClient: clientFactory.NewDiscordClient(),
		Permissions:   common.NewPermission(clientFactory.NewPermsClient(), []string{"sig_admins"}),
	}

	return &Command{name: name, factory: factory}
}
