package main

import (
	"fmt"
	proto "github.com/chremoas/chremoas/proto"
	discordsrv "github.com/chremoas/discord-gateway/proto"
	permsrv "github.com/chremoas/perms-srv/proto"
	rolesrv "github.com/chremoas/role-srv/proto"
	"github.com/chremoas/services-common/config"
	"github.com/chremoas/sig-cmd/command"
	"github.com/micro/go-micro"
	"github.com/micro/go-micro/client"
)

var Version = "SET ME YOU KNOB"
var service micro.Service
var serviceName = "sig"
var serviceType = "cmd"

func main() {
	service = config.NewService(Version, serviceType, serviceName, initialize)

	if err := service.Run(); err != nil {
		fmt.Println(err)
	}
}

// This function is a callback from the config.NewService function.  Read those docs
func initialize(config *config.Configuration) error {
	clientFactory := clientFactory{
		roleSrv:        config.LookupService("srv", "role"),
		permsSrv:       config.LookupService("srv", "perms"),
		discordGateway: config.LookupService("gateway", "discord"),
		client:         service.Client()}

	proto.RegisterCommandHandler(service.Server(),
		command.NewCommand(
			serviceName,
			serviceType,
			Version,
			&clientFactory,
		),
	)

	return nil
}

type clientFactory struct {
	roleSrv        string
	permsSrv       string
	discordGateway string
	client         client.Client
}

func (c clientFactory) NewPermsClient() permsrv.PermissionsService {
	return permsrv.NewPermissionsService(c.permsSrv, c.client)
}

func (c clientFactory) NewRoleClient() rolesrv.RolesService {
	return rolesrv.NewRolesService(c.roleSrv, c.client)
}

func (c clientFactory) NewDiscordClient() discordsrv.DiscordGatewayService {
	return discordsrv.NewDiscordGatewayService(c.discordGateway, c.client)
}
