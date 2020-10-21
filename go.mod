module github.com/chremoas/sig-cmd

go 1.14

require (
	github.com/chremoas/chremoas v1.3.0
	github.com/chremoas/perms-srv v1.3.0
	github.com/chremoas/role-srv v1.3.0
	github.com/chremoas/services-common v1.3.1
	github.com/micro/go-micro v1.9.1
	golang.org/x/net v0.0.0-20190724013045-ca1201d0de80
)

replace github.com/chremoas/services-common => /home/wonko/projects/chremoas/services-common
replace github.com/chremoas/sig-cmd => ../sig-cmd
replace github.com/hashicorp/consul => github.com/hashicorp/consul v1.5.1
