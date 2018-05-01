FROM scratch
MAINTAINER Brian Hechinger <wonko@4amlunch.net>

ADD sig-cmd-linux-amd64 sig-cmd
VOLUME /etc/chremoas

ENTRYPOINT ["/sig-cmd", "--configuration_file", "/etc/chremoas/chremoas.yaml"]
