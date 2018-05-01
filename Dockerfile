FROM scratch
MAINTAINER Brian Hechinger <wonko@4amlunch.net>
ADD sig-cmd-linux-amd64 sig-cmd
ENTRYPOINT ["/sig-cmd"]