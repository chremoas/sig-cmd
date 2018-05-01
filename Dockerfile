FROM scratch
MAINTAINER Brian Hechinger <wonko@4amlunch.net>
ADD sig-cmd sig-cmd
ENV PORT 80
EXPOSE 80
ENTRYPOINT ["/sig-cmd"]