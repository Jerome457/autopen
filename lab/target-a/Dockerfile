FROM alpine:3.22.2

RUN apk add --no-cache openssh-server \
    && adduser -D -s /bin/sh autopen-test \
    && mkdir -p /run/sshd

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/autopen-ssh-entrypoint

RUN chmod 0755 /usr/local/bin/autopen-ssh-entrypoint

EXPOSE 22

ENTRYPOINT ["/usr/local/bin/autopen-ssh-entrypoint"]
