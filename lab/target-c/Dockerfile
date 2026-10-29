FROM alpine:3.22.2

RUN apk add --no-cache vsftpd \
    && adduser -D -s /bin/sh autopen-ftp

COPY vsftpd.conf /etc/vsftpd/vsftpd.conf
COPY entrypoint.sh /usr/local/bin/autopen-ftp-entrypoint
COPY --chown=autopen-ftp:autopen-ftp sample.txt /home/autopen-ftp/sample.txt

RUN chmod 0755 /usr/local/bin/autopen-ftp-entrypoint

EXPOSE 21 30000-30009

ENTRYPOINT ["/usr/local/bin/autopen-ftp-entrypoint"]
