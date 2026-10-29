FROM alpine:3.22.2

RUN apk add --no-cache busybox-extras \
    && addgroup -S web \
    && adduser -S -D -H -G web web \
    && mkdir -p /srv/www \
    && chown -R web:web /srv/www

COPY --chown=web:web index.html /srv/www/index.html

USER web
EXPOSE 8080

CMD ["httpd", "-f", "-p", "8080", "-h", "/srv/www"]
