FROM alpine:3.21

RUN apk add --no-cache nsd bind-tools

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /var/db/nsd && chown nsd:nsd /var/db/nsd

EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/entrypoint.sh"]
