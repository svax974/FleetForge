FROM alpine:3.21

RUN apk update && apk add pgpool

# Needed for pgpool to launch
RUN mkdir -p /var/run/pgpool

CMD ["/usr/bin/pgpool", "-n"]
