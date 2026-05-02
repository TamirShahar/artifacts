FROM nginx:alpine

RUN apk add --no-cache iproute2 tcpdump

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html

EXPOSE 80

CMD ["sh", "-c", "tc qdisc replace dev eth0 root netem delay 50ms && exec nginx -g 'daemon off;'"]
