FROM nginx:1.27-alpine

RUN apk add --no-cache openssl

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
COPY start.sh /start.sh

RUN chmod +x /start.sh

EXPOSE 443

ENTRYPOINT ["/start.sh"]
