FROM nginx:alpine

RUN apk add --no-cache openssl

COPY docker-entrypoint.d/10-generate-self-signed-cert.sh /docker-entrypoint.d/10-generate-self-signed-cert.sh

RUN chmod +x /docker-entrypoint.d/10-generate-self-signed-cert.sh