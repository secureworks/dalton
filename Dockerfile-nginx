# spin up nginx with custom conf
FROM nginx:1.13.5
MAINTAINER David Wharton

ARG DALTON_EXTERNAL_PORT

RUN rm /etc/nginx/nginx.conf && rm -rf /etc/nginx/conf.d
COPY nginx-conf/nginx.conf /etc/nginx/nginx.conf
COPY nginx-conf/conf.d /etc/nginx/conf.d

# adjust nginx config so redirects point to external port
RUN sed -i 's/REPLACE_AT_DOCKER_BUILD/'"${DALTON_EXTERNAL_PORT}"'/' /etc/nginx/conf.d/dalton.conf

CMD nginx
