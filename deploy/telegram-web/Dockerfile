FROM nginx:stable-alpine3.20

# The checked-in public tree is already the production Vite artifact. Keeping
# Node out of this image means the LXC only builds a small nginx image.
RUN rm -f /etc/nginx/conf.d/default.conf \
  && mkdir -p /var/cache/nginx \
  && chown -R nginx:nginx /var/cache/nginx

COPY deploy/telegram-web/nginx.conf /etc/nginx/nginx.conf
COPY public/ /usr/share/nginx/html/

EXPOSE 8080
