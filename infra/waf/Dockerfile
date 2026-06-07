FROM owasp/modsecurity-crs:nginx

COPY infra/waf/default.conf /etc/nginx/templates/conf.d/default.conf.template

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://127.0.0.1/__waf_health || exit 1
