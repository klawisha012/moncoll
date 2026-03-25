FROM alpine:3.19 AS crs

RUN apk add --no-cache git \
 && git clone -b v3.3.5 https://github.com/coreruleset/coreruleset /crs \
 && cp /crs/crs-setup.conf.example /crs/crs-setup.conf \
 && cp /crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example \
      /crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf \
 && cp /crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example \
      /crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf

FROM docker.angie.software/angie:latest

COPY --from=crs /crs /var/lib/angie/modsecurity/coreruleset
