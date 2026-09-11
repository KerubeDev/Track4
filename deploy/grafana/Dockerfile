FROM grafana/grafana:11.1.0

# Install at image-build time so the runtime does not need to download plugins.
ARG CLICKHOUSE_PLUGIN_VERSION=4.5.1
RUN grafana cli --pluginsDir /var/lib/grafana/plugins \
    plugins install grafana-clickhouse-datasource ${CLICKHOUSE_PLUGIN_VERSION}
