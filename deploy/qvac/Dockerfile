FROM node:24-bookworm-slim

ARG QVAC_CLI_VERSION=0.13.0
RUN npm install --global "@qvac/cli@${QVAC_CLI_VERSION}"

WORKDIR /qvac
COPY qvac.config.json /qvac/qvac.config.json
ENV QVAC_CONFIG_PATH=/qvac/qvac.config.json
EXPOSE 11434
CMD ["qvac", "serve", "openai", "--host", "0.0.0.0", "--port", "11434"]
