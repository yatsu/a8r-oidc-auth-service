FROM node:8.15.1-alpine

COPY . /app/

RUN chown -R node:node /app

USER node

WORKDIR /app

RUN yarn install

ENTRYPOINT ["node", "server.js"]
