FROM node:20-alpine3.18 AS build-env
COPY package.json /app/package.json
COPY package-lock.json /app/package-lock.json
COPY index.js /app/index.js
WORKDIR /app
RUN npm run build

FROM node:20-alpine3.18
RUN apk add --no-cache curl
COPY --from=build-env /app/dist /app/dist
WORKDIR /app/dist
CMD ["node", "index.js"]
