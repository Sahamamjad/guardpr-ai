FROM node:18
WORKDIR /app
COPY . .
RUN npm init -y && npm install express
USER root
CMD ["node", "server.js"]
