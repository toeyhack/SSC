FROM node:20-alpine
WORKDIR /app
COPY frontend/package.json ./
RUN npm install
COPY frontend /app
CMD ["npm", "run", "dev"]
