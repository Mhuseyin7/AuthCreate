FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json ./
RUN npm install --ignore-scripts
COPY web ./
RUN npm run build

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /authcrate .
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /authcrate /authcrate
EXPOSE 8080
ENTRYPOINT ["/authcrate","serve"]
