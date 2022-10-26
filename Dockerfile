
FROM alpine as intermediate

LABEL stage=intermediate

RUN apk update && \
    apk add --update git

RUN git clone --branch stable https://github.com/nv-pipo/misp-to-sentinel-and-defender-connector.git

FROM python:3.10-alpine
ENV PYTHONUNBUFFERED=1

RUN apk update
RUN apk upgrade

RUN mkdir -p /code/
COPY --from=intermediate /misp-to-sentinel-and-defender-connector/app/src/ /code/misp_to_msgraph/
WORKDIR /code/misp_to_msgraph
RUN pip install httpx
# Copy custom config file
ADD app/src/ /code/misp_to_msgraph/

RUN addgroup -g 1000 sync-user && \
    adduser -u 1000 -D sync-user -G sync-user
ENV USER sync-user
ENV HOME /home/sync-user
WORKDIR /home/sync-user
USER sync-user

ENTRYPOINT python /code/misp_to_msgraph/main.py 2>&1 | grep "Unverified HTTPS request is being made to host" -v | grep "  InsecureRequestWarning" -v
