#!/bin/bash

# build the docker containers and start them up

cd "${0%/*}"
docker compose build && docker compose up -d
