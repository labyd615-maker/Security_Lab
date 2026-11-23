#!/bin/bash
cd ~/Labsetup_project/Labsetup
docker-compose -f docker-compose2.yml down
docker-compose -f docker-compose.yml up -d
docker ps --format "{{.ID}}  {{.Names}}"

