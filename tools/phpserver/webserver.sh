#! /bin/sh

PORT=8081
twistd -n web --path . --port "$PORT"
