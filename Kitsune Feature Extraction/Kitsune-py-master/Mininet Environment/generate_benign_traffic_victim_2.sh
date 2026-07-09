#!/bin/bash
while true; do
  ping -c 3 10.0.0.2
  ping -c 3 10.0.0.5
  curl -o /dev/null -w "%{http_code}\n" http://example.org
  nslookup wikipedia.org
  sleep 1
done
