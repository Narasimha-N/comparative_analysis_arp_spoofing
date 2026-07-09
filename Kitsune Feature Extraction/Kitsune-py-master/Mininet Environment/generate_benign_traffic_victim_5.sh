#!/bin/bash
while true; do
  ping -c 3 10.0.0.4
  ping -c 3 10.0.0.5
  curl -o /dev/null -w "%{http_code}\n" http://example.com
  nslookup google.com
  sleep 1
done
