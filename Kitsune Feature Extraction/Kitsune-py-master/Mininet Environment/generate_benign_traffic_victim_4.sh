#!/bin/bash
while true; do
  ping -c 3 10.0.0.3
  ping -c 3 10.0.0.6
  curl -o /dev/null -w "%{http_code}\n" http://wikipedia.org
  nslookup example.org
  sleep 1
done
