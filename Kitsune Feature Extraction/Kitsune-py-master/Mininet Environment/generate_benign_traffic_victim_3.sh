#!/bin/bash
while true; do
  ping -c 3 10.0.0.6
  ping -c 3 10.0.0.2
  curl -o /dev/null -w "%{http_code}\n" http://google.com
  nslookup example.com
  sleep 1
done
