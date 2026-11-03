#!/bin/sh
# Helper: ./run.sh logger | controller | topo | test
cd "$(dirname "$0")"
RYU=ryu-manager
[ -x .venv/bin/ryu-manager ] && RYU=.venv/bin/ryu-manager
case "$1" in
  logger)     python3 logger/logger_server.py ;;
  controller) $RYU controller/firewall_controller.py ;;
  topo)       sudo python3 topology/topo.py ;;
  test)       sudo python3 tests/run_tests.py ;;
  *) echo "usage: $0 logger|controller|topo|test" ;;
esac
