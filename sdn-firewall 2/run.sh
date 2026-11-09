#!/bin/sh
# Helper: ./run.sh logger | controller | topo [--bw N] | test | bench [--repeat N] | ctl <cmd>
cd "$(dirname "$0")"
RYU=ryu-manager
[ -x .venv/bin/ryu-manager ] && RYU=.venv/bin/ryu-manager
SUDO=sudo
[ "$(id -u)" = 0 ] && SUDO=
cmd=$1; [ $# -gt 0 ] && shift
case "$cmd" in
  logger)     python3 logger/logger_server.py ;;
  controller) PYTHONWARNINGS=ignore $RYU controller/firewall_controller.py ;;
  topo)       $SUDO python3 topology/topo.py "$@" ;;
  test)       $SUDO python3 tests/run_tests.py "$@" ;;
  bench)      $SUDO python3 tests/benchmark.py "$@" ;;
  ctl)        python3 tools/fwctl.py "$@" ;;
  *) echo "usage: $0 logger|controller|topo|test|bench|ctl" ;;
esac
