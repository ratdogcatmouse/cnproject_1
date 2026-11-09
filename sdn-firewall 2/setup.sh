#!/bin/sh
# One-time setup for Ubuntu 22.04 / 24.04 / newer. Run: ./setup.sh
# Mininet uses the system Python; Ryu runs in a Python 3.10 virtual env (.venv)
# because Ryu does not work on Python 3.12+.
set -e
cd "$(dirname "$0")"
sudo apt update
sudo apt install -y mininet openvswitch-switch iproute2 ethtool python3-pip curl unzip
sudo service openvswitch-switch start || sudo systemctl start openvswitch-switch || true

# uv: small tool that fetches Python 3.10 without touching the system Python
if ! command -v uv >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/uv" ]; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

uv venv --python 3.10 .venv
uv pip install --python .venv/bin/python "setuptools<66" wheel pbr
uv pip install --python .venv/bin/python --no-build-isolation -r requirements.txt

# Ryu 4.34 compatibility fix (its REST/WSGI module is not used by this project)
WSGI=$(.venv/bin/python -c "import site;print(site.getsitepackages()[0])")/ryu/app/wsgi.py
sed -i 's/from eventlet.wsgi import ALREADY_HANDLED/ALREADY_HANDLED = b""/' "$WSGI"

chmod +x run.sh
.venv/bin/python -c "import ryu.cmd.manager" && echo "Setup complete."
