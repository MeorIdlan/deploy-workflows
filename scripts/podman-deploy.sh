#!/usr/bin/env bash
# Pulls and starts one app under rootless Podman, then waits until it's healthy.
# The Docker path gets this from `docker compose up --wait`. podman-compose has
# no --wait, and its `up` can exit 0 even when a container failed to start, so
# its exit code proves nothing. Success here means: every service in the compose
# file is running, on the expected image tag, and not unhealthy.
#
# Needs APP, APP_DIR and IMAGE_TAG. GHCR_USER and GHCR_TOKEN are optional, and
# WAIT_TIMEOUT defaults to 180 seconds. The workflow sends these as the first
# lines of the script over stdin, so the token never reaches the process list.
set -euo pipefail

: "${APP:?APP is required}"
: "${APP_DIR:?APP_DIR is required}"
: "${IMAGE_TAG:?IMAGE_TAG is required}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-180}"
export IMAGE_TAG

cd "$APP_DIR"

if [ -n "${GHCR_TOKEN:-}" ]; then
  printf '%s\n' "$GHCR_TOKEN" | podman login ghcr.io -u "${GHCR_USER:?GHCR_USER is required}" --password-stdin >/dev/null
  trap 'podman logout ghcr.io >/dev/null 2>&1 || true' EXIT
fi

compose() { podman-compose -p "$APP" -f compose.prod.yml "$@"; }

# Pull each image directly first. `podman-compose pull` exits 0 for a tag that
# doesn't exist, and `up` then removes the running containers before it fails,
# so a bad tag would take the app down. podman pull stops here instead.
# podman-compose depends on python3-yaml, so this is always available.
images=$(python3 - <<'PY'
import os, re, yaml
tag = os.environ["IMAGE_TAG"]
services = yaml.safe_load(open("compose.prod.yml"))["services"]
for image in sorted({s["image"] for s in services.values()}):
    print(re.sub(r"\$\{IMAGE_TAG(:-[^}]*)?\}", tag, image))
PY
)
while IFS= read -r image; do
  podman pull -q "$image" >/dev/null
done <<< "$images"

compose up -d --remove-orphans

expected=$(python3 -c "import yaml; print(len(yaml.safe_load(open('compose.prod.yml'))['services']))")
uses_tag=false
grep -q 'IMAGE_TAG' compose.prod.yml && uses_tag=true

list_containers() {
  podman ps -a --filter "label=io.podman.compose.project=$APP" --format '{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}'
}

# Prints why the stack isn't ready yet, or nothing when it is.
not_ready() {
  local lines count
  lines=$(list_containers)
  count=$(printf '%s' "$lines" | grep -c '' || true)
  if [ "$count" -ne "$expected" ]; then
    echo "$count of $expected containers exist"
    return
  fi
  local name image state status
  while IFS='|' read -r name image state status; do
    case "$state" in
      running) ;;
      *) echo "$name is $state: $status" ;;
    esac
    case "$status" in
      *unhealthy*) echo "$name is unhealthy" ;;
      *starting*) echo "$name is still starting" ;;
    esac
    if $uses_tag; then
      case "$image" in
        *":$IMAGE_TAG") ;;
        *) echo "$name runs $image, not tag $IMAGE_TAG" ;;
      esac
    fi
  done <<< "$lines"
}

deadline=$((SECONDS + WAIT_TIMEOUT))
while :; do
  reason=$(not_ready)
  [ -z "$reason" ] && break
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "Stack not ready after ${WAIT_TIMEOUT}s:" >&2
    printf '%s\n' "$reason" >&2
    list_containers >&2
    exit 1
  fi
  sleep 5
done

echo "$IMAGE_TAG" > .current-tag
echo "$(date -Is) $IMAGE_TAG" >> .deploy-history
podman image prune -af --filter "until=72h" >/dev/null || true
list_containers
