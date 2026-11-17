#!/usr/bin/env bash
# Checks the observer's effective permissions. Run as a user allowed to impersonate.
# can-i checks authorization only: it proves nothing about network isolation or
# application policy.
set -euo pipefail

CONTEXT="${CONTEXT:-kind-kubeness}"
NS="${NS:-lab}"
SA="system:serviceaccount:kubeness:kubeness-observer"
fail=0

check() {
  local expected="$1"; shift
  local got
  got="$(kubectl --context "$CONTEXT" auth can-i "$@" --as="$SA" 2>/dev/null || true)"
  if [[ "$got" == "$expected" ]]; then
    printf 'ok    %-4s %s\n' "$expected" "$*"
  else
    printf 'FAIL  want %s got %s: %s\n' "$expected" "$got" "$*"
    fail=1
  fi
}

check yes get pods -n "$NS"
check yes watch events -n "$NS"
check yes list deployments.apps -n "$NS"
check yes get pods --subresource=log -n "$NS"
check no  get secrets -n "$NS"
check no  create pods --subresource=exec -n "$NS"
check no  patch deployments.apps -n "$NS"
check no  delete pods -n "$NS"
check no  get pods -n kube-system
check no  list nodes

exit "$fail"
