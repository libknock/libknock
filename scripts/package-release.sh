#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
mode=both
case "${1:-}" in
  --standard-only) mode=standard; shift ;;
  --with-vendor-only) mode=vendor; shift ;;
  --with-vendor) mode=both; shift ;;
  -h|--help)
    cat <<'EOF'
usage: scripts/package-release.sh [--with-vendor|--standard-only|--with-vendor-only] [version] [out_dir]

Default behavior is --with-vendor: create both libknock-VERSION.zip and
libknock-VERSION-with-vendor.zip. The standard archive excludes vendor/. The
vendored archive runs go work vendor and includes vendor/modules.txt.
EOF
    exit 0
    ;;
esac
version=${1:-$(date -u +%Y%m%dT%H%M%SZ)}
out_dir=${2:-/tmp}
mkdir -p "$out_dir"
out_dir=$(cd "$out_dir" && pwd)
base="libknock-${version}"
standard_out="${out_dir}/${base}.zip"
vendor_out="${out_dir}/${base}-with-vendor.zip"
normalize_archive_tree() {
  local dir=$1
  find "$dir" -type d -exec chmod 755 {} +
  find "$dir" -type f -exec chmod 644 {} +
  find "$dir/scripts" -type f -name '*.sh' -exec chmod 755 {} + 2>/dev/null || true
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if [[ "$mode" == standard || "$mode" == both ]]; then
  mkdir -p "$tmp/$base"
  git archive --format=tar HEAD | tar -C "$tmp/$base" -xf -
  rm -rf "$tmp/$base/vendor"
  normalize_archive_tree "$tmp/$base"
  (cd "$tmp" && zip -qr "$standard_out" "$base")
  sha256sum "$standard_out" > "$standard_out.sha256"
  printf '%s\n' "$standard_out"
  cat "$standard_out.sha256"
  rm -rf "$tmp/$base"
fi

if [[ "$mode" == vendor || "$mode" == both ]]; then
  mkdir -p "$tmp/$base"
  git archive --format=tar HEAD | tar -C "$tmp/$base" -xf -
  (
    cd "$tmp/$base"
    go work vendor
    test -f vendor/modules.txt
    test -f go.work
    test -f go.work.sum
  )
  normalize_archive_tree "$tmp/$base"
  (cd "$tmp" && zip -qr "$vendor_out" "$base")
  sha256sum "$vendor_out" > "$vendor_out.sha256"
  printf '%s\n' "$vendor_out"
  cat "$vendor_out.sha256"
fi
