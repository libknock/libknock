#!/usr/bin/env bash
set -euo pipefail

platform_os() {
  case "$(uname -s 2>/dev/null || echo unknown)" in
    Linux*) echo linux ;;
    Darwin*) echo darwin ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT) echo windows ;;
    *) echo unknown ;;
  esac
}

is_linux() { [ "$(platform_os)" = linux ]; }
