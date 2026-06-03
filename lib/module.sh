# shellcheck shell=bash
# lib/module.sh — modular hardening: registry + dispatch.
#
# A "module" is a self-contained hardening posture that lives under
# $ONIONARMOR_MODULES_DIR/<name>/ and provides three executable action
# scripts plus docs and tests:
#
#   modules/<name>/apply.sh     # apply the posture (supports --dry-run)
#   modules/<name>/audit.sh     # green/yellow/red status; non-zero if any red
#   modules/<name>/revert.sh    # undo the posture, restoring prior state
#   modules/<name>/README.md    # flags, examples, threat model
#   modules/<name>/tests/bats/  # module-specific bats suite
#
# Registry is a plain DIRECTORY SCAN — no manifest file, no YAML parser. A
# directory is a valid module iff it contains apply.sh, audit.sh and
# revert.sh. The one-line human description is read from the first
# `# MODULE: <text>` comment in apply.sh. (We considered modules/*/manifest.yaml
# but a directory scan needs no parser and can't drift from the real scripts.)

# module_dir <name> -> absolute path of the module directory.
module_dir() {
  printf '%s/%s\n' "$ONIONARMOR_MODULES_DIR" "$1"
}

# module_action_script <name> <action> -> path to apply.sh / audit.sh / revert.sh
module_action_script() {
  printf '%s/%s.sh\n' "$(module_dir "$1")" "$2"
}

# module_is_valid <name>: true if the dir holds all three action scripts.
module_is_valid() {
  local d; d=$(module_dir "$1")
  [ -d "$d" ] || return 1
  [ -f "$d/apply.sh" ] && [ -f "$d/audit.sh" ] && [ -f "$d/revert.sh" ]
}

# module_validate <name>: die with a helpful message unless <name> is valid.
module_validate() {
  local name=$1
  case "$name" in
    "" )            die "module name is required (--module <name>)" ;;
    */*|*..*|*$'\n'* ) die "invalid module name: $name" ;;
  esac
  if ! module_is_valid "$name"; then
    die "unknown module: $name (try: onionarmor list-modules)"
  fi
}

# module_describe <name>: print the first `# MODULE:` line's text from apply.sh,
# or empty if none.
module_describe() {
  local s; s=$(module_action_script "$1" apply)
  [ -f "$s" ] || return 0
  awk -F'# MODULE:[[:space:]]*' '/^# MODULE:/ { print $2; exit }' "$s"
}

# module_list: print one valid module name per line (sorted by the shell glob).
module_list() {
  local d base
  [ -d "$ONIONARMOR_MODULES_DIR" ] || return 0
  for d in "$ONIONARMOR_MODULES_DIR"/*/; do
    [ -d "$d" ] || continue
    base=$(basename "$d")
    module_is_valid "$base" || continue
    printf '%s\n' "$base"
  done
}

# args_have_module <args...>: succeed if the arg list contains --module / --module=.
# Used by main() to route apply/audit/revert to a module instead of the
# role-based sysctl path.
args_have_module() {
  local a
  for a in "$@"; do
    case "$a" in
      --module|--module=*) return 0 ;;
    esac
  done
  return 1
}

# module_extract_name <args...>: echo the value of --module from the arg list
# (supports `--module x` and `--module=x`). Empty if absent.
module_extract_name() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --module)   printf '%s' "${2:-}"; return 0 ;;
      --module=*) printf '%s' "${1#--module=}"; return 0 ;;
    esac
    shift
  done
}

# module_dispatch <action> <args...>: pull --module <name> out of the args,
# validate it, then EXEC the module's <action>.sh with the remaining args.
# exec means the module script's exit status becomes the CLI's exit status —
# critical for `audit` returning non-zero when a check is red.
module_dispatch() {
  local action=$1; shift
  local name; name=$(module_extract_name "$@")
  module_validate "$name"

  # Rebuild the arg list with the --module <name> pair stripped out so the
  # module script only sees its own flags.
  local -a rest=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --module)   shift 2 ;;
      --module=*) shift ;;
      *)          rest+=("$1"); shift ;;
    esac
  done

  local script; script=$(module_action_script "$name" "$action")
  [ -f "$script" ] || die "module $name has no $action action ($script)"

  export ONIONARMOR_PREFIX ONIONARMOR_MODULES_DIR
  # ${rest[@]+...} keeps `set -u` happy when the module takes no extra flags.
  exec bash "$script" ${rest[@]+"${rest[@]}"}
}
