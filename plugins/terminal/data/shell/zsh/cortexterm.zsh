# CortexTerm marks for zsh (sourced by our .zshenv in interactive shells).
#   OSC 133;A prompt start, 133;B input start, 133;C command start, 133;D;<exit>;<nonce> command done
#   OSC 7 file://<host><cwd>
#   OSC 633;E;<command line>;<nonce> before C
#   OSC 6973;env|alias|func;<base64>;<nonce> the PATH, aliases and functions, when they change
# The nonce is kept in a shell variable and removed from the environment, so programs started
# here cannot read it to fake a command line.

typeset -g _ct_nonce=$CORTEXTERM_NONCE
builtin unset CORTEXTERM_NONCE
typeset -gi _ct_zle=0
typeset -g _ct_path= _ct_aliases= _ct_funcs=

_ct_b64() { builtin print -rn -- "$1" | command base64 | command tr -d '\n' }

_ct_send() {
  [[ $2 == "$3" ]] && return 1
  builtin printf '\e]6973;%s;%s;%s\a' $1 "$(_ct_b64 "$2")" $_ct_nonce
}

_ct_precmd() {
  local ret=$?
  # Every prompt: a D without a C is ignored by the terminal, and the signed D tells it that an
  # unsigned one comes from a shell inside this one (ssh).
  builtin printf '\e]133;D;%s;%s\a' $ret $_ct_nonce
  # Run after every other precmd hook (prompt themes print and redraw there).
  if [[ ${precmd_functions[-1]} != _ct_precmd ]]; then
    precmd_functions=(${precmd_functions:#_ct_precmd} _ct_precmd)
  fi
  builtin printf '\e]7;file://%s%s\a' $HOST ${${PWD//\%/%25}// /%20}
  _ct_send env "$PATH" "$_ct_path" && _ct_path=$PATH
  local k a= f=${(pj:\n:)${(ok)functions[(I)[^_]*]}}
  for k in ${(ok)aliases}; do a+="$k=${aliases[$k]}"$'\n'; done
  _ct_send alias "$a" "$_ct_aliases" && _ct_aliases=$a
  _ct_send func "$f" "$_ct_funcs" && _ct_funcs=$f
  if (( ! _ct_zle )); then
    # After .zshrc: frameworks that define zle-line-init themselves are kept and chained.
    _ct_zle=1
    # The window shows each command's output itself, so no pager takes the screen
    # (CORTEXTERM_KEEP_PAGER=1 keeps the user's).
    [[ $CORTEXTERM_KEEP_PAGER == 1 ]] || builtin export PAGER=cat GIT_PAGER=cat
    builtin autoload -Uz add-zle-hook-widget && add-zle-hook-widget line-init _ct_line_init
  fi
  builtin printf '\e]133;A\a'
}

_ct_preexec() {
  local c=$1
  c=${c//\\/\\\\}
  c=${c//;/\\x3b}
  c=${c//$'\n'/\\x0a}
  c=${c//$'\a'/\\x07}
  c=${c//$'\e'/\\x1b}
  builtin printf '\e]633;E;%s;%s\a\e]133;C\a' $c $_ct_nonce
}

_ct_line_init() { builtin printf '\e]133;B\a' }

precmd_functions+=(_ct_precmd)
preexec_functions+=(_ct_preexec)
