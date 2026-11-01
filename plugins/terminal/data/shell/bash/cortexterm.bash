# CortexTerm shell integration for bash 4.4+. The terminal plugin starts `bash --posix` with
# ENV pointing here; in POSIX mode an interactive bash reads only $ENV, so this file turns POSIX
# mode off, reads the startup files bash would have read, then installs the hooks that emit the
# marks (see ../zsh/cortexterm.zsh for the list). The user's files are never edited.

builtin set +o posix
builtin unset ENV

if [[ $CORTEXTERM_BASH_LOGIN == 1 ]]; then
  [[ -r /etc/profile ]] && builtin source /etc/profile
  for _ct_file in ~/.bash_profile ~/.bash_login ~/.profile; do
    if [[ -r $_ct_file ]]; then
      builtin source "$_ct_file"
      break
    fi
  done
  builtin unset _ct_file
else
  [[ -r /etc/bash.bashrc ]] && builtin source /etc/bash.bashrc
  [[ -r ~/.bashrc ]] && builtin source ~/.bashrc
fi
builtin unset CORTEXTERM_BASH_LOGIN

# The window shows each command's output itself, so no pager takes the screen
# (CORTEXTERM_KEEP_PAGER=1 keeps the user's).
if [[ $CORTEXTERM_KEEP_PAGER != 1 && -n $CORTEXTERM_NONCE ]]; then
  builtin export PAGER=cat GIT_PAGER=cat
fi

if [[ $- == *i* && -n $CORTEXTERM_NONCE ]]; then
  _ct_nonce=$CORTEXTERM_NONCE
  builtin unset CORTEXTERM_NONCE
  _ct_path=
  _ct_aliases=
  _ct_funcs=

  _ct_send() {
    [[ $2 == "$3" ]] && return 1
    builtin printf '\e]6973;%s;%s;%s\a' "$1" "$(builtin printf '%s' "$2" | command base64 | command tr -d '\n')" "$_ct_nonce"
  }

  _ct_precmd() {
    local ret=$? k a=
    # Every prompt: a D without a C (an empty line, the first prompt) is ignored by the terminal,
    # and the signed D tells it that an unsigned one comes from a shell inside this one (ssh).
    builtin printf '\e]133;D;%s;%s\a' "$ret" "$_ct_nonce"
    builtin printf '\e]7;file://%s%s\a' "$HOSTNAME" "${PWD// /%20}"
    _ct_send env "$PATH" "$_ct_path" && _ct_path=$PATH
    for k in "${!BASH_ALIASES[@]}"; do a+="$k=${BASH_ALIASES[$k]}"$'\n'; done
    _ct_send alias "$a" "$_ct_aliases" && _ct_aliases=$a
    k=$(builtin compgen -A function)
    _ct_send func "$k" "$_ct_funcs" && _ct_funcs=$k
    builtin printf '\e]133;A\a'
    [[ $PS1 == *'133;B'* ]] || PS1+='\[\e]133;B\a\]'
    return $ret
  }

  # Expanded in PS0 (a subshell, after the line is read and before it runs).
  _ct_preexec() {
    local c
    c=$(HISTTIMEFORMAT= builtin history 1)
    [[ $c =~ ^[[:space:]]*[0-9]+[*]?[[:space:]]+(.*)$ ]] && c=${BASH_REMATCH[1]}
    c=${c//\\/\\\\}
    c=${c//;/\\x3b}
    c=${c//$'\n'/\\x0a}
    c=${c//$'\a'/\\x07}
    c=${c//$'\e'/\\x1b}
    builtin printf '\e]633;E;%s;%s\a\e]133;C\a' "$c" "$_ct_nonce"
  }

  # First in PROMPT_COMMAND, so it sees the command's exit status.
  if [[ $(builtin declare -p PROMPT_COMMAND 2>/dev/null) == "declare -a"* ]]; then
    PROMPT_COMMAND=(_ct_precmd "${PROMPT_COMMAND[@]}")
  else
    PROMPT_COMMAND="_ct_precmd${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
  fi
  PS0+='$(_ct_preexec)'
fi
