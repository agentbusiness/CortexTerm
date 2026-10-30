# CortexTerm shell integration for zsh. The terminal plugin starts zsh with ZDOTDIR pointing here,
# so this file runs instead of the user's .zshenv. It puts the user's ZDOTDIR back (zsh then reads
# their .zprofile, .zshrc and .zlogin from there as usual), runs their .zshenv, and installs the
# hooks that emit the marks. The user's files are never edited.

if [[ -n ${CORTEXTERM_ZDOTDIR+x} ]]; then
  builtin export ZDOTDIR=$CORTEXTERM_ZDOTDIR
else
  builtin unset ZDOTDIR
fi
builtin unset CORTEXTERM_ZDOTDIR
typeset -g _cortexterm_zsh=${${(%):-%x}:A:h}/cortexterm.zsh

if [[ -f ${ZDOTDIR:-$HOME}/.zshenv && -r ${ZDOTDIR:-$HOME}/.zshenv ]]; then
  builtin source ${ZDOTDIR:-$HOME}/.zshenv
fi

if [[ -o interactive && -n $CORTEXTERM_NONCE && -r $_cortexterm_zsh ]]; then
  builtin source $_cortexterm_zsh
fi
builtin unset _cortexterm_zsh
