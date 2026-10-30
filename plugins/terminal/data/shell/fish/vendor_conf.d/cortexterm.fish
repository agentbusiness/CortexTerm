# CortexTerm shell integration for fish. The terminal plugin puts this folder's parent first in
# XDG_DATA_DIRS, so fish reads this file from vendor_conf.d; it takes the entry out again (programs
# started here see the user's XDG_DATA_DIRS) and installs the hooks that emit the marks (see
# ../../zsh/cortexterm.zsh for the list). The user's files are never edited.

if set -q CORTEXTERM_FISH_DIR
    set -l dirs (string split : -- "$XDG_DATA_DIRS")
    set -l at (contains -i -- $CORTEXTERM_FISH_DIR $dirs)
    and set -e dirs[$at]
    if test (count $dirs) -gt 0
        set -gx XDG_DATA_DIRS (string join : -- $dirs)
    else
        set -e XDG_DATA_DIRS
    end
    set -e CORTEXTERM_FISH_DIR
end
# The plugin turned fish's own marks and terminal queries off for this shell; programs started
# here see the user's fish_features again.
if set -q CORTEXTERM_FISH_FEATURES
    if test -n "$CORTEXTERM_FISH_FEATURES"
        set -gx fish_features $CORTEXTERM_FISH_FEATURES
    else
        set -e fish_features
    end
    set -e CORTEXTERM_FISH_FEATURES
end

status is-interactive; or return
set -q CORTEXTERM_NONCE; or return
set -g __ct_nonce $CORTEXTERM_NONCE
set -e CORTEXTERM_NONCE
set -g __ct_path ""
set -g __ct_funcs ""
set -g __ct_first 1

function __ct_send -a kind value last
    test "$value" = "$last"; and return 1
    printf '\e]6973;%s;%s;%s\a' $kind (printf '%s' "$value" | command base64 | command tr -d '\n') $__ct_nonce
end

function __ct_postexec --on-event fish_postexec
    printf '\e]133;D;%s\a' $status
end

function __ct_prompt --on-event fish_prompt
    if test $__ct_first = 1
        # After config.fish: the window shows each command's output itself, so no pager takes
        # the screen (CORTEXTERM_KEEP_PAGER=1 keeps the user's).
        set -g __ct_first 0
        if test "$CORTEXTERM_KEEP_PAGER" != 1
            set -gx PAGER cat
            set -gx GIT_PAGER cat
        end
    end
    printf '\e]7;file://%s%s\a' $hostname (string replace -a ' ' '%20' -- $PWD)
    set -l path (string join : -- $PATH)
    __ct_send env "$path" "$__ct_path"; and set -g __ct_path "$path"
    set -l funcs (functions -n | string collect)
    __ct_send func "$funcs" "$__ct_funcs"; and set -g __ct_funcs "$funcs"
    printf '\e]133;A\a'
end

function __ct_preexec --on-event fish_preexec
    set -l c (string replace -a '\\' '\\\\' -- $argv[1] | string replace -a ';' '\\x3b' | string replace -a \e '\\x1b' | string replace -a \a '\\x07' | string join '\\x0a')
    printf '\e]633;E;%s;%s\a\e]133;C\a' "$c" $__ct_nonce
end
