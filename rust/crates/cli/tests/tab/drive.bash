# drive.bash: what Tab offers in bash, without a terminal.
#
#   bash --norc --noprofile drive.bash <completion script> <command line>
#
# Sources the script, sets COMP_WORDS/COMP_CWORD/COMP_LINE/COMP_POINT as bash
# does for a Tab at the end of <command line>, calls the function the script
# registered with `complete -F`, and prints COMPREPLY one word per line.
#
# cobra's script asks the bash-completion package for the words
# (_get_comp_words_by_ref); that package is not part of bash, so the shim below
# fills the same four variables from COMP_WORDS, without the package's
# COMP_WORDBREAKS re-splitting (no command line here contains = or :).
source "$1"

_get_comp_words_by_ref() {
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD-1]}
    words=("${COMP_WORDS[@]}")
    cword=$COMP_CWORD
}

line=$2
COMP_LINE=$line
COMP_POINT=${#line}
read -r -a COMP_WORDS <<< "$line"
if [[ $line == *" " ]]; then
    COMP_WORDS+=("")
fi
COMP_CWORD=$((${#COMP_WORDS[@]} - 1))

spec=$(complete -p wapps) || exit 3
fn=${spec##*-F }
fn=${fn%% *}
"$fn" wapps "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
printf '%s\n' "${COMPREPLY[@]}"
