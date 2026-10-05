# drive.zsh: what Tab offers in zsh, without a terminal of our own.
#
#   zsh -f drive.zsh <completion script> <command line> <out file>
#
# zsh completes only inside its line editor, so an interactive `zsh -f` runs
# under zsh/zpty: compinit, the script sourced (it registers itself with
# compdef), then <command line> and a Tab are typed. `compadd` is wrapped so
# every word a completion function finally adds is appended to <out file>
# (calls with -O/-A/-D only collect or filter words, they add nothing, and are
# passed through untouched). The line is then cleared and a marker printed, so
# the read below returns only after the Tab has been fully handled.
zmodload zsh/zpty
script=$1 line=$2 out=$3
: > $out
zpty tab 'TERM=xterm zsh -f -i'
zpty -w tab "PS1='READY''> '"
zpty -w tab "autoload -U compinit && compinit -u -D"
zpty -w tab "compadd () { if [[ \${@[1,(i)(-|--)]} == *-(O|A|D)\\ * ]]; then builtin compadd \"\$@\"; return \$?; fi; local -a __hits; builtin compadd -A __hits \"\$@\"; (( \$#__hits )) && print -rl -- \$__hits >> ${(q)out}; builtin compadd \"\$@\" }"
zpty -w tab "source ${(q)script}; print SOURCED-\$((1+1))"
zpty -r tab x '*SOURCED-2*'
zpty -r tab x '*READY> *'
zpty -w -n tab "$line"$'\t'
zpty -w -n tab $'\C-u'"print TAB''DONE-\$((2+2))"$'\n'
zpty -r tab x '*TABDONE-4*'
zpty -d tab
