#!/bin/bash
# Runs h2spec against the echo server of `utils`, whose requests and responses
# the HTTP/2 parser reads. Each case is run on its own, with the parser set up
# to capture every field the case sends, and passes if
#
# * h2spec passes it, i.e. the parser neither stalls nor corrupts a connection,
# * and the parser captures what was sent, in both directions, failing only on
#   the frames h2spec malforms on purpose.
#
# The latter is checked by the `conformance` binary, see its docs for how it
# is driven.
LOGFILE="/tmp/conformance.log"
H2SPEC_VERSION="v2.6.0"
ADDR="127.0.0.1:8080"

# the eBPF programs are compiled with the level RUST_LOG sets for `bpf`, so
# their errors reach the log
export RUST_LOG="conformance=info,bpf=error"
export NO_COLOR=1

# axum fails this one without the parser too, as it tells HTTP/1.1 from
# HTTP/2 by the preface
KNOWN_FAILURES="http2/3.5/2"

override_h2spec=false

while getopts "F" opt; do
    case $opt in
        F) override_h2spec=true ;;
        *) echo "Usage: $0 [-F]"; exit 1 ;;
    esac
done

if ! [ -e "/tmp/h2spec" ] || $override_h2spec ; then
    curl -sSfL "https://github.com/summerwind/h2spec/releases/download/${H2SPEC_VERSION}/h2spec_linux_amd64.tar.gz" \
        | tar -xz -C /tmp h2spec || exit 1
fi

cargo build --locked -p utils --bin conformance || exit 1
coproc CHECKER { sudo --preserve-env=RUST_LOG,NO_COLOR ./target/debug/conformance "${ADDR}" 2> "${LOGFILE}"; }
CHECKER_PID_SAVED="${CHECKER_PID}"

# reads the next line the checker prints into `line`, and fails if it died
next_line() {
    if ! IFS= read -r -t 60 line <&"${CHECKER[0]}"; then
        echo "the checker died, its logs:"
        cat "${LOGFILE}"
        exit 1
    fi
}

next_line
[[ "${line}" == "listening on ${ADDR}" ]] || { echo "unexpected: ${line}"; cat "${LOGFILE}"; exit 1; }

# h2spec has no machine readable listing, so the case ids, e.g. http2/6.5.3/2,
# are pieced together from the titles: a suite, a section, and a case number
CASES=$(/tmp/h2spec --dryrun | awk '
/^[^ ]/ { suite = /^Generic/ ? "generic" : /^HPACK/ ? "hpack" : "http2"; next }
$1 ~ /^[0-9]+:$/ { print suite "/" sec "/" substr($1, 1, length($1) - 1); next }
$1 ~ /^[0-9.]+$/ { sec = substr($1, 1, length($1) - 1) }')

PROBLEMS=()
for id in ${CASES}; do
    # axum's verdict on a few cases hinges on timing, e.g. whether it answers a
    # request before it reads the frame that makes the request malformed
    for _ in 1 2 3; do
        echo "case ${id}" >&"${CHECKER[1]}"
        next_line
        [[ "${line}" == "ready ${id}" ]] || { PROBLEMS+=("${id}: ${line}"); continue 2; }

        out=$(/tmp/h2spec -h "${ADDR%:*}" -p "${ADDR#*:}" "${id}")
        h2spec_status=$?

        # waits until the parser has seen all of the case's connections
        echo "check ${id}" >&"${CHECKER[1]}"
        report=""
        while next_line; do
            report+="${line}"$'\n'
            [[ "${line}" =~ ^(pass|fail)\  ]] && break
        done

        [ "${h2spec_status}" -eq 0 ] && break
    done

    echo "${line}"

    if [ "${h2spec_status}" -ne 0 ] && ! [[ " ${KNOWN_FAILURES} " == *" ${id} "* ]]; then
        PROBLEMS+=("${id}: h2spec failed"$'\n'"${out}")
    fi
    if [[ "${line}" == fail* ]]; then
        PROBLEMS+=("${id}: the parser failed"$'\n'"${report}")
    fi
done

# the checker exits once its stdin is closed
exec {CHECKER[1]}>&-
wait "${CHECKER_PID_SAVED}"

if [ "${#PROBLEMS[@]}" -eq 0 ]; then
    echo "h2spec passed!"
    exit 0
fi

printf '%s\n' "${PROBLEMS[@]}"
echo "h2spec failed! checker logs:"
cat "${LOGFILE}"
exit 1
