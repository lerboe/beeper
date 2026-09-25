#!/bin/bash
# Runs h2spec against the example server, whose traffic the parsers read. The
# parsers pass if they neither stall nor corrupt a connection, and fail to parse
# only the frames h2spec malforms on purpose.
LOGFILE="/tmp/h2server.log"
H2SPEC_VERSION="v2.6.0"

# the eBPF programs are compiled with the level RUST_LOG sets for `bpf`, so
# their errors reach the server log
export RUST_LOG="example=info,bpf=error"
export NO_COLOR=1

# axum fails this one without the parsers too, as it tells HTTP/1.1 from
# HTTP/2 by the preface
KNOWN_FAILURES="http2/3.5/2"

# the cases that send a malformed frame on purpose: a field with index 0, and a
# HEADERS frame whose padding is longer than its payload
EXPECTED_ERRORS="hpack/6.1/1 http2/6.2/4"

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

cargo build --locked --bin example || exit 1
exec 3< <(sudo --preserve-env=RUST_LOG,NO_COLOR ./target/debug/example 2>&1)
SERVER_PID=$!

# wait 'til the server is listening, then pipe its logs to a file
sed '/listening on 127.0.0.1:8080/q' <&3 ; cat <&3 > "${LOGFILE}" &

# h2spec has no machine readable listing, so the case ids, e.g. http2/6.5.3/2,
# are pieced together from the titles: a suite, a section, and a case number
CASES=$(/tmp/h2spec --dryrun | awk '
/^[^ ]/ { suite = /^Generic/ ? "generic" : /^HPACK/ ? "hpack" : "http2"; next }
$1 ~ /^[0-9]+:$/ { print suite "/" sec "/" substr($1, 1, length($1) - 1); next }
$1 ~ /^[0-9.]+$/ { sec = substr($1, 1, length($1) - 1) }')

errors() {
    grep -c ' ERROR bpf' "${LOGFILE}"
}

# each case runs on its own, so that an eBPF error is tied to the case it
# occurred in
PROBLEMS=()
for id in ${CASES}; do
    before=$(errors)

    # axum's verdict on a few cases hinges on timing, e.g. whether it answers a
    # request before it reads the frame that makes the request malformed
    for _ in 1 2 3; do
        out=$(/tmp/h2spec -p 8080 "${id}") && break
    done
    if [ $? -ne 0 ] && ! [[ " ${KNOWN_FAILURES} " == *" ${id} "* ]]; then
        PROBLEMS+=("${id}: failed"$'\n'"${out}")
    fi

    # the log is written from a ring buffer
    sleep 0.25
    after=$(errors)

    if [[ " ${EXPECTED_ERRORS} " == *" ${id} "* ]]; then
        [ "${after}" -gt "${before}" ] || PROBLEMS+=("${id}: expected an eBPF error, got none")
    elif [ "${after}" -gt "${before}" ]; then
        PROBLEMS+=("${id}: $((after - before)) eBPF error(s)")
    fi
done

if [ "${#PROBLEMS[@]}" -eq 0 ]; then
    echo "h2spec passed!"
    H2SPEC_STATUS=0
else
    printf '%s\n' "${PROBLEMS[@]}"
    echo "h2spec failed! server logs:"
    cat "${LOGFILE}"
    H2SPEC_STATUS=1
fi
sudo kill "${SERVER_PID}"
exit "${H2SPEC_STATUS}"
