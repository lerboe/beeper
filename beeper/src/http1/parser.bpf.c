#include "vmlinux.h"
#include "beeper/http1.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>

// The parser for HTTP/1.x messages. It is the protocol agnostic DFA parser,
// reporting its results in an `http_parse_res`.

#define PARSE_RES http_parse_res
#define MATCH http_match
#define MATCH_EXTRA .in_msg = true,

#include "../dfa/parser.bpf.h"
