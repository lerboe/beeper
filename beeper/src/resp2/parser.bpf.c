#include "vmlinux.h"
#include "beeper/resp2.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>

// The parser for RESP2 messages. It is the protocol agnostic DFA parser,
// reporting its results in a `resp2_parse_res`.

#define PARSE_RES resp2_parse_res
#define MATCH resp2_match
#define MATCH_EXTRA

#include "../dfa/parser.bpf.h"
