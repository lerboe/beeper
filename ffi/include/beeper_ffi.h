#ifndef BEEPER_FFI_H
#define BEEPER_FFI_H

#include <stdbool.h>
#include <stdint.h>

typedef struct beeper_http1_parser beeper_http1_parser;
typedef struct beeper_http1_attached beeper_http1_attached;
typedef struct beeper_http2_parser beeper_http2_parser;
typedef struct beeper_http2_attached beeper_http2_attached;

/* The buffer type of the stub function in the target program. */
typedef enum {
    BEEPER_MSG_BUF_SKB = 0,
    BEEPER_MSG_BUF_MSG = 1,
    BEEPER_MSG_BUF_DYNPTR = 2,
} beeper_msg_buf;

typedef struct {
    uint32_t count;
    uint32_t size;
    uint32_t max_size;
    uint32_t deleted;
    uint32_t dirty;
} beeper_dynamic_table_info;

/*
 * Every function that returns `char *` returns NULL on success, and an error
 * message otherwise. Free the error message with beeper_free_error.
 *
 * Header names include pseudo headers such as ":path" or ":status".
 * Addresses are IPv4 "ip:port" strings, e.g. "127.0.0.1:8080".
 */
void beeper_free_error(char *err);

beeper_http1_parser *beeper_http1_new(void);
void beeper_http1_free(beeper_http1_parser *p);
char *beeper_http1_parse_fn(beeper_http1_parser *p, const char *name, beeper_msg_buf buf);
char *beeper_http1_matched_fn(beeper_http1_parser *p, const char *name);
char *beeper_http1_get_fn(beeper_http1_parser *p, const char *name, beeper_msg_buf buf);
char *beeper_http1_capture_hdr(beeper_http1_parser *p, const char *name, uint8_t *mid);
char *beeper_http1_match_http2_preface(beeper_http1_parser *p, uint8_t *mid);
/* Always frees `p`, also on error. Free `*attached` with beeper_http1_detach. */
char *beeper_http1_attach(beeper_http1_parser *p, int32_t prog_fd, beeper_http1_attached **attached);
void beeper_http1_detach(beeper_http1_attached *p);

beeper_http2_parser *beeper_http2_new(void);
void beeper_http2_free(beeper_http2_parser *p);
char *beeper_http2_parse_fn(beeper_http2_parser *p, const char *name, beeper_msg_buf buf);
char *beeper_http2_matched_fn(beeper_http2_parser *p, const char *name);
char *beeper_http2_get_fn(beeper_http2_parser *p, const char *name, beeper_msg_buf buf);
char *beeper_http2_get_dynamic_table_entry_fn(beeper_http2_parser *p, const char *name);
char *beeper_http2_capture_hdr(beeper_http2_parser *p, const char *name, uint8_t *mid);
/* Always frees `p`, also on error. Free `*attached` with beeper_http2_detach. */
char *beeper_http2_attach(beeper_http2_parser *p, int32_t prog_fd, beeper_http2_attached **attached);
void beeper_http2_detach(beeper_http2_attached *p);
/* Sets `*found` to false if the parser has no dynamic table for the connection. */
char *beeper_http2_dynamic_table_info(const beeper_http2_attached *p, const char *local,
                                      const char *remote, beeper_dynamic_table_info *info,
                                      bool *found);
char *beeper_http2_forget_conn(const beeper_http2_attached *p, const char *local, const char *remote);

#endif
