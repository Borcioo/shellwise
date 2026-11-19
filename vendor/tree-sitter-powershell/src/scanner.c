// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See the LICENSE file in the project root for full license information.

#include "tree_sitter/parser.h"
#include <wctype.h>

enum TOKEN_TYPE {
    STATEMENT_TERMINATOR,
    BARE_DASHES,
    EXPANDABLE_STRING_TEXT,
    EXPANDABLE_HERE_STRING_TEXT
};

/* --- API --- */

void *tree_sitter_powershell_external_scanner_create();

void tree_sitter_powershell_external_scanner_destroy(void *p);

unsigned tree_sitter_powershell_external_scanner_serialize(void *payload, char *buffer);

void tree_sitter_powershell_external_scanner_deserialize(void *payload, const char *buffer, unsigned length);

bool tree_sitter_powershell_external_scanner_scan(void *payload, TSLexer *lexer, const bool *valid_symbols);

/* --- Internal Functions --- */

static void skip(TSLexer *lexer) { lexer->advance(lexer, true); }

// `gap`: the scan started on whitespace (`scan_bare_dashes` may have skipped it already).
static bool scan_statement_terminator(void *payload, TSLexer *lexer, const bool *valid_symbols, bool gap)
{
    if (valid_symbols[STATEMENT_TERMINATOR]) {
        lexer->result_symbol = STATEMENT_TERMINATOR;
        // This token has no characters -- everything is lookahead to determine its existence
        lexer->mark_end(lexer);

        for (;;) {
            if (lexer->lookahead == 0) return true;
            if (lexer->lookahead == '}') return true;
            if (lexer->lookahead == ';') return true;
            if (lexer->lookahead == ')') return true;
            if (lexer->lookahead == '\n') return true;
            // A CR alone ends a line too (PowerShell reads CR, LF and CRLF alike).
            if (lexer->lookahead == '\r') return true;
            // A backtick line end after a gap continues the line: look past it, so that a blank
            // line after it still ends the statement (`git status `<LF><LF>ri x` is two
            // commands). Glued to a word, it belongs to the word (`git`<LF>`).
            if (lexer->lookahead == '`' && gap) {
                skip(lexer);
                if (lexer->lookahead == '\r') {
                    skip(lexer);
                    if (lexer->lookahead == '\n') skip(lexer);
                    continue;
                }
                if (lexer->lookahead == '\n') {
                    skip(lexer);
                    continue;
                }
                return false;
            }
            if (!iswspace(lexer->lookahead)) return false;
            skip(lexer);
        }
    }

    return false;
}

// A bare `-` or `--` argument: `--` ends option parsing for a native command
// (`git log -- path`, `cargo test -- --nocapture`) and `-` names stdin
// (`tar -xf -`). `--` is also the decrement operator and `-` the unary minus,
// so the lexer cannot tell them apart by length or precedence: the token is
// recognised only when the dashes are followed by whitespace or the end of the
// command.
static bool scan_bare_dashes(void *payload, TSLexer *lexer, const bool *valid_symbols)
{
    if (!valid_symbols[BARE_DASHES]) return false;

    while (lexer->lookahead == ' ' || lexer->lookahead == '\t') skip(lexer);
    if (lexer->lookahead != '-') return false;
    lexer->advance(lexer, false);
    if (lexer->lookahead == '-') lexer->advance(lexer, false);
    lexer->mark_end(lexer);

    switch (lexer->lookahead) {
        case 0:
        case ' ':
        case '\t':
        case '\r':
        case '\n':
        case ';':
        case '|':
        case '&':
        case ')':
        case '}':
            lexer->result_symbol = BARE_DASHES;
            return true;
        default:
            return false;
    }
}

static bool is_double_quote(int32_t c)
{
    return c == '"' || c == 0x201C || c == 0x201D || c == 0x201E;
}

// The text of a double-quoted string (or a here-string line) up to the next `$`, backtick,
// quote (strings) or line end (here-strings). Read here because the internal lexer would take a
// `#` inside the string for the start of a comment, which is longer.
static bool scan_string_text(TSLexer *lexer, bool here)
{
    bool any = false;
    for (;;) {
        int32_t c = lexer->lookahead;
        if (c == 0 || c == '$' || c == '`') break;
        if (here ? (c == '\r' || c == '\n') : is_double_quote(c)) break;
        lexer->advance(lexer, false);
        any = true;
    }
    if (!any) return false;
    lexer->mark_end(lexer);
    lexer->result_symbol = here ? EXPANDABLE_HERE_STRING_TEXT : EXPANDABLE_STRING_TEXT;
    return true;
}

/* --- API Implementation --- */

bool tree_sitter_powershell_external_scanner_scan(void *payload, TSLexer *lexer, const bool *valid_symbols)
{
    // During error recovery every symbol is valid; string text is read only inside a string.
    bool recovering = valid_symbols[STATEMENT_TERMINATOR] && valid_symbols[EXPANDABLE_STRING_TEXT];
    if (!recovering) {
        if (valid_symbols[EXPANDABLE_STRING_TEXT]) return scan_string_text(lexer, false);
        if (valid_symbols[EXPANDABLE_HERE_STRING_TEXT]) return scan_string_text(lexer, true);
    }
    // The statement terminator consumes nothing, so it must be tried last: when
    // both are valid, a `--` has to win over the empty terminator.
    bool gap = iswspace(lexer->lookahead);
    if (scan_bare_dashes(payload, lexer, valid_symbols)) return true;
    return scan_statement_terminator(payload, lexer, valid_symbols, gap);
}

void *tree_sitter_powershell_external_scanner_create()
{
    return NULL;
}

void tree_sitter_powershell_external_scanner_destroy(void *p)
{
}

unsigned tree_sitter_powershell_external_scanner_serialize(void *payload, char *buffer)
{
    return 0;
}

void tree_sitter_powershell_external_scanner_deserialize(void *payload, const char *buffer, unsigned length)
{
}
