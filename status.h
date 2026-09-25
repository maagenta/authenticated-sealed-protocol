#ifndef PROTO_STATUS_H
#define PROTO_STATUS_H

/*
 * Status codes returned by the library.
 *
 * Failures are negative; success is PROTO_OK or one of the positive values
 * below, which report an outcome the caller may want to act on. `rc < 0` is
 * therefore the one test that always means failure. `rc != 0` is only safe
 * on functions documented to return nothing but PROTO_OK or an error — it
 * would mistake a positive result for one. Failure values are grouped in
 * hundreds: the hundreds digit is the family, the rest is sequential within
 * it, and a value is never reused. New codes join their family's range, so
 * the documented tables stay ordered as the library grows. Functions
 * returning a pointer still report failure with NULL.
 *
 * proto_strerror() turns any code into a message. The library never prints:
 * where diagnostics go is the application's decision.
 */
typedef enum {
    /* success — the positive values carry something the caller may want to
     * act on, but nothing failed. Only negative values are failures. */
    PROTO_OK                   =    0,
    PROTO_REGISTER_REQUESTED   =    1,  /* handshake ok; server wants our enc pubkey */
    PROTO_KEEPALIVE_DEFAULTED  =    2,  /* probing on; a knob kept the system value */

    /* -1xx: caller mistakes */
    PROTO_E_PARAM              = -101,  /* invalid argument                  */
    PROTO_E_BUFFER_TOO_SMALL   = -102,  /* caller buffer cannot hold result  */
    PROTO_E_NO_ALLOWLIST       = -103,  /* allowed_hex is NULL               */
    PROTO_E_BAD_ALLOWLIST      = -104,  /* allowed_hex not 64 lowercase hex  */
    PROTO_E_NO_HANDLER         = -105,  /* handler is NULL                   */
    PROTO_E_BAD_ADDRESS        = -106,  /* bind_addr is not an IPv4 literal  */
    PROTO_E_BAD_PORT           = -107,  /* port outside 1..65535             */

    /* -2xx: resources and initialization */
    PROTO_E_NOMEM              = -201,  /* allocation failed                 */
    PROTO_E_SODIUM             = -202,  /* sodium_init() failed              */

    /* -3xx: key files */
    PROTO_E_KEY_OPEN           = -301,  /* could not open the key file       */
    PROTO_E_KEY_EMPTY          = -302,  /* key file is empty                 */
    PROTO_E_KEY_FORMAT         = -303,  /* not base64 of the expected size   */
    PROTO_E_KEY_MISMATCH       = -304,  /* public half does not match secret */

    /* -4xx: cryptography */
    PROTO_E_CRYPTO             = -401,  /* libsodium operation failed        */
    PROTO_E_BAD_SIGNATURE      = -402,  /* signature did not verify          */

    /* -5xx: sockets and addressing */
    PROTO_E_SOCKET             = -501,  /* socket() failed                   */
    PROTO_E_RESOLVE            = -502,  /* getaddrinfo() failed              */
    PROTO_E_CONNECT            = -503,  /* connect() failed                  */
    PROTO_E_BIND               = -504,  /* bind() failed                     */
    PROTO_E_PORT_IN_USE        = -505,  /* bind() failed with EADDRINUSE     */
    PROTO_E_PERM_DENIED        = -506,  /* bind() denied: EACCES or EPERM    */
    PROTO_E_LISTEN             = -507,  /* listen() failed                   */
    PROTO_E_KEEPALIVE          = -508,  /* SO_KEEPALIVE rejected: no probing */
    PROTO_E_ACCEPT             = -509,  /* listening socket no longer usable */
    PROTO_E_CONNECT_TIMEOUT    = -510,  /* no answer within the deadline     */

    /* -6xx: reading and writing lines */
    PROTO_E_WRITE              = -601,  /* write() failed                    */
    PROTO_E_READ               = -602,  /* read() failed                     */
    PROTO_E_PEER_CLOSED        = -603,  /* peer closed the connection        */
    PROTO_E_LINE_TOO_LONG      = -604,  /* over buffer or cap; rest unread   */
    PROTO_E_TIMEOUT            = -605,  /* deadline passed before the line   */

    /* -7xx: handshake, client side */
    PROTO_E_UNEXPECTED_REPLY   = -701,  /* server said something else        */
    PROTO_E_BAD_CHALLENGE      = -702,  /* challenge malformed or not 32 B   */
    PROTO_E_REJECTED           = -703,  /* server refused the handshake      */
    PROTO_E_REGISTER_REJECTED  = -704   /* server refused our REGISTER       */
} proto_status_t;

/* Message for any code, never NULL. Unknown values get a generic string, so
 * it is safe to pass a return value through without checking it first. */
const char *proto_strerror(int code);

#endif /* PROTO_STATUS_H */
