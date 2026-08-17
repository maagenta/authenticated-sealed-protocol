#ifndef PROTO_ERROR_H
#define PROTO_ERROR_H

/*
 * Error codes returned by the library.
 *
 * All are negative, so existing `rc < 0` and `rc != 0` checks keep working
 * unchanged; only callers that want the reason need to look closer. Values
 * are assigned sequentially and never reused: the number is an opaque
 * identifier, the name and the section comment say which family it belongs
 * to. Functions returning a pointer still report failure with NULL.
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

    /* caller mistakes */
    PROTO_E_PARAM              =   -1,  /* invalid argument                  */
    PROTO_E_BUFFER_TOO_SMALL   =   -2,  /* caller buffer cannot hold result  */
    PROTO_E_NO_ALLOWLIST       =   -3,  /* allowed_hex is NULL               */
    PROTO_E_BAD_ALLOWLIST      =   -4,  /* allowed_hex is not 64 hex chars   */
    PROTO_E_NO_HANDLER         =   -5,  /* handler is NULL                   */

    /* resources */
    PROTO_E_NOMEM              =   -6,  /* allocation failed                 */

    /* initialization */
    PROTO_E_SODIUM             =   -7,  /* sodium_init() failed              */

    /* key files */
    PROTO_E_KEY_OPEN           =   -8,  /* could not open the key file       */
    PROTO_E_KEY_EMPTY          =   -9,  /* key file is empty                 */
    PROTO_E_KEY_FORMAT         =  -10,  /* not base64 of the expected size   */

    /* cryptography */
    PROTO_E_CRYPTO             =  -11,  /* libsodium operation failed        */
    PROTO_E_BAD_SIGNATURE      =  -12,  /* signature did not verify          */

    /* sockets and addressing */
    PROTO_E_SOCKET             =  -13,  /* socket() failed                   */
    PROTO_E_RESOLVE            =  -14,  /* getaddrinfo() failed              */
    PROTO_E_CONNECT            =  -15,  /* connect() failed                  */
    PROTO_E_BIND               =  -16,  /* bind() failed                     */
    PROTO_E_PORT_IN_USE        =  -17,  /* bind() failed with EADDRINUSE     */
    PROTO_E_PERM_DENIED        =  -18,  /* bind() denied: EACCES or EPERM    */
    PROTO_E_LISTEN             =  -19,  /* listen() failed                   */
    PROTO_E_KEEPALIVE          =  -20,  /* SO_KEEPALIVE rejected: no probing */

    /* reading and writing lines */
    PROTO_E_WRITE              =  -21,  /* write() failed                    */
    PROTO_E_READ               =  -22,  /* read() failed                     */
    PROTO_E_PEER_CLOSED        =  -23,  /* peer closed the connection        */
    PROTO_E_LINE_TOO_LONG      =  -24,  /* line did not fit; rest unread     */

    /* handshake, client side */
    PROTO_E_UNEXPECTED_REPLY   =  -25,  /* server said something else        */
    PROTO_E_BAD_CHALLENGE      =  -26,  /* challenge malformed or not 32 B   */
    PROTO_E_REJECTED           =  -27,  /* server refused the handshake      */
    PROTO_E_REGISTER_REJECTED  =  -28   /* server refused our REGISTER       */
} proto_err_t;

/* Message for any code, never NULL. Unknown values get a generic string, so
 * it is safe to pass a return value through without checking it first. */
const char *proto_strerror(int err);

#endif /* PROTO_ERROR_H */
