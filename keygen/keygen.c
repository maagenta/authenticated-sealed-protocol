#include "../protocol.h"
#include <sodium.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Ask whether the current directory honours file permissions. The mode
 * passed to open() is a request: a filesystem without permissions (FAT,
 * some network mounts) creates the file with whatever it uses and open()
 * succeeds anyway, so the only way to know is to create a file and look.
 * Returns 1 if a 0600 file really is 0600, 0 if it is not, -1 if the
 * directory is not writable at all (the key files would fail too). */
static int dir_honours_mode(void) {
    const char *probe = ".keygen-probe";
    int fd = open(probe, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return -1;
    struct stat st;
    int ok = fstat(fd, &st) == 0 && (st.st_mode & 077) == 0;
    close(fd);
    unlink(probe);
    return ok;
}

/* y/n on the terminal. Anything but an explicit yes is a no, including a
 * stdin that is not a terminal: a script cannot accept a risk on the
 * user's behalf. */
static int confirm(const char *question) {
    if (!isatty(STDIN_FILENO)) return 0;
    printf("%s [y/N] ", question);
    fflush(stdout);
    char answer[8];
    if (!fgets(answer, sizeof answer, stdin)) return 0;
    return answer[0] == 'y' || answer[0] == 'Y';
}

/* Write one key as a single line of base64 (standard variant).
 *
 * The file is created with mode 0600 in the same call that creates it:
 * fopen() followed by chmod() would expose the secret between the two,
 * and would silently reuse the permissions of a file that already exists.
 * O_EXCL refuses to overwrite: a second run must not destroy an identity
 * the user may have no other copy of. */
static int write_key_file(const char *path,
                          const unsigned char *key, size_t key_len) {
    char b64[512];
    sodium_bin2base64(b64, sizeof(b64), key, key_len,
                      sodium_base64_VARIANT_ORIGINAL);

    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        if (errno == EEXIST)
            fprintf(stderr, "Error: %s already exists; refusing to overwrite a key\n", path);
        else
            fprintf(stderr, "Error: could not create %s: %s\n", path, strerror(errno));
        return -1;
    }
    FILE *f = fdopen(fd, "w");
    if (!f) {
        fprintf(stderr, "Error: could not open %s: %s\n", path, strerror(errno));
        close(fd); unlink(path);
        return -1;
    }
    /* Writes are buffered, so a full disk surfaces at fclose(). Check it:
     * a truncated key file would otherwise pass as created and fail later
     * in proto_load_keys with no hint of why. Remove the partial file. */
    if (fprintf(f, "%s\n", b64) < 0 || fclose(f) != 0) {
        fprintf(stderr, "Error: could not write %s: %s\n", path, strerror(errno));
        unlink(path);
        return -1;
    }
    printf("  Created: %s\n", path);
    return 0;
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: could not initialize libsodium\n");
        return 1;
    }

    printf("=== proto key generator ===\n\n");

    /* Refuse before generating anything if any file exists, so a partial
     * identity is never left behind. O_EXCL below still guards each file:
     * this check is for the message, that one is for the race. */
    static const char *const files[] = { "auth.key", "auth.pub", "enc.key" };
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
        if (access(files[i], F_OK) == 0) {
            fprintf(stderr, "Error: %s already exists; refusing to overwrite a key.\n"
                            "Back up and remove the old files to generate a new identity.\n",
                    files[i]);
            return 1;
        }
    }

    /* Settle the permissions question before any secret touches the disk:
     * if the user declines, nothing has been written. */
    int protected = dir_honours_mode();
    if (protected < 0) {
        fprintf(stderr, "Error: cannot create files here: %s\n", strerror(errno));
        return 1;
    }
    if (!protected) {
        printf("Warning: this directory is on a filesystem that does not support\n"
               "file permissions (chmod). The key files will be readable by every\n"
               "user of this machine, which may be unsafe.\n\n");
        if (!confirm("Create the key files here anyway?")) {
            printf("Aborted; no files were created.\n");
            return 1;
        }
        printf("\n");
    }

    /* --- Authentication key pair (Ed25519) --- */
    printf("Generating authentication key pair (Ed25519)...\n");
    unsigned char auth_pk[AUTH_PK_LEN];
    unsigned char auth_sk[AUTH_SK_LEN];
    crypto_sign_keypair(auth_pk, auth_sk);

    if (write_key_file("auth.key", auth_sk, AUTH_SK_LEN) != 0)
        return 1;
    if (write_key_file("auth.pub", auth_pk, AUTH_PK_LEN) != 0)
        return 1;

    /* --- Encryption key pair (X25519) --- */
    /* Only the secret key is written: the public key is re-derived from it
     * on load (proto_load_keys) and reaches the server via REGISTER. */
    printf("\nGenerating encryption key pair (X25519)...\n");
    unsigned char enc_pk[ENC_PK_LEN];
    unsigned char enc_sk[ENC_SK_LEN];
    crypto_box_keypair(enc_pk, enc_sk);

    if (write_key_file("enc.key", enc_sk, ENC_SK_LEN) != 0)
        return 1;

    printf("\nKeys generated successfully");
    if (protected) printf(" (files created with mode 0600 — owner only)");
    else           printf(" (WARNING: files are readable by other users)");
    printf(":\n");
    printf("  auth.key  — authentication private key (KEEP SECRET)\n");
    printf("  auth.pub  — authentication public key  (server allowlist)\n");
    printf("  enc.key   — encryption private key     (KEEP SECRET)\n");
    printf("\nClients load auth.key + enc.key  (proto_load_keys).\n");
    printf("Servers load auth.pub             (proto_load_pubkey_hex).\n");
    return 0;
}
