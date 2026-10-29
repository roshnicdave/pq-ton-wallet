/* Disposable testnet research only. Pinned upstream primitives, binary stdin.
 * keygen: seed48 -> public32. sign: secret64 || random16 || M' -> signature3856.
 * No secret argv, files, cache, key counters or key generation via the test RNG.
 */
#include <stdio.h>
#include <string.h>
#include "api.h"
extern void set_rng_buffer(const unsigned char *, unsigned long long);
static void wipe(unsigned char *p, size_t n) {
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}
int main(int argc, char **argv) {
    unsigned char sk[64], pk[32], random[16], msg[512], sig[3856];
    size_t len, siglen = 0;
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "keygen")) {
        unsigned char seed[48];
        if (fread(seed, 1, 48, stdin) != 48 || getchar() != EOF) return 2;
        if (crypto_sign_seed_keypair(pk, sk, seed)) return 3;
        wipe(seed, sizeof seed); wipe(sk, sizeof sk);
        return fwrite(pk, 1, sizeof pk, stdout) == sizeof pk ? 0 : 4;
    }
    if (strcmp(argv[1], "sign")) return 2;
    if (fread(sk, 1, 64, stdin) != 64 || fread(random, 1, 16, stdin) != 16) return 2;
    len = fread(msg, 1, sizeof msg, stdin);
    if (len == sizeof msg || ferror(stdin)) return 2;
    memcpy(pk, sk + 32, sizeof pk);
    set_rng_buffer(random, sizeof random);
    int failed = crypto_sign_signature(sig, &siglen, msg, len, sk);
    wipe(sk, sizeof sk); wipe(random, sizeof random);
    if (failed || siglen != sizeof sig || crypto_sign_verify(sig, siglen, msg, len, pk)) return 3;
    return fwrite(sig, 1, siglen, stdout) == siglen ? 0 : 4;
}
