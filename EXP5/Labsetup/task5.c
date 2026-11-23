#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *s1 = BN_new();
    BIGNUM *s2 = BN_new();
    BIGNUM *m1 = BN_new();
    BIGNUM *m2 = BN_new();

    BN_hex2bn(&n, "DCBCD38D02D6794D721DD40A9F2DF164F92186C3631C94D44F8C8619FB020DF05EC24C12D3380D6D19C483F20420786591BB4D916E04A751433E770428B4783F");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&m, "4c61756e63682061206d697373696c652e");

    BN_hex2bn(&s1, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&s2, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

    BN_mod_exp(m1, s1, e, n, ctx);
    BN_mod_exp(m2, s2, e, n, ctx);

    printBN("Decrypted Original Signature M1  = ", m1);
    printBN("Decrypted Corrupted Signature M2 = ", m2);

    printf("\n--- Verification Results ---\n");
    if (BN_cmp(m1, m) == 0) {
        printf("Signature 1 (s1): VALID [Matches Original Message]\n");
    } else {
        printf("Signature 1 (s1): INVALID\n");
    }

    if (BN_cmp(m2, m) == 0) {
        printf("Signature 2 (s2): VALID\n");
    } else {
        printf("Signature 2 (s2): INVALID [Corrupted / Tampered]\n");
    }

    BN_free(n);
    BN_free(e);
    BN_free(m);
    BN_free(s1);
    BN_free(s2);
    BN_free(m1);
    BN_free(m2);
    BN_CTX_free(ctx);

    return 0;
}
