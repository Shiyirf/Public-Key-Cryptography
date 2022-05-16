#include <stdlib.h>
#include <math.h>
#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"

void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {
    uint64_t pbits;
    mpz_t fn, g_gcd, p_1, q_1, rand_n, rand_m;
    mpz_init(fn);
    mpz_init(g_gcd);
    mpz_init(p_1);
    mpz_init(q_1);
    mpz_init_set_ui(rand_n, nbits / 2);
    mpz_init(rand_m);

    mpz_urandomm(rand_m, state, rand_n);
    pbits = nbits / 4 + mpz_get_ui(rand_m); // get p bits using random

    make_prime(p, pbits, iters);
    make_prime(q, nbits - pbits, iters);
    mpz_mul(n, p, q);
    mpz_sub_ui(p_1, p, 1);
    mpz_sub_ui(q_1, q, 1);
    mpz_mul(fn, p_1, q_1);
    while (true) {
        mpz_urandomb(e, state, nbits);
        gcd(g_gcd, e, fn);
        if (mpz_cmp_ui(g_gcd, 1) == 0) {
            break; // find e
        }
    }

    mpz_clear(fn);
    mpz_clear(g_gcd);
    mpz_clear(p_1);
    mpz_clear(q_1);
    mpz_clear(rand_n);
    mpz_clear(rand_m);
}

void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fprintf(pbfile, "%ZX\n", n);
    gmp_fprintf(pbfile, "%ZX\n", e);
    gmp_fprintf(pbfile, "%ZX\n", s);
    gmp_fprintf(pbfile, "%s\n", username);
}

void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fscanf(pbfile, "%ZX", n);
    gmp_fscanf(pbfile, "%ZX", e);
    gmp_fscanf(pbfile, "%ZX", s);
    gmp_fscanf(pbfile, "%s", username);
}

void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
    mpz_t fn, p_1, q_1;
    mpz_init(fn);
    mpz_init(p_1);
    mpz_init(q_1);
    mpz_sub_ui(p_1, p, 1);
    mpz_sub_ui(q_1, q, 1);

    mpz_mul(fn, p_1, q_1);
    mod_inverse(d, e, fn);

    mpz_clear(fn);
    mpz_clear(p_1);
    mpz_clear(q_1);
}

void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fprintf(pvfile, "%ZX\n", n);
    gmp_fprintf(pvfile, "%ZX\n", d);
}

void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fscanf(pvfile, "%ZX", n);
    gmp_fscanf(pvfile, "%ZX", d);
}

void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    pow_mod(c, m, e, n);
}

// helper function
double log_n(mpz_t n) {
    double di;
    signed long int ex;
    di = mpz_get_d_2exp(&ex, n);
    return ex
           + pow(
               log(di), -1); // xi = di * 2 ^ ex  ==> log(xi) = log(di) + ex * log(2)log_n = log2(n)
}

void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {
    mpz_t m, c;
    mpz_init(m);
    mpz_init(c);

    size_t j;
    uint64_t k; //block size
    k = (uint64_t)((log_n(n) - 1) / 8); // get block size

    uint8_t *block = malloc(k);
    block[0] = 0xFF;
    while ((j = fread(block + 1, 1, k - 1, infile))) {
        mpz_import(m, j + 1, 1, 1, 1, 0, block);
        rsa_encrypt(c, m, e, n);
        gmp_fprintf(outfile, "%ZX\n", c);
        if (j != k - 1) {
            break;
        }
    }
    mpz_clear(m);
    mpz_clear(c);
    free(block);
}

void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    pow_mod(m, c, d, n);
}

void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
    mpz_t c, m;
    mpz_init(c);
    mpz_init(m);

    size_t j;
    uint64_t k; //block size
    k = (uint64_t)((log_n(n) - 1) / 8); // get block size

    uint8_t *block = malloc(k);
    while (gmp_fscanf(infile, "%ZX", c) != EOF) {
        rsa_decrypt(m, c, d, n);
        mpz_export(block, &j, 1, 1, 1, 0, m);
        fwrite(block + 1, 1, j - 1, outfile);
        // if (j != k) {
        //     break;
        // }
    }

    mpz_clear(c);
    mpz_clear(m);
    free(block);
}

void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    pow_mod(s, m, d, n);
}

bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    mpz_t t;
    mpz_init(t);
    pow_mod(t, s, e, n);
    if (mpz_cmp(m, t) == 0) {
        mpz_clear(t);
        return true;
    }
    mpz_clear(t);
    return false;
}
