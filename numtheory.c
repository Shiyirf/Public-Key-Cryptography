#include "numtheory.h"

gmp_randstate_t state;

void pow_mod(mpz_t out, mpz_t base, mpz_t exponent, mpz_t modulus) {
    mpz_t v, p, num, t_d;
    mpz_init_set_ui(v, 1);
    mpz_init_set(p, base);
    mpz_init_set(t_d, exponent);
    mpz_init_set_ui(num, 2);
    while (mpz_cmp_ui(t_d, 0) > 0) {
        if (mpz_odd_p(t_d)) {
            mpz_mul(v, v, p);
            mpz_mod(v, v, modulus);
        }
        mpz_mul(p, p, p);
        mpz_mod(p, p, modulus);
        mpz_fdiv_q(t_d, t_d, num);
    }
    mpz_set(out, v);
    mpz_clears(v, p, num, t_d, NULL);
}

bool is_prime(mpz_t n, uint64_t iters) {
    if (mpz_cmp_ui(n, 0) == 0 || mpz_cmp_ui(n, 1) == 0) {
        return false;
    } else if (mpz_cmp_ui(n, 2) == 0 || mpz_cmp_ui(n, 3) == 0) {
        return true;
    }
    mpz_t r, s, a, n_3, y, j, n_1, s_1, num;
    mpz_init(r);
    mpz_init_set_ui(s, 0);
    mpz_init(a);
    mpz_init(n_1);
    mpz_init(n_3);
    mpz_init(y);
    mpz_init(j);
    mpz_init(s_1);
    mpz_init_set_ui(num, 2);

    mpz_sub_ui(r, n, 1);
    mpz_sub_ui(n_3, n, 3); //n_3 = n-3
    mpz_sub_ui(n_1, n, 1); //n_1 = n-1
    while (mpz_even_p(r)) {
        mpz_cdiv_q_ui(r, r, 2);
        mpz_add_ui(s, s, 1);
    }
    for (uint64_t i = 0; i < iters; i++) {
        mpz_urandomm(a, state, n_3); //0 <= a <= n-4
        mpz_add_ui(a, a, 2); //2 <= a <= n-2
        pow_mod(y, a, r, n);
        if (mpz_cmp_ui(y, 1) != 0 && mpz_cmp(y, n_1) != 0) {
            mpz_set_ui(j, 1);
            mpz_sub_ui(s_1, s, 1); //s_1 = s-1
            while (mpz_cmp(j, s_1) <= 0 && mpz_cmp(y, n_1) != 0) {
                pow_mod(y, y, num, n);
                if (mpz_cmp_ui(y, 1) == 0) {
                    mpz_clears(r, s, a, n_3, y, j, n_1, s_1, num, NULL);
                    return false;
                }
                mpz_add_ui(j, j, 1);
            }
            if (mpz_cmp(y, n_1) != 0) {
                mpz_clears(r, s, a, n_3, y, j, n_1, s_1, num, NULL);
                return false;
            }
        }
    }
    mpz_clears(r, s, a, n_3, y, j, n_1, s_1, num, NULL);
    return true;
}

void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    mpz_t t;
    mpz_init(t);
    mpz_ui_pow_ui(t, 2, bits);
    mpz_urandomb(p, state, bits);
    mpz_add(p, p, t); // at least bits long
    while (is_prime(p, iters) == false) {
        mpz_urandomb(p, state, bits);
        mpz_add(p, p, t);
    }
    mpz_clear(t);
}

void gcd(mpz_t g, mpz_t a, mpz_t b) {
    mpz_t t, t_a, t_b;
    mpz_init(t);
    mpz_init_set(t_a, a);
    mpz_init_set(t_b, b);
    while (mpz_cmp_ui(t_b, 0) != 0) {
        mpz_set(t, t_b);
        mpz_mod(t_b, t_a, t_b);
        mpz_set(t_a, t);
    }
    mpz_set(g, t_a);
    mpz_clears(t, t_a, t_b, NULL);
}

void mod_inverse(mpz_t i, mpz_t a, mpz_t n) {
    mpz_t r1, r2, t1, t2, q, tmp, tmul;
    mpz_init(q);
    mpz_init(tmp);
    mpz_init(tmul);
    mpz_init_set(r1, n);
    mpz_init_set(r2, a);
    mpz_init_set_ui(t1, 0);
    mpz_init_set_ui(t2, 1);
    while (mpz_cmp_ui(r2, 0) != 0) {
        mpz_fdiv_q(q, r1, r2);
        mpz_set(tmp, r1);
        mpz_set(r1, r2);
        mpz_mul(tmul, q, r2);
        mpz_sub(r2, tmp, tmul);
        mpz_set(tmp, t1);
        mpz_set(t1, t2);
        mpz_mul(tmul, q, t2);
        mpz_sub(t2, tmp, tmul);
    }
    if (mpz_cmp_ui(r1, 1) > 0) {
        mpz_set_ui(i, 0);
    } else if (mpz_cmp_ui(t1, 0) < 0) {
        mpz_add(t1, t1, n);
        mpz_set(i, t1);
    } else {
        mpz_set(i, t1);
    }
    mpz_clears(r1, r2, t1, t2, q, tmp, tmul, NULL);
}
