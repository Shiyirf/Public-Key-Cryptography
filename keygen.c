#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "randstate.h"
#include "rsa.h"

int main(int argc, char *argv[]) {
    int ch;
    uint64_t nbits = 256; // set a default number
    uint64_t iters = 50;
    uint64_t seed = time(NULL);
    char *pbfile = "rsa.pub";
    char *pvfile = "rsa.priv";

    bool verbose = false;
    while ((ch = getopt(argc, argv, "b:c:n:d:s:vh")) != -1) {
        switch (ch) {
        case 'b': sscanf(optarg, "%lu", &nbits); break;

        case 'c': sscanf(optarg, "%lu", &iters); break;

        case 'n': pbfile = optarg; break;

        case 'd': pvfile = optarg; break;

        case 's': sscanf(optarg, "%lu", &seed); break;

        case 'v': verbose = true; break;

        default: // show help
            printf("SYNOPSIS\n\tGenerates an RSA public/private key pair.\n\n");
            printf("USAGE\n\t%s [-hv] [-b bits] -n pbfile -d pvfile\n\n", argv[0]);
            printf("OPTIONS\n");
            printf("\t-h              Display program help and usage.\n");
            printf("\t-v              Display verbose program output.\n");
            printf("\t-b bits         Minimum bits needed for public key n.\n");
            printf("\t-c confidence   Miller-Rabin iterations for testing primes (default: 50).\n");
            printf("\t-n pbfile       Public key file (default: rsa.pub).\n");
            printf("\t-d pvfile       Private key file (default: rsa.priv).\n");
            printf("\t-s seed         Random seed for testing.\n");
            exit(0);
        }
    }

    FILE *p_pbfile = fopen(pbfile, "w+");
    if (p_pbfile == NULL) {
        printf("%s open failed!\n", pbfile);
        exit(1);
    }
    FILE *p_pvfile = fopen(pvfile, "w+");
    if (p_pvfile == NULL) {
        printf("%s open failed!\n", pvfile);
        exit(1);
    }

    int fd = fileno(p_pvfile); // get file descriptor of pvfile
    fchmod(fd, S_IRUSR | S_IWUSR); // set to 0600
    randstate_init(seed);

    mpz_t p, q, n, e, d, mpz_user, s;
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(e);
    mpz_init(d);
    mpz_init(s);
    mpz_init(mpz_user);

    rsa_make_pub(p, q, n, e, nbits, iters);
    rsa_make_priv(d, e, p, q);
    char *user_name = getenv("USER");
    mpz_set_str(mpz_user, user_name, 62);
    rsa_sign(s, mpz_user, d, n);
    rsa_write_pub(n, e, s, user_name, p_pbfile);
    rsa_write_priv(n, d, p_pvfile);

    if (verbose) {
        printf("user = %s\n", user_name);
        gmp_printf("s (%d bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("p (%d bits) = %Zd\n", mpz_sizeinbase(p, 2), p);
        gmp_printf("q (%d bits) = %Zd\n", mpz_sizeinbase(q, 2), q);
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%d bits) = %Zd\n", mpz_sizeinbase(e, 2), e);
        gmp_printf("d (%d bits) = %Zd\n", mpz_sizeinbase(d, 2), d);
    }

    fclose(p_pbfile);
    fclose(p_pvfile);
    randstate_clear();
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(s);
    mpz_clear(mpz_user);
}
