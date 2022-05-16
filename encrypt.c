#include "rsa.h"
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int ch;
    FILE *infile = stdin, *outfile = stdout;
    char *pbfile = "rsa.pub";

    bool verbose = false;
    while ((ch = getopt(argc, argv, "i:o:n:vh")) != -1) {
        switch (ch) {
        case 'i':
            infile = fopen(optarg, "r");
            if (infile == NULL) {
                printf("%s open failed!\n", optarg);
                exit(1);
            }
            break;

        case 'o':
            outfile = fopen(optarg, "w+");
            if (outfile == NULL) {
                printf("%s open failed!\n", optarg);
                exit(1);
            }
            break;

        case 'n': pbfile = optarg; break;

        case 'v': verbose = true; break;

        default: // show help
            printf("SYNOPSIS\n\tEncrypts data using RSA encryption.\n\tEncrypted data is decrypted "
                   "by the decrypt program.\n\n");
            printf("USAGE\n\t%s [-hv] [-i infile] [-o outfile] -n pubkey\n\n", argv[0]);
            printf("OPTIONS\n");
            printf("\t-h              Display program help and usage.\n");
            printf("\t-v              Display verbose program output.\n");
            printf("\t-i infile       Input file of data to decrypt (default: stdin).\n");
            printf("\t-o outfile      Output file for decrypted data (default: stdout).\n");
            printf("\t-n pbfile       Public key file (default: rsa.pub).\n");
            exit(0);
        }
    }

    FILE *p_pbfile = fopen(pbfile, "r");
    if (p_pbfile == NULL) {
        printf("%s open failed!\n", pbfile);
        exit(1);
    }

    mpz_t n, e, s, mpz_user;
    mpz_init(n);
    mpz_init(e);
    mpz_init(s);
    mpz_init(mpz_user);

    char user_name[20];
    rsa_read_pub(n, e, s, user_name, p_pbfile);

    if (verbose) {
        printf("user = %s\n", user_name);
        gmp_printf("s (%d bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%d bits) = %Zd\n", mpz_sizeinbase(e, 2), e);
    }
    mpz_set_str(mpz_user, user_name, 62);
    if (rsa_verify(mpz_user, s, e, n) == false) { // verify signature
        printf("signature verify failed!\n");
        exit(1);
    }
    rsa_encrypt_file(infile, outfile, n, e);

    fclose(p_pbfile);
    if (infile != stdin) {
        fclose(infile);
    }
    if (outfile != stdout) {
        fclose(outfile);
    }
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(s);
    mpz_clear(mpz_user);
}
