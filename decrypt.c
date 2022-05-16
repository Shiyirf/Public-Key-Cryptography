#include "rsa.h"
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int ch;
    FILE *infile = stdin, *outfile = stdout;
    char *pvfile = "rsa.priv";

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

        case 'n': pvfile = optarg; break;

        case 'v': verbose = true; break;

        default: // show help
            printf("SYNOPSIS\n\tDecrypts data using RSA decryption.\n\tEncrypted data is encrypted "
                   "by the encrypt program.\n\n");
            printf("USAGE\n\t%s [-hv] [-i infile] [-o outfile] -n privkey\n\n", argv[0]);
            printf("OPTIONS\n");
            printf("\t-h              Display program help and usage.\n");
            printf("\t-v              Display verbose program output.\n");
            printf("\t-i infile       Input file of data to decrypt (default: stdin).\n");
            printf("\t-o outfile      Output file for decrypted data (default: stdout).\n");
            printf("\t-n pvfile       Private key file (default: rsa.priv).\n");
            exit(0);
        }
    }

    FILE *p_pvfile = fopen(pvfile, "r");
    if (p_pvfile == NULL) {
        printf("%s open failed!\n", pvfile);
        exit(1);
    }

    mpz_t n, d;
    mpz_init(n);
    mpz_init(d);

    rsa_read_priv(n, d, p_pvfile);

    if (verbose) {
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("d (%d bits) = %Zd\n", mpz_sizeinbase(d, 2), d);
    }

    rsa_decrypt_file(infile, outfile, n, d);

    fclose(p_pvfile);
    if (infile != stdin) {
        fclose(infile);
    }
    if (outfile != stdout) {
        fclose(outfile);
    }
    mpz_clear(n);
    mpz_clear(d);
}
