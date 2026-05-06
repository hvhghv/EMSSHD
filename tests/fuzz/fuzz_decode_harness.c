#include "fuzz_decode_common.h"

#include <stdio.h>

#define FUZZ_INPUT_MAX 256u

#ifdef EMSSH_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    emssh_fuzz_exercise_decoders(data, size);
    return 0;
}
#else
static int fuzz_file(const char *path)
{
    uint8_t data[FUZZ_INPUT_MAX + 1u];
    FILE *fp;
    size_t len;

    if (path[0] == '-' && path[1] == '\0') {
        fp = stdin;
    } else {
        fp = fopen(path, "rb");
        if (fp == NULL) {
            fprintf(stderr, "failed to open %s\n", path);
            return 1;
        }
    }

    len = fread(data, 1u, sizeof(data), fp);
    if (ferror(fp)) {
        if (fp != stdin) {
            fclose(fp);
        }
        fprintf(stderr, "failed to read %s\n", path);
        return 1;
    }
    if (fp != stdin) {
        fclose(fp);
    }

    emssh_fuzz_exercise_decoders(data, len);
    return 0;
}

int main(int argc, char **argv)
{
    int rc;
    int i;

    if (argc < 2) {
        emssh_fuzz_exercise_decoders(NULL, 0u);
        return 0;
    }

    rc = 0;
    for (i = 1; i < argc; ++i) {
        if (fuzz_file(argv[i]) != 0) {
            rc = 1;
        }
    }
    return rc;
}
#endif
