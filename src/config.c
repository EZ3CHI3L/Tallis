#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <libconfig.h>
#include "tallis.h"
#include "error.h"

int tallis_parse_config(config_t *config)
{
    errno = 0;
    const char *home = getenv("HOME");

    if (!home)
        home = getpwuid(getuid())->pw_dir;

    if (!home)
    {
        perror(NULL);
        fprintf(stderr, "%s\n", "could not determine home directory");
        return 1;
    }

    const char *conf_dir = "/.tallis/", *conf_file = "tallis.conf";
    int len = strlen(home) + strlen(conf_dir) + strlen(conf_file) + 1;

    char tallis_conf_file_path[len];

    snprintf(tallis_conf_file_path, len, "%s%s%s", home, conf_dir, conf_file);

    errno = 0;
    FILE *file;
    file = fopen(tallis_conf_file_path, "a+");

    if (!file)
    {
        perror(NULL);
        fprintf(stderr, "%s\n", "fopen failed");
        fclose(file);
        return 1;
    }

    fclose(file);

    config_init(config);
    int rv = config_read_file(config, tallis_conf_file_path);

    if (rv == CONFIG_FALSE)
    {
        int err = config_error_type(config);

        switch (err)
        {
            case CONFIG_ERR_PARSE:
                fprintf(stderr, "%s\n%s:line %d\n%s\n", "error parsing file:",
                        tallis_conf_file_path,
                        config_error_line(config),
                        config_error_text(config));
                config_destroy(config);
                return 1;
                break;

            case CONFIG_ERR_FILE_IO:
                fprintf(stderr, "%s\n%s\n", "error opening file:",
                        tallis_conf_file_path);
                config_destroy(config);
                return 1;
                break;

            case CONFIG_ERR_NONE:
                fprintf(stderr, "%s\n", "unknown error");
                config_destroy(config);
                return 1;
                break;
        }
    }

    return 0;
}
