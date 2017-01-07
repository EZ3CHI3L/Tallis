#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <libconfig.h>
#include "conf.h"
#include "tallis.h"
#include "error.h"

int tallis_get_sasl_password(tallis_t* tallis)
{
    int rv = config_lookup_string(&tallis->settings.config, "sasl_password",
            &tallis->sasl_password);

    if (!rv)
        return 0;

    tallis->settings.has_sasl = 1;

    return 1;
}


void tallis_config_fail(tallis_t *tallis)
{
    tallis->settings.has_config = 0;
    puts("running with default settings, create ~/.tallis/tallis.conf" \
            " or fix your syntax");
}

char *tallis_set_conf_path()
{
    errno = 0;
    const char *home = getenv("HOME");

    if (!home)
        home = getpwuid(getuid())->pw_dir;

    if (!home)
    {
        perror(NULL);
        fprintf(stderr, "%s\n", "could not determine home directory");
        return NULL;
    }

    const char *conf_dir = "/.tallis/", *conf_file = "tallis.conf";
    int len = strlen(home) + strlen(conf_dir) + strlen(conf_file) + 1;
    char *path = malloc(len);
    snprintf(path, len, "%s%s%s", home, conf_dir, conf_file);

    return path;
}

int tallis_parse_config(config_t *config, const char *path)
{
    errno = 0;
    FILE *file;
    file = fopen(path, "a+");

    if (!file)
    {
        perror(NULL);
        fprintf(stderr, "%s\n", "couldn't open config");
        return 0;
    }

    fclose(file);

    config_init(config);
    int rv = config_read_file(config, path);

    if (rv == CONFIG_FALSE)
    {
        int err = config_error_type(config);

        switch (err)
        {
            case CONFIG_ERR_PARSE:
                fprintf(stderr, "%s\n%s:line %d\n%s\n", "error parsing file:",
                        path,
                        config_error_line(config),
                        config_error_text(config));
                config_destroy(config);
                return 0;
                break;

            case CONFIG_ERR_FILE_IO:
                fprintf(stderr, "%s\n%s\n", "error opening file:",
                        path);
                config_destroy(config);
                return 0;
                break;

            case CONFIG_ERR_NONE:
                fprintf(stderr, "%s\n", "unknown error");
                config_destroy(config);
                return 0;
                break;
        }
    }

    return 1;
}
