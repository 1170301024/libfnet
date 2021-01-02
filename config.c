
/**
 * \file config.c
 *
 * \brief implementation for the configuration system
 *
 */

#include <stdio.h>
#include <stdlib.h>       
#include <limits.h>
#include <ctype.h> 
#include <stdbool.h>
#include <string.h>

#include "include/error.h"
#include "include/config.h"

/** returns if two string are the same */
#define match(c, x) (strlen(x) == strlen(c) && !strncmp(c, x, strlen(x)))

/* parses an integer value */
static int parse_int (unsigned int *x, const char *arg, int num_arg, unsigned int min, unsigned int max) {
    const char *c = arg;

    if (x == NULL) {
        return -1;
    }

    if (num_arg == 2) {
        if (arg == NULL) {
            return -1;
        }
        while (*c != 0) {
            if (!isdigit(*c)) {
                      printf("error: argument %s must be a number ", arg);
                      return -1;
            }
            c++;
        }
        *x = atoi(arg);
        if (*x < min || *x > max) {
            printf("error: value must be between %d and %d ", min, max);
            return -1;
        }
    } else {
        return -1;
    }
    return 0;
}

/* parses a boolean value */
static int parse_bool (bool *x, const char *arg, int num_arg) {
    bool val = 0;

    /* if the number of arguments is one, default turn the option on */
    if (num_arg == 1) {
        *x = 1;
        return 0;
    }

    /* sanity check the length of the value string */
    if (strlen(arg) > 1) {
        printf("error: value too big, value must be 0 or 1");
        return -1;
    }

    /* make sure value is a digit */
    if (!isdigit(*arg)) {
        printf("error: non-digit, value must be 0 or 1");
        return -1;
    }

    /* change the value into a digit */
    val = atoi(arg);

    /* if value is not 1, turn off option */
    if (val == 1) {
        *x = 1;
    } else {
        *x = 0;
    }
    return 0;
}

/*parses a string values */
static int parse_string (char **s, char *arg, int num_arg) {
    if (s == NULL || arg == NULL || num_arg != 2) {
        return -1;
    }
  
    if (strncmp(arg, NULL_KEYWORD, strlen(NULL_KEYWORD)) == 0) {
        *s = NULL;
    } else {
        *s = strdup(arg); /* note: must be freed later */
    }
    return 0;
}

/* parses mutliple part string values */
static int parse_string_multiple (char **s, char *arg, int num_arg,
           unsigned int string_num, unsigned int string_num_max) {
    if (s == NULL) {
        return 1;
    }
    if (string_num >= string_num_max) {
        return 1;
    }
    return parse_string(&s[string_num], arg, num_arg);
}

/* see if parse checks are ok */
#define parse_check(s) if ((s)) {                   \
   fprintf(stdout, "error in command %s\n", command); \
   return 1;                                  \
  } else {                                          \
  return 0;                                        \
}


/* parse commands */
static int config_parse_command (configuration_t *config,
                         const char *command, char *arg, int num) {  
    char *tmp;
  
    /* remove trailing whitespace from argument */
    tmp = arg + strnlen(arg, LINEMAX) - 1;
    while (isblank(*tmp)) {
        *tmp = 0;
        tmp--;
    }
  
    /*
     * note: because of the simplistic match function currently
     * implemented, each command name MUST NOT be a prefix of any other
     * command name; otherwise, the shorter name will be matched rather
     * than the longer one
     */

    if (match(command, "ip")) {
        parse_check(parse_bool(&config->ip, arg, num));

    } else if (match(command, "tcp")) {
        parse_check(parse_bool(&config->tcp, arg, num));

    } else if (match(command, "outfile")) {
        parse_check(parse_string(&config->filename, arg, num));

    } else if (match(command, "outdir")) {
        parse_check(parse_string(&config->outputdir, arg, num));

    } else if (match(command, "logfile")) {
        parse_check(parse_string(&config->logfile, arg, num));

    }
    //config_all_features_bool(feature_list);

    return 1;
}

/**
 * \fn void config_set_defaults (configuration_t *config)
 *
 * \brief Using the global \p config struct, assign the default
 *        values for options contained within.
 *
 * \param config pointer to configuration structure
 * \return none
 */
void config_set_defaults (configuration_t *config) {
    // config->verbosity = 4;
    // config->show_config = 0;
    // config->show_interfaces = 0;
    // config->num_pkts = DEFAULT_NUM_PKT_LEN;
    // config->num_threads = 1;
    // config->updater_on = 0;
}

#define MAX_FILEPATH 128

static FILE* open_config_file(const char *filename) {
    FILE *fp = NULL;

    /* Try the filename that was given (it may be whole path needed) */
    fp = fopen(filename, "r");

#ifdef WIN32
    if (!fp) {
        /* In case of Windows install, try looking in the LocalAppData */
        char *filepath = NULL;
        PWSTR windir = NULL;

        /* Allocate memory to store constructed file path */
        filepath = calloc(MAX_FILEPATH, sizeof(char));
	if (!filepath) {
	    joy_log_err("out of memory");
	}

        SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &windir);

        snprintf(filepath, MAX_FILEPATH, "%ls\\Joy\\%s", windir, filename);
        fp = fopen(filepath, "r");

        if (windir != NULL) {
            CoTaskMemFree(windir);
        }

        if (filepath) {
            free(filepath);
        }
    }
#endif

    if (!fp) {
        err_msg("could not open %s", filename);
    }

    return fp;
}

/**
 * \fn void config_set_from_file (configuration_t *config, const char *fname)
 *
 * \brief Read in a .cfg file and parse the contents for option values.
 *
 * \param config pointer to configuration structure
 * \param fname file with configuration items in it
 * \return ok
 * \return failure
 */
int config_set_from_file (configuration_t *config, const char *fname) {
    FILE *f;
    char *line = NULL;
    size_t ignore;
    int len;
    unsigned int linecount = 0;
    char *c;

    f = open_config_file(fname);
    if (f == NULL) {
        err_msg("could not find config file %s\n", fname);
        return 0;
    } 

    /*
     * Setting the default configuration values!
     */
    config_set_defaults(config);

    while ((len = getline(&line, &ignore, f)) != -1) {
        int num;
        char lhs[LINEMAX], rhs[LINEMAX];

        linecount++;
        if (len > LINEMAX) {
            fprintf(stderr, "error: line too long in file %s\n", fname);
            fclose(f);
            return 0;
        }

        /* ignore blank lines and comments */
        c = line;
        while (isblank(*c)) {
            c++;
        }
        if (*c == '#' || *c == '\n') {
            ;
        } else {
            /*
             * a valid command line consists of a LHS, possibly followed by
             * an "=" and a RHS.  The newline and # (start of comment) is
             * not part of the RHS.
             */
            num = sscanf(line, "%[^=] = %[^\n#]", lhs, rhs);
            if (num == 2 || num == 1) {
                       // printf("%s = %s ### %d ### %s", lhs, rhs, num, line);
                       if (config_parse_command(config, lhs, rhs, num) != 1) {
                           fprintf(stderr, "error: unknown command (%s)\n", lhs);
                           fclose(f);
                           exit(EXIT_FAILURE);
                       }
            } else if (num == 1) {
                       printf("error: could not parse line %u in file %s (\"%s ...\")\n", 
                                      linecount, fname, lhs);
                       fclose(f);
                       exit(EXIT_FAILURE);
            } else {
                       printf("error: could not parse line %s in file %s\n", line, fname);
                       fprintf(stderr, "error: could not parse line %s in file %s\n", 
                                             line, fname);
            }
        }
    }
    free(line);
    fclose(f);
    return 0;
}

/**
 * \fn int config_set_from_argv (configuration_t *config, char *argv[], int argc)
 *
 * \brief Read in from the command line and parse the args for option values.
 *
 * \param config pointer to configuration structure
 * \param argv arguments passed in
 * \param argc number of arguments
 * \return ok
 * \return failure
 */
int config_set_from_argv (configuration_t *config, char *argv[], int argc) {
    puts(argv[0]);
    puts(argv[1]);
    const char *line = NULL;
    int len;
        int i;
    unsigned int linecount = 0;
    const char *c;

    config_set_defaults(config);

    for (i=1; i<argc; i++) {
        int num;
        char lhs[LINEMAX], rhs[LINEMAX];

        line = argv[i];
        len = strlen(line);

        linecount++;
        if (len > LINEMAX) {
            fprintf(stderr, "error: line too long in argument %s\n", argv[i]);
            return 0;
        }

        /* ignore blank lines and comments */
        c = line;
        while (isblank(*c)) {
            c++;
        }
        if (*c == '#' || *c == '\n') {
            ;
        } else {
            /*
             * a valid command line consists of a LHS, possibly followed by
             * an "=" and a RHS.  The newline and # (start of comment) is
             * not part of the RHS.
             */
            num = sscanf(line, "%[^=] = %[^\n#]", lhs, rhs);
            if (num == 2) {
                     // printf("%s = %s ### %d ### %s", lhs, rhs, num, line);
                      if (config_parse_command(config, lhs, rhs, num) != 0) {
                          printf("error: did not understand command %s\n", lhs);
                          exit(EXIT_FAILURE);
                          //      break;
                      }
            } else if (num == 1) {
                      /* 
                       * since there is no "=" in argument, we assume that it is a
                       * filename
                       */
                      break;    
            } else {
                      printf("error: could not parse argument %s\n", line);
            }
        }
    }
    return i-1;
}

/** determine if we have avlue or not */
#define val(x) x ? x : NULL_KEYWORD 

/**
 * \fn void config_print (FILE *f, const configuration_t *c)
 * \param f file to print configuration to
 * \param c pointer to the configuration structure
 * \return none
 */
/*
void config_print (FILE *f, const configuration_t *c) {
    unsigned int i;
#ifdef PACKAGE_VERSION
    fprintf(f, "joy version = %s\n", PACKAGE_VERSION);
#else
    fprintf(f, "joy version = %s\n", VERSION);
#endif
    fprintf(f, "interface = %s\n", val(c->intface));
    fprintf(f, "promisc = %u\n", c->promisc);
    fprintf(f, "output = %s\n", val(c->filename));
    fprintf(f, "outputdir = %s\n", val(c->outputdir));
    fprintf(f, "username = %s\n", val(c->username));
    fprintf(f, "count = %u\n", c->max_records); 
    fprintf(f, "upload = %s\n", val(c->upload_servername));
    fprintf(f, "keyfile = %s\n", val(c->upload_key));
    for (i=0; i<c->num_subnets; i++) {
        fprintf(f, "label=%s\n", c->subnet[i]);
    }
    fprintf(f, "retain = %u\n", c->retain_local);
    fprintf(f, "bidir = %u\n", c->bidir);
    fprintf(f, "num_pkts = %u\n", c->num_pkts);
    fprintf(f, "zeros = %u\n", c->include_zeroes);
    fprintf(f, "retrans = %u\n", c->include_retrans);
    fprintf(f, "dist = %u\n", c->byte_distribution);
    fprintf(f, "cdist = %s\n", val(c->compact_byte_distribution));
    fprintf(f, "entropy = %u\n", c->report_entropy);
    fprintf(f, "hd = %u\n", c->report_hd);
    fprintf(f, "classify = %u\n", c->include_classifier);
    fprintf(f, "idp = %u\n", c->idp);
    fprintf(f, "exe = %u\n", c->report_exe);
    fprintf(f, "anon = %s\n", val(c->anon_addrs_file));
    fprintf(f, "useranon = %s\n", val(c->anon_http_file));
    fprintf(f, "bpf = %s\n", val(c->bpf_filter_exp));

    config_print_all_features_bool(feature_list);

    fprintf(f, "verbosity = %u\n", c->verbosity);
    fprintf(f, "threads = %u\n", c->num_threads);
    fprintf(f, "updater = %u\n", c->updater_on);
  */
    /* note: anon_print_subnets is silent when no subnets are configured */
    /*anon_print_subnets(f);
}
*/
/**
 * \fn void config_print_json (zfile f, const configuration_t *c)
 * \param f file to print configuration to
 * \param c pointer to the configuration structure
 * \return none
 *
void config_print_json (zfile f, const configuration_t *c) {
    unsigned int i;

    zprintf(f, "{\"version\":\"%s\",", VERSION);
    zprintf(f, "\"interface\":\"%s\",", val(c->intface));
    zprintf(f, "\"promisc\":%u,", c->promisc);
    zprintf(f, "\"output\":\"%s\",", val(c->filename));
    zprintf(f, "\"outputdir\":\"%s\",", val(c->outputdir));
    zprintf(f, "\"username\":\"%s\",", val(c->username));
    zprintf(f, "\"info\":\"%s\",", val(c->logfile));
    zprintf(f, "\"count\":%u,", c->max_records); 
    zprintf(f, "\"upload\":\"%s\",", val(c->upload_servername));
    zprintf(f, "\"keyfile\":\"%s\",", val(c->upload_key));
    for (i=0; i<c->num_subnets; i++) {
        zprintf(f, "\"label\":\"%s\",", c->subnet[i]);
    }
    zprintf(f, "\"retain\":%u,", c->retain_local);
    zprintf(f, "\"bidir\":%u,", c->bidir);
    zprintf(f, "\"num_pkts\":%u,", c->num_pkts);
    zprintf(f, "\"zeros\":%u,", c->include_zeroes);
    zprintf(f, "\"retrans\":%u,", c->include_retrans);
    zprintf(f, "\"dist\":%u,", c->byte_distribution);
    zprintf(f, "\"cdist\":\"%s\",", val(c->compact_byte_distribution));
    zprintf(f, "\"entropy\":%u,", c->report_entropy);
    zprintf(f, "\"hd\":%u,", c->report_hd);
    zprintf(f, "\"classify\":%u,", c->include_classifier);
    zprintf(f, "\"idp\":%u,", c->idp);
    zprintf(f, "\"exe\":%u,", c->report_exe);
    zprintf(f, "\"anon\":\"%s\",", val(c->anon_addrs_file));
    zprintf(f, "\"useranon\":\"%s\",", val(c->anon_http_file));
    zprintf(f, "\"bpf\":\"%s\",", val(c->bpf_filter_exp));
    zprintf(f, "\"verbosity\":%u,", c->verbosity);
    zprintf(f, "\"threads\":%u,", c->num_threads);
    zprintf(f, "\"updater\":%u,", c->updater_on);

    config_print_json_all_features_bool(feature_list);

    zprintf(f, "\"end-config\":1}\n"); 
}*/

