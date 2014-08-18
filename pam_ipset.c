#define _BSD_SOURCE

#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#define PAM_IPSET_SUCCESS 0
#define PAM_IPSET_CALL_FAIL -10

#define DFTL_NUM_GROUPS 10
#define GRP_NAME_LEN 65
#define SET_NAME_LEN 65
#define CONF_LINE_LEN 256
#define MAX_GROUPS 64
#define MAX_CLI_LEN 128
#define MAX_CLI_OUT_LEN 1024

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>  
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

struct ipset_map {
  char *grp_name;
  char *set_name;
};

struct pam_conf {
  char *conf_file;
  char *ipset_path;
  bool debug;
  bool user_match;
  bool group_match;
  bool break_on_match;
  bool create_set;
  bool fail_open;
};

char conf_file[] = "/etc/security/ipset.conf";
char ipset_path[] = "/usr/sbin/ipset";
const char *ipset_list = "-n list";

static void _pam_log(int crit, const char *format, ...) {
  va_list args;

  va_start(args, format);
  openlog("pam_ipset", LOG_PID, LOG_AUTHPRIV);
  vsyslog(crit, format, args);
  va_end(args);
  closelog();
}

int load_ipset_mapping(const char *conf_file, struct ipset_map *ipset_mapping) {
  FILE *fp = NULL;
  unsigned int line_num = 0, grp_num = 0; 
  char grp_name[GRP_NAME_LEN];
  char set_name[SET_NAME_LEN];
  char conf_line[CONF_LINE_LEN];
  struct ipset_map *map = NULL;

  errno = 0;
  if ((fp = fopen(conf_file, "r")) == NULL ) {
    _pam_log(LOG_CRIT, "Unable to read config file %s. %s", conf_file, strerror(errno));
    return PAM_ABORT;
  } else {
    _pam_log(LOG_DEBUG, "Opened %s for reading", conf_file);
  }

  /* Walk the file to grab the group to ipset mappings */
  while(fgets(conf_line, sizeof(conf_line), fp)) {
    ++line_num;
    /* Ignore comments */
    if (conf_line[0] != '#') {
      /* Expecting 2 fields separate by whitespace. Grab 2 first and ignore the end of the line */
      if (sscanf(conf_line, " %s %s ", grp_name, set_name) == 2) {
        _pam_log(LOG_DEBUG, "Got group to ipset mapping at line %u: %s => %s", line_num, grp_name, set_name);
        if ((map = malloc(sizeof(struct ipset_map))) == NULL) {
          _pam_log(LOG_CRIT, "Out of memory. Call to malloc failed at %s:%d", __FILE__, __LINE__);
          return PAM_ABORT;
        }
        map->grp_name = strdup(grp_name);
        map->set_name = strdup(set_name);
        memcpy(&ipset_mapping[grp_num++], map, sizeof(struct ipset_map));
        free(map);
      }
    }
  }
  return grp_num;
}

void free_ipset_mapping(int map_len, struct ipset_map *ipset_mapping) {
  for (int i = 0; i < map_len; i++) {
    struct ipset_map map = ipset_mapping[i];
    free(map.grp_name);
    free(map.set_name);
  }
}

int get_group_list(const char* username, gid_t **groups) {
  int ngroups = (DFTL_NUM_GROUPS);
  struct passwd *user;

  if ((*groups = malloc(ngroups * sizeof(gid_t))) == NULL) {
    _pam_log(LOG_CRIT, "Out of memory. Call to malloc failed at %s:%d", __FILE__, __LINE__);
    return PAM_ABORT;
  }
  
  /* Retrieve the user structure for the username. Contains uid, gid, ... */
  // TODO: Move to getpawnam_r which is thread-safe
  user = getpwnam(username);
  if (user == NULL) {
    _pam_log(LOG_ERR, "Failed to retrieve user structure for user %s", username);
    return PAM_USER_UNKNOWN;
  }
  
  /* Grab the group memberships. If getgrouplist returns -1, then ngroups contains the number of groups
  a user is memberof. Use that value to reallocate an array of the right size */
  if (getgrouplist(username, user->pw_gid, (unsigned int *)*groups, &ngroups) == -1) {
    _pam_log(LOG_DEBUG, "Array is to small to hold all group memberships. User %s is member of %d groups", username, ngroups);
    *groups = realloc(*groups, sizeof(gid_t));
    if (groups == NULL) {
      _pam_log(LOG_CRIT, "Out of memory. Call to malloc failed at %s:%d", __FILE__, __LINE__);
      return PAM_ABORT;
    }
    _pam_log(LOG_DEBUG, "Resized the group array to hold %d group names", ngroups);
    if (getgrouplist(username, user->pw_gid, (unsigned int *)*groups, &ngroups) == -1) {
      _pam_log(LOG_ERR, "Failed to retrieve group memberships for user %s.", username);
      return PAM_PERM_DENIED;
    }
  }
  _pam_log(LOG_INFO, "Successfully retrieved group memberships for username %s", username);
  return ngroups;
}

void free_group_list(gid_t *groups) {
  if (groups != NULL) {
    free(groups);
  }
}

int run_ipset_cmd(const char *ipset_path, const char *ipset_cmd, char **cmd_result) {
  char cmd[MAX_CLI_LEN];
  FILE *fd = NULL;
  if ((*cmd_result = calloc(MAX_CLI_OUT_LEN, sizeof(char))) == NULL) {
    _pam_log(LOG_CRIT, "Out of memory. Call to malloc failed at %s:%d", __FILE__, __LINE__);
    return PAM_ABORT;
  }
  snprintf(&cmd, sizeof(cmd), "%s %s", ipset_path, ipset_cmd);
  if ((fd = popen(cmd, "r")) == NULL) {
    _pam_log(LOG_DEBUG, "Failed to run cmd %s", cmd);
    return PAM_IPSET_CALL_FAIL;
  }
  fread(*cmd_result, sizeof(char), MAX_CLI_OUT_LEN * sizeof(char), fd);
  _pam_log(LOG_DEBUG, "Ipset command: %s returned: %s\n", cmd, *cmd_result);
  return pclose(fd);
}

int insert_ip_set(struct pam_conf *conf, const char *ip, const char *set) {
  char *cmd_out;
  int cmd_ret = 0;
  int arg_len = MAX_CLI_LEN - strlen(conf->ipset_path);
  char arg[arg_len];
  /* Check if the set exists already */
  if ((cmd_ret = run_ipset_cmd(conf->ipset_path, "-n list", &cmd_out)) != 0) {
    if (cmd_ret == PAM_IPSET_CALL_FAIL) {
      _pam_log(LOG_ALERT, "Exec of ipset at path %s failed with error %s", conf->ipset_path, cmd_out);
      free(cmd_out);
      return conf->fail_open ? PAM_IGNORE : PAM_ABORT;
    }
  } 
  if (strstr(cmd_out, set) == NULL) {
    if (conf->create_set) {
      snprintf(arg, arg_len, "create -! %s hash:net", set);
      if ((cmd_ret = run_ipset_cmd(conf->ipset_path, arg, &cmd_out)) != 0) {
        if (cmd_ret == PAM_IPSET_CALL_FAIL) {
          _pam_log(LOG_ALERT, "Exec of ipset at path %s failed with error %s", conf->ipset_path, cmd_out);
          free(cmd_out);
          return conf->fail_open ? PAM_IGNORE : PAM_ABORT;
        }
      }
    } else {
      _pam_log(LOG_ERR, "Ipset %s not found", set);
      return conf->fail_open ? PAM_IGNORE : PAM_ABORT;
    }
  } 
  memset(arg, 0, arg_len);
  snprintf(arg, arg_len, "add -! %s %s", set, ip);
  if ((cmd_ret = run_ipset_cmd(conf->ipset_path, arg, &cmd_out)) != 0) {
    if (cmd_ret == PAM_IPSET_CALL_FAIL) {
      _pam_log(LOG_ALERT, "Exec of ipset at path %s failed with error %s", conf->ipset_path, cmd_out);
      free(cmd_out);
      return conf->fail_open ? PAM_IGNORE : PAM_ABORT;
    }
  }
  _pam_log(LOG_INFO, "Added user ip address %s to set %s successfully", ip, set);
  /* If not error, unless create_set is true */
  free(cmd_out);
  return PAM_IPSET_SUCCESS;
}

/*
 * 
 */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  
  const char *username = "cisco";
  const char *ip = "4.4.4.4";
  gid_t *groups;
  struct group *group;
  struct ipset_map ipset_mapping[MAX_GROUPS] = {{0,0}};
  bool found_match = false, failed_insert = false;;
  int pam_ret = 0;

  struct pam_conf conf = {
                         .conf_file = &conf_file,
                         .ipset_path = &ipset_path,
                         .debug = false,
                         .user_match = false,
                         .group_match = true,
                         .break_on_match = false,
                         .create_set = false,
                         .fail_open = false
                         };

  pam_ret = pam_get_user(pamh, &username, NULL);
  if (pam_ret != PAM_SUCCESS || username == NULL) {
    syslog(LOG_INFO, "Failed to retrieve PAM username");
    return PAM_IGNORE;
  }

  pam_ret = pam_get_item(pamh, PAM_RHOST, &ip);
  if (pam_ret != PAM_SUCCESS || ip == NULL) {
    syslog(LOG_INFO, "Failed to retrieve PAM username");
    return PAM_IGNORE;
  }

  int ngroups = get_group_list(username, &groups); 

  int n_grp_map = load_ipset_mapping(conf_file, ipset_mapping);
  
  if (conf.user_match) {
    for (int i = 0; i < n_grp_map; i++) {
      if (!((conf.break_on_match) && (found_match))) {
        struct ipset_map map = ipset_mapping[i];
        if (strncmp(username, map.grp_name, strlen(username)) == 0) {
          found_match = true;
          _pam_log(LOG_INFO, "Found set match %s for username %s", map.set_name, username);
          if (insert_ip_set(&conf, ip, map.set_name) != 0) {
            _pam_log(LOG_ERR, "Failed to insert ip %s for username %s in set %s", ip, username, map.set_name);
            return conf.fail_open ? PAM_IGNORE : PAM_ABORT;
          } else {
            _pam_log(LOG_INFO, "Inserted ip %s for username %s in set %s", ip, username, map.set_name);
          }
        }
      } else {
        break;
      }
    }
  }
  
  found_match = false;

  if (conf.group_match) {
    for (int i = 0; i < ngroups; i++) {
      if (!((conf.break_on_match) && (found_match))) {
        group = getgrgid(groups[i]);
        for (int j = 0; j < n_grp_map; j++) {
          if (!((conf.break_on_match) && (found_match))) {
            struct ipset_map map = ipset_mapping[j];
            if (strncmp(group->gr_name, map.grp_name, strlen(group->gr_name)) == 0) {
              found_match = true;
              _pam_log(LOG_INFO, "Found set match %s for username %s (group %s)", map.set_name, username, group->gr_name);
              if (insert_ip_set(&conf, ip, map.set_name) != 0) {
                _pam_log(LOG_ERR, "Failed to insert ip %s for username %s in set %s", ip, username, map.set_name);
                failed_insert = true;
              } else {
                _pam_log(LOG_INFO, "Inserted ip %s for username %s in set %s", ip, username, map.set_name);
                failed_insert = false;
              }
            }
          } else {
            break;
          }
        }
      } else {
        break;
      }
    }
  }

  free_ipset_mapping(n_grp_map, ipset_mapping);
  free_group_list(groups);
  if (failed_insert) return conf.fail_open ? PAM_IGNORE : PAM_ABORT; 
  return PAM_SUCCESS;
}

