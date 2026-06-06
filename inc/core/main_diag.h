#ifndef MAIN_DIAG_H
#define MAIN_DIAG_H

#include <stdint.h>

struct app_config;

void main_diag_log_db_apply(const struct app_config *cfg, int trigger_profile_id,
                            const struct app_config *prev_cfg);
/* DB notify when only policies/profiles changed (LAN client MAC is lan_neigh, not Postgres). */
void main_diag_log_db_policy_apply(const struct app_config *cfg, int trigger_profile_id,
                                   const struct app_config *prev_cfg);
void main_diag_log_no_update(int trigger_profile_id, const struct app_config *cfg);
void main_diag_log_config_summary(struct app_config *cfg, int trigger_profile_id,
                                  int is_reload, int policy_only);
void main_diag_log_dataplane_ready(struct app_config *cfg);
void main_diag_log_local_port_macs(const struct app_config *cfg);
void main_diag_log_lan_neigh_event(const char *ifname, uint32_t client_ip,
                                   const uint8_t old_mac[6],
                                   const uint8_t new_mac[6],
                                   const char *event);

void main_diag_log_lan_neigh_resolve(const char *ifname, uint32_t client_ip,
                                     const uint8_t client_mac[6],
                                     const char *via);

#endif
