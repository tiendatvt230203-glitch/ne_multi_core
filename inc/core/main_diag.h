#ifndef MAIN_DIAG_H
#define MAIN_DIAG_H

#include <stddef.h>
#include <stdint.h>

struct app_config;

void main_diag_log_loaded_config(struct app_config *cfg, int config_id);
void main_diag_log_link_macs(struct app_config *cfg);
void main_diag_log_lan_client_mac(const char *ifname,
                                  const uint8_t client_mac[6],
                                  const char *event);

void main_diag_log_reload_ok(struct app_config *cfg, int trigger_profile_id);

#endif
