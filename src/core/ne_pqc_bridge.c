#include "../../inc/core/ne_pqc_bridge.h"
#include "../../inc/core/config.h"
#include "pqc_handshake.h"
#include "pqc_l2_handshake.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>

static int profile_uses_pqc(const struct app_config *cfg, const struct profile_config *prof)
{
    if (prof->has_pqc_identity)
        return 1;
    for (int j = 0; j < prof->policy_count; j++) {
        int pi = prof->policy_indices[j];
        if (pi >= 0 && pi < cfg->policy_count &&
            cfg->policies[pi].crypto_mode == CRYPTO_MODE_PQC)
            return 1;
    }
    return 0;
}

int ne_pqc_ensure_profile_binding(int profile_id)
{
    char *lpriv = NULL;
    char *lpub = NULL;
    char *peer = NULL;
    if (sig_pqc_get_profile_keys(profile_id, &lpriv, &lpub, &peer) == 0)
        return 0;
    sig_pqc_bind_profile_keys(profile_id, NULL, NULL, NULL, NULL);
    return 0;
}

int ne_pqc_default_local_fingerprint(char out_fp[16])
{
    if (!out_fp)
        return -1;

    DIR *dir = opendir("/dev/shm/.enc_config");
    if (!dir)
        return -1;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "identity_", 9) == 0 &&
            strstr(entry->d_name, "_priv.key") != NULL) {
            memset(out_fp, 0, 16);
            strncpy(out_fp, entry->d_name + 9, 15);
            closedir(dir);
            return 0;
        }
    }
    closedir(dir);
    return -1;
}

bool ne_pqc_profile_binding_key_ready(int profile_id)
{
    uint8_t probe[PQC_TRAFFIC_KEY_SZ];
    return sig_pqc_diversify_key(profile_id, 0, probe) == 0;
}

void ne_pqc_runtime_setup_profiles(struct app_config *cfg)
{
    if (!cfg)
        return;

    for (int p_idx = 0; p_idx < cfg->profile_count; p_idx++) {
        struct profile_config *prof = &cfg->profiles[p_idx];
        if (!profile_uses_pqc(cfg, prof))
            continue;

        ne_pqc_ensure_profile_binding(prof->id);

        char local_fp[16] = {0};
        if (prof->local_identity_fingerprint[0] != '\0')
            strncpy(local_fp, prof->local_identity_fingerprint, sizeof(local_fp) - 1);
        else if (ne_pqc_default_local_fingerprint(local_fp) == 0)
            strncpy(prof->local_identity_fingerprint, local_fp,
                    sizeof(prof->local_identity_fingerprint) - 1);

        char *lpriv = NULL;
        char *lpub = NULL;
        if (local_fp[0] != '\0' && sig_pqc_find_identity(local_fp, &lpriv, &lpub) == 0) {
            if (prof->has_pqc_identity && prof->pqc_peer_pub[0] != '\0')
                sig_pqc_bind_profile_keys(prof->id, lpriv, lpub, prof->pqc_peer_pub,
                                        prof->peer_fingerprint[0] ? prof->peer_fingerprint : NULL);
            fprintf(stderr, "[PQC-BIND] Profile %d identity ready (local fp=%s)\n", prof->id, local_fp);
        }

        if (prof->has_pqc_identity && prof->pqc_peer_pub[0] != '\0')
            sig_pqc_set_peer_identity(prof->pqc_peer_pub,
                                      prof->peer_fingerprint[0] ? prof->peer_fingerprint : NULL);
    }
}

void ne_pqc_start_handshakes(struct app_config *cfg)
{
    if (!cfg)
        return;

    for (int p_idx = 0; p_idx < cfg->profile_count; p_idx++) {
        const struct profile_config *prof = &cfg->profiles[p_idx];
        if (!profile_uses_pqc(cfg, prof))
            continue;

        char peer_ip_str[64] = "0.0.0.0";
        const char *wan_ifname = "";
        pqc_get_profile_handshake_params(cfg, p_idx, peer_ip_str, &wan_ifname);
        if (!wan_ifname || wan_ifname[0] == '\0')
            continue;

        char local_fp[16] = {0};
        if (prof->local_identity_fingerprint[0] != '\0')
            strncpy(local_fp, prof->local_identity_fingerprint, sizeof(local_fp) - 1);
        else
            (void)ne_pqc_default_local_fingerprint(local_fp);

        sig_pqc_set_handshake_config(prof->id, prof->pqc_is_initiator != 0,
                                     peer_ip_str, local_fp[0] ? local_fp : NULL, wan_ifname);
        sig_pqc_handshake_start(prof->id, wan_ifname, peer_ip_str);
    }
}
