#ifndef WAN_IPC_H
#define WAN_IPC_H

typedef const struct app_config *(*wan_ipc_cfg_fn)(void);

int wan_ipc_handle_cli(int argc, char **argv);

void wan_ipc_set_cfg_provider(wan_ipc_cfg_fn fn);
void wan_ipc_start_server(void);
void wan_ipc_cleanup(void);

#endif
