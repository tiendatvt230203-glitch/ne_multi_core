#include "../../inc/core/mac_learn.h"

#include <string.h>

static int find_idx(const struct mac_learn_table *t, const char *ifname)
{
    for (int i = 0; i < t->count; i++) {
        if (strcmp(t->list[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

void mac_learn_init(struct mac_learn_table *t)
{
    if (t)
        memset(t, 0, sizeof(*t));
}

void mac_learn_add(struct mac_learn_table *t, const char *ifname, const uint8_t mac[MAC_LEN])
{
    if (!t || !ifname || !ifname[0] || !mac)
        return;
    if (find_idx(t, ifname) >= 0 || t->count >= MAX_INTERFACES)
        return;

    strncpy(t->list[t->count].ifname, ifname, IF_NAMESIZE - 1);
    t->list[t->count].ifname[IF_NAMESIZE - 1] = '\0';
    memcpy(t->list[t->count].mac, mac, MAC_LEN);
    t->count++;
}

void mac_learn_edit(struct mac_learn_table *t, const char *ifname, const uint8_t mac[MAC_LEN])
{
    int i;

    if (!t || !ifname || !ifname[0] || !mac)
        return;
    i = find_idx(t, ifname);
    if (i < 0)
        return;
    memcpy(t->list[i].mac, mac, MAC_LEN);
}

void mac_learn_delete(struct mac_learn_table *t, const char *ifname)
{
    int i;

    if (!t || !ifname || !ifname[0])
        return;
    i = find_idx(t, ifname);
    if (i < 0)
        return;

    if (i + 1 < t->count)
        memmove(&t->list[i], &t->list[i + 1],
                (size_t)(t->count - i - 1) * sizeof(t->list[0]));
    memset(&t->list[t->count - 1], 0, sizeof(t->list[0]));
    t->count--;
}

// Hàm lúc traffic match policy và kiểm tra traffic này đang chưa biết mac là gì thì
// sẽ tự động đẩy gói tin đó lên toàn bộ interface local (hoạt động y chang sw khi chưa biết được mac)

// Hàm học mac khi gói tin từ local đi lên nhưng chỉ học những gói tin match policy(arp,tcp,udp,icmp,...)

// Hàm tự động Flooding khi chưa biết mac của thiết bị local là gì



