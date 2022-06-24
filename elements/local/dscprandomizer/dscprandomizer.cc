#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <click/ipaddress.hh>
#include <clicknet/ip.h>
#include "dscprandomizer.hh"

CLICK_DECLS

DscpRandomizer::DscpRandomizer()
{
}

void DscpRandomizer::push(int port, Packet *p)
{
    int tos_array[] = {0,
                       32,
                       64,
                       96,
                       128,
                       160,
                       192,
                       224,
                       40,
                       48,
                       56,
                       72,
                       80,
                       88,
                       104,
                       112,
                       120,
                       136,
                       144,
                       152,
                       184,
                       176};
    assert(p->has_network_header());
    WritablePacket *q;
    if (!(q = p->uniqueify()))
        return;
    click_ip *iph = q->ip_header();
    uint16_t old_hw = (reinterpret_cast<uint16_t *>(iph))[0];
    int n = sizeof(tos_array) / sizeof(tos_array[0]);
    int index = (rand() % static_cast<int>(n + 1));
    int new_dscp = tos_array[index];
    iph->ip_tos = (iph->ip_tos & 0x3) | new_dscp;
    click_update_in_cksum(&iph->ip_sum, old_hw, reinterpret_cast<uint16_t *>(iph)[0]);
    output(0).push(q);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DscpRandomizer)
ELEMENT_REQUIRES(userlevel)