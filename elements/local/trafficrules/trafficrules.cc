#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/router.hh>
// #include <click/straccum.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/glue.hh>
#include <click/hashtable.hh>
#include <click/ipaddress.hh>
#include <clicknet/ip.h>
#include <clicknet/icmp.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/ether.h>
#include "trafficrules.hh"

CLICK_DECLS

/*
TR will have a table
There will be a function which would be called from Lvap to add the TR match and action
This function has to add the TR to the table
But before that, check if it already exists
    -> if yes, update it
    -> if no, insert it
*/

TrafficRules::TrafficRules() {
    // click_chatter("Traffic rules constructor");
}

TrafficRules::~TrafficRules() {}

int TrafficRules::initialize(ErrorHandler *errh) { return 0; }

void TrafficRules::cleanup(CleanupStage) {}

empower_traffic_rule_match TrafficRules::makePacketMatch(WritablePacket *q)
{
    empower_traffic_rule_match match;
    click_ip *iph = q->ip_header();
    match.set_src_ip(iph->ip_src);
    match.set_dst_ip(iph->ip_dst);
    match.set_protocol(iph->ip_p);
    match.set_dscp(iph->ip_tos >> 2);

    if (match.get_protocol() == IP_PROTO_TCP)
    {
        // click_chatter("the packet was  ip");
        const click_tcp *tcph = q->tcp_header();
        match.set_src_port(ntohs(tcph->th_sport));
        match.set_dst_port(ntohs(tcph->th_dport));
    }
    else if (match.get_protocol() == IP_PROTO_UDP)
    {
        // click_chatter("the packet was udp");
        const click_udp *udph = q->udp_header();
        match.set_src_port(ntohs(udph->uh_sport));
        match.set_dst_port(ntohs(udph->uh_dport));
    }
    // click_chatter("made a match struct ");
    // match.print();
    return match;
}

inline Packet *TrafficRules::smaction(Packet *p)
{
    assert(p->has_network_header());
    if (traffic_rules.size() == 0)
        return p;
    // click_chatter("in the smaction function with traffic_rule size %d", traffic_rules.size());
    WritablePacket *q;
    if (!(q = p->uniqueify()))
        return p;
    click_ip *iph = q->ip_header();
    if (iph->ip_p != IP_PROTO_TCP && iph->ip_p != IP_PROTO_UDP)
    {
        click_chatter("packet is somethjing else %d while upd is %d", iph->ip_p, IP_PROTO_UDP);
        return q;
    }
    empower_traffic_rule_match match = makePacketMatch(q);
    if (!match)
        return q;

    // second parameter is the default value if no match is found
    uint8_t new_dscp = match.get_dscp();
    for (HashMap<empower_traffic_rule_match, uint8_t>::iterator it = traffic_rules.begin(); it.live(); it++)
    {
        empower_traffic_rule_match m = it.key();
        // m.print();
        if (match == m)
        {
            new_dscp = it.value();
            break;
        }
    }
    // uint8_t new_dscp = traffic_rules.find(match, match.get_dscp());
    // click_chatter("The new dscp is %d", new_dscp );
    if (new_dscp != match.get_dscp())
    {
        uint8_t dscp_dec = new_dscp >> 2;
        click_chatter("found a match with old DSCP %d and new DSCP %d", match.get_dscp(), dscp_dec);
        uint16_t old_hw = (reinterpret_cast<uint16_t *>(iph))[0];
        iph->ip_tos = (iph->ip_tos & 0x3) | new_dscp; // This needs to be DSCP decimal
        click_update_in_cksum(&iph->ip_sum, old_hw, reinterpret_cast<uint16_t *>(iph)[0]);
    }

    // click_chatter("done with the packet");

    return q;
}

void TrafficRules::push(int, Packet *p)
{
    if ((p = smaction(p)) != 0)
        output(0).push(p);
}

void TrafficRules::add_traffic_rule(uint8_t dscp, empower_traffic_rule_match match)
{
    click_chatter("change DSCP code from %d to %d", match.get_dscp(), dscp >> 2);
    // match.print();
    traffic_rules.insert(match, dscp);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(TrafficRules)
ELEMENT_REQUIRES(userlevel)