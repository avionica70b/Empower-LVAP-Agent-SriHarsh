#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/router.hh>
// #include <click/straccum.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/glue.hh>
#include <click/hashmap.hh>
#include <click/ipaddress.hh>
#include <clicknet/ip.h>
#include <clicknet/icmp.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/ether.h>
#include "dscpstats.hh"

CLICK_DECLS

DSCPStats::DSCPStats() : packet_count(0)
{
    // click_chatter("dscp stats constructor");
}
DSCPStats::~DSCPStats() {}

int DSCPStats::initialize(ErrorHandler *errh)
{
    return 0;
}
void DSCPStats::cleanup(CleanupStage)
{
    dscpMap.clear();
    dscpStat.clear();
}

int DSCPStats::statsSize()
{
    return dscpStat.size();
}

int DSCPStats::mapSize()
{
    return dscpMap.size();
}

Vector<DSCPStat> DSCPStats::getStats()
{
    return dscpStat;
}

void DSCPStats::printDSCPMap()
{
    // click_chatter("Length of HashMap: %d", dscpMap.size());

    for (HashMap<uint8_t, uint32_t>::iterator it = dscpMap.begin(); it.live(); it++)
    {
        // click_chatter("Key %d: %d", it.key(), it.value());
    }
}

void DSCPStats::push(int port, Packet *p)
{

    if (!p->has_network_header())
        return;

    packet_count += 1;

    update_packet_stats(p);
    update_dscp_stats(p);

    // printDSCPMap();
    output(0).push(p);
}

uint32_t DSCPStats::get_packes_length(uint8_t dscp)
{
    return packet_size_map.find(dscp);
}

void DSCPStats::update_dscp_stats(Packet *p)
{
    const click_ip *iph = p->ip_header();
    uint8_t packet_dscp = iph->ip_tos >> 2; // Gets the DSCP Decimal
    uint8_t dscp_code = dscpMap.find(packet_dscp);
    uint32_t length = p->length();

    if (!dscp_code && dscp_code != 0)
    {
        dscpMap.insert(packet_dscp, 1);
        packet_size_map.insert(packet_dscp, length);
        // click_chatter("The DSCP was not found before");
    }
    else
    {
        uint32_t current_count = dscpMap.find(packet_dscp) + 1;
        dscpMap.insert(packet_dscp, current_count);
        uint32_t current_length = packet_size_map.find(packet_dscp) + length;
        packet_size_map.insert(packet_dscp, current_length);
        // click_chatter("The DSCP was found before");
    }
}

void DSCPStats::update_packet_stats(Packet *p)
{

    DSCPStat stat;

    const click_ip *iph = p->ip_header();

    stat.dscp = iph->ip_tos >> 2; // Gets the DSCP Deceimal
    stat.protocol = iph->ip_p;
    stat.src_ip = iph->ip_src;
    stat.dst_ip = iph->ip_dst;

    if (stat.protocol == IP_PROTO_TCP)
    {
        const click_tcp *tcph = p->tcp_header();
        stat.src_port = ntohs(tcph->th_sport);
        stat.dst_port = ntohs(tcph->th_dport);
    }
    else if (stat.protocol == IP_PROTO_UDP)
    {
        const click_udp *udph = p->udp_header();
        stat.src_port = ntohs(udph->uh_sport);
        stat.dst_port = ntohs(udph->uh_dport);
    }

    // stat.print();
    dscpStat.push_back(stat);
}

HashMap<uint8_t, uint32_t> DSCPStats::getDSCPMap()
{
    return dscpMap;
}

void DSCPStats::clearStats()
{
    dscpStat.clear();
    packet_size_map.clear();
    dscpMap.clear();
    packet_count = 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DSCPStats)
ELEMENT_REQUIRES(userlevel)