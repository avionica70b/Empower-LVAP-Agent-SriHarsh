#ifndef CLICK_TRAFFICRULES_HH
#define CLICK_TRAFFICRULES__HH
struct empower_traffic_rule_match;
#pragma once

#include <click/element.hh>
#include <click/tokenbucket.hh>
#include <click/task.hh>
#include <click/hashtable.hh>
#include <click/hashmap.hh>
#include <click/straccum.hh>
// #include <click/router.hh>
#include <click/error.hh>
// #include <click/etheraddress.hh>
#include "empowerpacket.hh"
CLICK_DECLS

class TrafficRules : public Element
{
public:
    // template< typename  empower_traffic_rule_match>

    TrafficRules();
    ~TrafficRules();

    const char *class_name() const { return "TrafficRules"; }
    const char *port_count() const { return PORTS_1_1; }
    const char *processing() const { return PUSH; }
    // void add_handlers() CLICK_COLD;
    void cleanup(CleanupStage);
    Packet *smaction(Packet *);
    void push(int, Packet *p);

    empower_traffic_rule_match makePacketMatch(WritablePacket *q);

    void add_traffic_rule(uint8_t dscp, empower_traffic_rule_match match);

    int initialize(ErrorHandler *errh); 

private:
    HashMap<empower_traffic_rule_match, uint8_t> traffic_rules;
};

CLICK_ENDDECLS

#endif