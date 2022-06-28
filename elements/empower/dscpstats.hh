#ifndef CLICK_DSCPSTATS__HH
#define CLICK_DSCPSTATS__HH

#include <click/element.hh>
#include <click/tokenbucket.hh>
#include <click/task.hh>
#include <click/hashmap.hh>
#include <click/straccum.hh>
// #include <click/router.hh>
#include <click/error.hh>

#include <click/etheraddress.hh>

#define _BSD_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

CLICK_DECLS

class DSCPStat
{
public:
    ErrorHandler *_errh;
    DSCPStat()
    {
        // src_mac = EtherAddress();
        src_ip = in_addr();
        src_port = 0;
        // dst_mac = EtherAddress();
        dst_ip = in_addr();
        dst_port = 0;
        dscp = 0;
        int protocol = 0;
        // const Router *router = Element::router;
        // _errh = router->chatter_channel("default");
    }
    ~DSCPStat(){};

    // EtherAddress get_src_mac_add()
    // {
    //     return this.src_mac;
    // }

    // in_add get_src_ip_add()
    // {
    //     return this->src_ip;
    // }

    // int get_src_port()
    // {
    //     return src_port;
    // }

    // EtherAddress get_dst_mac_add()
    // {
    //     return this.dst_mac;
    // }

    // in_add get_dst_ip_add()
    // {
    //     return this->dst_ip;
    // }

    // int get_dst_port()
    // {
    //     return dst_port;
    // }

    void print()
    {
        // click_chatter("Printing...");
        click_chatter("Source IP: %s", inet_ntoa(src_ip));
        click_chatter("Desctination Ip: %s", inet_ntoa(dst_ip));
        click_chatter("Source Port: %d", src_port);
        click_chatter("Destination Port: %d", dst_port);
        click_chatter("Protocol: %d", protocol);
        click_chatter("DSCP: %d", dscp);
        click_chatter("\n\n");
        // click_chatter("Done...");
    }
    // private:
    // src mac add - EtherAddress
    // EtherAddress src_mac;
    // src ip add - uint32_t, IPAddress
    in_addr src_ip;
    uint16_t src_port;
    // EtherAddress dst_mac;
    // dest ip add - in_addr
    in_addr dst_ip;
    uint16_t dst_port;
    uint8_t dscp;
    uint8_t protocol;
};

class DSCPStats : public Element
{

public:
    DSCPStats();
    ~DSCPStats();

    const char *class_name() const { return "DSCPStats"; }
    const char *port_count() const { return PORTS_1_1; }
    const char *processing() const { return PUSH; }
    // void add_handlers() CLICK_COLD;

    void push(int, Packet *);
    // Packet *simple_action(Packet *);

    // int configure(Vector<String> &conf, ErrorHandler *errh) CLICK_COLD;
    int initialize(ErrorHandler *errh);
    void cleanup(CleanupStage);

    int statsSize();
    int mapSize();
    Vector<DSCPStat> getStats();
    HashMap<uint8_t, uint32_t> getDSCPMap();
    uint32_t get_packes_length(uint8_t dscp);
    void clearStats();

    void update_packet_stats(Packet *p);
    void update_dscp_stats(Packet *p);
    void printDSCPMap();

    // bool run_task(Task *task);
    // Packet *pull(int);

private:
    HashMap<uint8_t, uint32_t> dscpMap;
    HashMap<uint8_t, uint32_t> packet_size_map;
    Vector<DSCPStat> dscpStat;
    uint32_t packet_count;

    // static String read_param(Element *, void *) CLICK_COLD;
    // static int change_param(const String &, Element *, void *, ErrorHandler *);

    
};

CLICK_ENDDECLS

#endif