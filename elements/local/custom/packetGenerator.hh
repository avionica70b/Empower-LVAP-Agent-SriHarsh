#ifndef CLICK_PACKETGENERATOR__HH
#define CLICK_PACKETGENERATOR__HH

#include <click/element.hh>
#include <click/tokenbucket.hh>
#include <click/task.hh>

CLICK_DECLS


class PacketGenerator : public Element
{

public:
    PacketGenerator() CLICK_COLD;
    // ~PacketGenerator();

    const char *class_name() const { return "PacketGenerator"; }
    const char *port_count() const { return PORTS_0_1; }
    const char *processing() const { return AGNOSTIC; }
    void add_handlers() CLICK_COLD;

    // Packet *simple_action(Packet *p);

    int configure(Vector<String> &conf, ErrorHandler *errh) CLICK_COLD;
    int initialize(ErrorHandler *errh) CLICK_COLD;
    void cleanup(CleanupStage) CLICK_COLD;

    bool run_task(Task *task);
    // Packet *pull(int);

protected:
    static const unsigned NO_LIMIT = 0xFFFFFFFFU;

    TokenBucket _tb;
    unsigned _count;
    unsigned _limit;
    int _datasize;
    bool _active;
    bool _stop;
    Packet **_packets;
    Packet *_current_packet;
    int _current_packet_count;
    Task _task;
    Timer _timer;
    String _data;

    void setup_packet();

    static String read_param(Element *, void *) CLICK_COLD;
    static int change_param(const String &, Element *, void *, ErrorHandler *);
};

CLICK_ENDDECLS

#endif