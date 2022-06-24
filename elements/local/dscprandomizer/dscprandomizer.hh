#ifndef CLICK_DSCPRANDOMIZER__HH
#define CLICK_DSCPRANDOMIZER__HH

#include <click/element.hh>

CLICK_DECLS

class DscpRandomizer : public Element
{
public:
    DscpRandomizer() CLICK_COLD;

    const char *class_name() const { return "DscpRandomizer"; }
    const char *port_count() const { return PORTS_1_1; }
    const char *processing() const { return PUSH; }

    void push(int port, Packet *p);


private:
};

CLICK_ENDDECLS

#endif
