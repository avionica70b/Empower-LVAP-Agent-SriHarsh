#include <click/config.h>
#include "packetGenerator.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <click/straccum.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/glue.hh>

CLICK_DECLS

int TOTAL_PACKETS_COUNT = 22;

const unsigned PacketGenerator::NO_LIMIT;

// need a change here
PacketGenerator::PacketGenerator()
    : _task(this), _timer(&_task)
{
    _packets = new Packet *[TOTAL_PACKETS_COUNT];
    for (int i = 0; i < TOTAL_PACKETS_COUNT; i++)
    {
        _packets[i] = 0;
    }
    _current_packet = 0;
}

int PacketGenerator::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String data =
        "Random bullshit in a packet, at least 64 bytes long. Well, now it is.";
    unsigned rate = 10;
    unsigned bandwidth = 0;
    int limit = -1;
    int datasize = -1;
    bool active = true, stop = false;

    // for (auto i : conf)
    // {
    //     click_chatter("This is the data -> %s", i);
    // }

    if (Args(conf, this, errh)
            .read_p("DATA", data)
            .read_p("RATE", rate)
            .read_p("LIMIT", limit)
            .read_p("ACTIVE", active)
            .read("LENGTH", datasize)
            .read("DATASIZE", datasize) // deprecated
            .read("STOP", stop)
            .read("BANDWIDTH", BandwidthArg(), bandwidth)
            .complete() < 0)
        return -1;

    _data = data;

    // click_chatter("This is the _data -> %s",
    //               _data.data());
    // _data.swap(data);
    _datasize = datasize;
    if (bandwidth > 0)
        rate = bandwidth / (_datasize < 0 ? _data.length() : _datasize);
    int burst = rate < 200 ? 2 : rate / 100;
    if (bandwidth > 0 && burst < 2 * datasize)
        burst = 2 * datasize;
    _tb.assign(rate, burst);
    _limit = (limit >= 0 ? unsigned(limit) : NO_LIMIT);
    _active = active;
    _stop = stop;

    setup_packet();

    return 0;
}

int PacketGenerator::initialize(ErrorHandler *errh)
{
    _count = 0;
    _current_packet_count = 0;
    if (output_is_push(0))
        ScheduleInfo::initialize_task(this, &_task, errh);
    _tb.set(1);
    _timer.initialize(this);
    return 0;
}

void PacketGenerator::cleanup(CleanupStage)
{
    for (int i = 0; i < TOTAL_PACKETS_COUNT; i++)
    {
        Packet *_packet = _packets[i];
        if (_packet)
            _packet->kill();
        _packet = 0;
    }
}

void PacketGenerator::setup_packet()
{
    if (_current_packet)
        _current_packet->kill();

    // note: if you change `headroom', change `click-align'
    unsigned int headroom = 16 + 20 + 24;

    String DSCP_CODES[TOTAL_PACKETS_COUNT][2] = {
        {"CS0", "00"},
        {"CS1", "20"},
        {"CS2", "40"},
        {"CS3", "60"},
        {"CS4", "80"},
        {"CS5", "A0"},
        {"CS6", "C0"},
        {"CS7", "E0"},
        {"AF11", "28"},
        {"AF12", "30"},
        {"AF13", "38"},
        {"AF21", "44"},
        {"AF22", "50"},
        {"AF23", "58"},
        {"AF31", "68"},
        {"AF32", "70"},
        {"AF33", "78"},
        {"AF41", "88"},
        {"AF42", "90"},
        {"AF43", "98"},
        {"EF", "B8"},
        {"VOICE-ADMIT", "B0"}};

    for (int i = 0; i < TOTAL_PACKETS_COUNT; i++)
    {

        // to get data type: typeid(variable).name()

        //   _data.swap
        // This is an IP packet, the ones below this are Packets which include Ethernet Header
        // These are packets with Ethernet header
        // _data = "45 " + DSCP_CODES[i][1] + " 00 5B 40 7B 00 00 80 11 D4 08 82 59 A3 B5 FF FF FF FF D5 8E 3E 81 00 47 B4 0E 01 56 69 65 77 41 6C 6C 3E 30 30 30 39 30 30 30 30 34 34 72 47 76 33 4D 30 67 2F 41 70 30 6F 51 6B 42 4A 48 46 33 38 67 6B 37 48 53 66 30 79 58 2B 68 64 56 48 53 2B 57 34 53 4F 36 41 49 3D";
        // _data = "FF FF FF FF FF FF 88 AE DD 02 12 D3 08 00 45 " + DSCP_CODES[i][1] + " 00 5B 40 7B 00 00 80 11 D4 08 82 59 A3 B5 FF FF FF FF D5 8E 3E 81 00 47 B4 0E 01 56 69 65 77 41 6C 6C 3E 30 30 30 39 30 30 30 30 34 34 72 47 76 33 4D 30 67 2F 41 70 30 6F 51 6B 42 4A 48 46 33 38 67 6B 37 48 53 66 30 79 58 2B 68 64 56 48 53 2B 57 34 53 4F 36 41 49 3D";
        // _data = "00 00 C0 AE 67 EF 00 00 00 00 00 00 08 00 45 " + DSCP_CODES[i][1] + " 00 28 00 00 00 00 40 11 77 C3 01 00 00 01 02 00 00 02 13 69 13 69 00 14 D6 41 55 44 50 20 70 61 63 6B 65 74 21 0A";
        // _data = "00 00 C0 AE 67 EF 00 00 00 00 00 00 08 00 45 " + DSCP_CODES[i][1] + " 00 28 00 00 00 00 40 11 77 C3 01 00 00 01 02 00 00 02 13 69 13 69 00 14 D6 41 55 44 50 20 70 61 63 6B 65 74 21 0A 04 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08 00 80 04 08 53 53 00 00 53 53 00 00 05 00 00 00 00 10 00 00 01 00 00 00 54 53 00 00 54 E3 04 08 54 E3 04 08 D8 01 00 00";
        // String trim = _data.trim_space();

        // _data.swap(trim);

        const char *data = _data.data();

        const String printable = _data.printable();
        const String hex = _data.quoted_hex();

        int count = 9;

        char at1 = _data.at(count);
        char at2 = _data.at(count + 1);
        char at3 = _data.at(count + 2);

        // click_chatter("This is the raw data -> %X",
        //               _data.~String());
        // click_chatter("This is the printable -> %s",
        //               printable);
        // click_chatter("This is the hex -> %s",
        //               hex);
        // click_chatter("This is the at1 -> %c",
        //               at1);
        // click_chatter("This is the at2 -> %c",
        //               at2);
        // click_chatter("This is the at3 -> %c",
        //               at3);

        if (_datasize < 0)
            _packets[i] = Packet::make(headroom, (unsigned char *)_data.data(), _data.length(), 0);
        else if (_datasize <= _data.length())
            _packets[i] = Packet::make(headroom, (unsigned char *)_data.data(), _datasize, 0);
        else
        {
            // make up some data to fill extra space
            StringAccum sa;
            while (sa.length() < _datasize)
                sa << _data;
            _packets[i] = Packet::make(headroom, (unsigned char *)sa.data(), _datasize, 0);
        }
    }
}

bool PacketGenerator::run_task(Task *)
{
    if (!_active)
        return false;
    if (_limit != NO_LIMIT && _count >= _limit)
    {
        if (_stop)
            router()->please_stop_driver();
        return false;
    }

    _tb.refill();
    if (_tb.remove_if(1))
    {

        Packet *p = _packets[_current_packet_count]->clone();
        const unsigned char *data = p->data();

        const char dscp_data[2] = {data[3], data[4]};

        // click_chatter("current element count -> %d\n Packet Data -> %s \n DSCP code -> 0x%c%c",
        //               _current_packet_count, data, dscp_data[0], dscp_data[1]);
        click_chatter("%d. DSCP code -> 0x%c%c",
                      _current_packet_count, dscp_data[0], dscp_data[1]);

        _current_packet = _packets[_current_packet_count];
        p->set_timestamp_anno(Timestamp::now());
        output(0).push(p);
        _count++;
        _current_packet_count++;
        if (_current_packet_count == TOTAL_PACKETS_COUNT)
            _current_packet_count = 0;
        _task.fast_reschedule();
        return true;
    }
    else
    {
        _timer.schedule_after(Timestamp::make_jiffies(_tb.time_until_contains(1)));
        return false;
    }
}

String
PacketGenerator::read_param(Element *e, void *vparam)
{
    PacketGenerator *rs = (PacketGenerator *)e;
    switch ((intptr_t)vparam)
    {
    case 0: // data
        return rs->_data;
    case 1: // rate
        return String(rs->_tb.rate());
    case 2: // limit
        return (rs->_limit != NO_LIMIT ? String(rs->_limit) : String("-1"));
    default:
        return "";
    }
}

int PacketGenerator::change_param(const String &s, Element *e, void *vparam,
                                  ErrorHandler *errh)
{
    PacketGenerator *rs = (PacketGenerator *)e;
    switch ((intptr_t)vparam)
    {

    case 0: // data
            //   rs->_data = s;
            //   if (rs->_packet)
            //   rs->_packet->kill();
            //   rs->_packet = Packet::make(rs->_data.data(), rs->_data.length());
        break;

    case 1:
    { // rate
        unsigned rate;
        if (!IntArg().parse(s, rate))
            return errh->error("syntax error");
        rs->_tb.assign_adjust(rate, rate < 200 ? 2 : rate / 100);
        break;
    }

    case 2:
    { // limit
        int limit;
        if (!IntArg().parse(s, limit))
            return errh->error("syntax error");
        rs->_limit = (limit >= 0 ? unsigned(limit) : NO_LIMIT);
        break;
    }

    case 3:
    { // active
        bool active;
        if (!BoolArg().parse(s, active))
            return errh->error("syntax error");
        rs->_active = active;
        if (rs->output_is_push(0) && !rs->_task.scheduled() && active)
        {
            rs->_tb.set(1);
            rs->_task.reschedule();
        }
        break;
    }

    case 5:
    { // reset
        rs->_count = 0;
        rs->_tb.set(1);
        if (rs->output_is_push(0) && !rs->_task.scheduled() && rs->_active)
            rs->_task.reschedule();
        break;
    }

    case 6:
    { // datasize
        int datasize;
        if (!IntArg().parse(s, datasize))
            return errh->error("syntax error");
        rs->_datasize = datasize;
        rs->setup_packet();
        break;
    }
    }
    return 0;
}

void PacketGenerator::add_handlers()
{
    add_read_handler("data", read_param, 0, Handler::f_calm);
    add_write_handler("data", change_param, 0, Handler::f_raw);
    add_read_handler("rate", read_param, 1);
    add_write_handler("rate", change_param, 1);
    add_read_handler("limit", read_param, 2, Handler::f_calm);
    add_write_handler("limit", change_param, 2);
    add_data_handlers("active", Handler::f_read | Handler::f_checkbox, &_active);
    add_write_handler("active", change_param, 3);
    add_data_handlers("count", Handler::f_read, &_count);
    add_write_handler("reset", change_param, 5, Handler::f_button);
    add_data_handlers("length", Handler::f_read, &_datasize);
    add_write_handler("length", change_param, 6);
    // deprecated
    add_data_handlers("datasize", Handler::f_read | Handler::f_deprecated, &_datasize);
    add_write_handler("datasize", change_param, 6);

    if (output_is_push(0))
        add_task_handlers(&_task);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PacketGenerator)
ELEMENT_REQUIRES(userlevel)
