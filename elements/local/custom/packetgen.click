// packets :: PacketGenerator( DATA \<
// //   // Ethernet header
//   08 00 c0 ae 67 ef  00 00 00 00 00 00  08 00
//   // IP header
//   45 00 00 28  00 00 00 00  40 11 77 c3  01 00 00 01  02 00 00 02
//   // UDP header
//   13 69 13 69  00 14 d6 41
//   // UDP payload
//   55 44 50 20  70 61 63 6b  65 74 21 0a  04 00 00 00  01 00 00 00  
//   01 00 00 00  00 00 00 00  00 80 04 08  00 80 04 08  53 53 00 00
//   53 53 00 00  05 00 00 00  00 10 00 00  01 00 00 00  54 53 00 00
//   54 e3 04 08  54 e3 04 08  d8 01 00 00
// >, LIMIT 22, STOP true, RATE 1);

// packets :: RatedSource( DATA \<
// FF FF FF FF FF FF 88 AE DD 02 12 D3 08 00 45 00 00 5B 40 7B 00 00 80 11 D4 08 82 59 A3 B5 FF FF FF FF D5 8E 3E 81 00 47 B4 0E 01 56 69 65 77 41 6C 6C 3E 30 30 30 39 30 30 30 30 34 34 72 47 76 33 4D 30 67 2F 41 70 30 6F 51 6B 42 4A 48 46 33 38 67 6B 37 48 53 66 30 79 58 2B 68 64 56 48 53 2B 57 34 53 4F 36 41 49 3D
// >, LIMIT 22, STOP true, RATE 1);

// packets :: PacketGenerator( DATA \<
// FF FF FF FF FF FF 88 AE DD 02 12 D3 08 00 45 00 00 5B 40 7B 00 00 80 11 D4 08 82 59 A3 B5 FF FF FF FF D5 8E 3E 81 00 47 B4 0E 01 56 69 65 77 41 6C 6C 3E 30 30 30 39 30 30 30 30 34 34 72 47 76 33 4D 30 67 2F 41 70 30 6F 51 6B 42 4A 48 46 33 38 67 6B 37 48 53 66 30 79 58 2B 68 64 56 48 53 2B 57 34 53 4F 36 41 49 3D
// >, LIMIT 22, STOP true, RATE 1);

// packets :: FromDevice(wlp4s0);
// packets :: FromDump(/home/sriharsh/Thesis/5G-Empower/empower-lvap-agent/elements/local/custom/tcpdump.pcap);
// packets :: FromTcpdump("-");
// SetIPDSCP
// CheckIPHeader
// IPPrint requires CheckIPHeader or similar element to exist where valid packets go to port 0 and invalid packets go to port 1,
// IPPrint(CONTENTS ASCII, PAYLOAD false, TOS true)
// MarkIPHeader(OFFSET 14) -> 

// packets :: PacketGenerator(LIMIT 22, STOP true, RATE 1);
checker :: CheckIPHeader2(OFFSET 14, VERBOSE  true)

// https://www.bytesolutions.com/dscp-tos-cos-presidence-conversion-chart/
// SetIPDSCP sets the dscp in the decimal format which can be viewed using IPPrint which can show the tos in decimal 

// packets -> MarkIPHeader(OFFSET 0) -> SetIPDSCP(0x20) -> Print(CONTENTS ASCII, MAXLENGTH 43, HEADROOM false, PRINTANNO false) -> Discard();
FromDevice(wlx00e0270073ed, PROMISC false, OUTBOUND true, SNIFFER false, BURST 1000) -> MarkIPHeader(OFFSET 14) ->  checker 
    // -> SetIPDSCP(10) 
    // -> TrafficRules()
    // -> Print(TIMESTAMP false, CONTENTS HEX, MAXLENGTH 16, HEADROOM false, PRINTANNO false) 
    // -> IPPrint(TOS true) 
    -> DSCPStats()
    -> Discard();
// packgen  -> MarkIPHeader(OFFSET 14) ->  checker :: CheckIPHeader2(OFFSET 14, VERBOSE  true) -> SetIPDSCP(0x20) -> Print(CONTENTS ASCII, MAXLENGTH 5, HEADROOM false, PRINTANNO true) -> Discard();
checker [1] -> Print("Discarded", CONTENTS ASCII, MAXLENGTH 5, PRINTANNO false) -> Discard();