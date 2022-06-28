elementclass RateControl {
  $rates|

  filter_tx :: FilterTX()

  input -> filter_tx -> output;

  rate_control :: Minstrel(OFFSET 4, TP $rates);
  filter_tx [1] -> [1] rate_control [1] -> Discard();
  input [1] -> rate_control -> [1] output;

};

ControlSocket("TCP", 7777);

ers :: EmpowerRXStats(EL el);

// Traffic Rule and DSCP stats
dscpStats :: DSCPStats();
traffic_rules :: TrafficRules();

// Data classifier might not work, then use 0/ff since IP packets contain ff at 0
wifi_cl :: Classifier(0/08%0c,  // data
                      0/00%0c); // mgt

ers -> wifi_cl;

tee :: EmpowerTee(1, EL el);
checker :: CheckIPHeader2(OFFSET 14, VERBOSE  true)
switch_mngt :: PaintSwitch();


// Might have to change DEBUGFS to /dev/regmon and create a regmon folder and register-log
// /sys/kernel/debug/ieee80211/phy0/regmon
reg_0 :: EmpowerRegmon(EL el, IFACE_ID 0, DEBUGFS /dev/regmon );
rates_default_0 :: TransmissionPolicy(MCS "2 4 11 22 12 18 24 36 48 72 96 108", HT_MCS "0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15");
rates_0 :: TransmissionPolicies(DEFAULT rates_default_0); 

rc_0 :: RateControl(rates_0);
eqm_0 :: EmpowerQOSManager(EL el, RC rc_0/rate_control, IFACE_ID 0, DEBUG true);

// change the interface
// SNIFFER duplicate the packet from interface to inbound- true for virtual testing
// OUTBOUND sends packets to interface, false for virtual testing
// FromDevice(moni0, PROMISC false, OUTBOUND true, SNIFFER false, BURST 1000)
RatedSource( DATA \<
FF FF FF FF FF FF 88 AE DD 02 12 D3 08 00 45 B8 
00 5B 40 7B 00 00 80 11 D4 08 82 59 A3 B5 FF FF FF FF D5 8E 3E 81 00 47 B4 0E 01 56 69 65 77 41 6C 6C 3E 30 30 30 39 30 30 30 30 34 34 72 47 76 33 4D 30 67 2F 41 70 30 6F 51 6B 42 4A 48 46 33 38 67 6B 37 48 53 66 30 79 58 2B 68 64 56 48 53 2B 57 34 53 4F 36 41 49 3D
>, LIMIT 30, STOP true, RATE 1)
//   -> RadiotapDecap()
  -> FilterPhyErr()
  -> rc_0
  -> WifiDupeFilter()
  -> Paint(0)
  -> ers;

sched_0 :: PrioSched()
  -> WifiSeq()
  -> [1] rc_0 [1]
//   -> RadiotapEncap()
  // Change interface
//   -> ToDevice (moni0);
    -> Discard()

switch_mngt[0]
  -> Queue(50)
  -> [0] sched_0;

tee[0]
  // Traffic Rules and DSCP stats
  -> checker
  -> SetIPDSCP(48) // This is in DSCP decemal 
  -> IPPrint(TOS true) 
  -> dscpStats
  -> traffic_rules
  -> IPPrint(TOS true)
  -> MarkIPHeader(14)
  -> Paint(0)
  -> eqm_0
  -> [1] sched_0;

// DEV_NAME is deprecated -  DEV_NAME empower0
// 10.0.0.1/24
kt :: KernelTap(10.53.239.2/16, BURST 500)
  -> tee;

// Change IP Address to that of COntroller 
ctrl :: Socket(TCP, 127.0.0.1, 4433, CLIENT true, VERBOSE true, RECONNECT_CALL el.reconnect)
    -> el :: EmpowerLVAPManager(WTP 00:0D:B9:5E:04:1C,
                                // Bridge argument is unknown - remove in testing
                                // BRIDGE_DPID 0000000db92f5664,
                                EBS ebs,
                                EAUTHR eauthr,
                                EASSOR eassor,
                                EDEAUTHR edeauthr,
                                MTBL mtbl,
                                E11K e11k,
                                RES " 04:F0:21:09:F9:98/1/HT20",
                                RCS " rc_0/rate_control",
                                PERIOD 5000,
                                DEBUGFS " /sys/kernel/debug/ieee80211/phy0/netdev:moni0/../ath9k/bssid_extra",
                                ERS ers,
                                EQMS " eqm_0",
                                REGMONS " reg_0",
                                // Add DSCP stats and Traffic rule to LVAP man.
                                DSCP dscpStats,
                                TR traffic_rules,
                                DEBUG true)
    -> ctrl;

  mtbl :: EmpowerMulticastTable(DEBUG true);

  wifi_cl [0]
    -> wifi_decap :: EmpowerWifiDecap(EL el, DEBUG true)
    -> MarkIPHeader(14)
    -> igmp_cl :: IPClassifier(igmp, -);

  igmp_cl[0]
    -> EmpowerIgmpMembership(EL el, MTBL mtbl, DEBUG true)
    -> Discard();

  igmp_cl[1]
    -> kt;

  wifi_decap [1] -> tee;

  wifi_cl [1]
    -> mgt_cl :: Classifier(0/40%f0,  // probe req
                            0/b0%f0,  // auth req
                            0/00%f0,  // assoc req
                            0/20%f0,  // reassoc req
                            0/c0%f0,  // deauth
                            0/a0%f0,  // disassoc
                            0/d0%f0); // action

  mgt_cl [0]
    -> ebs :: EmpowerBeaconSource(EL el, DEBUG true)
    -> switch_mngt;

  mgt_cl [1]
    -> eauthr :: EmpowerOpenAuthResponder(EL el, DEBUG true)
    -> switch_mngt;

  mgt_cl [2]
    -> eassor :: EmpowerAssociationResponder(EL el, DEBUG true)
    -> switch_mngt;

  mgt_cl [3]
    -> eassor;

  mgt_cl [4]
    -> edeauthr :: EmpowerDeAuthResponder(EL el, DEBUG true)
    -> switch_mngt;

  mgt_cl [5]
    -> EmpowerDisassocResponder(EL el, DEBUG true)
    -> Discard();

  mgt_cl [6]
    -> e11k :: Empower11k(EL el, DEBUG true)
    -> switch_mngt;
