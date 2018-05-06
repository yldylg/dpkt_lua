--
return {
    utils = require("dpkt.utils"),
    pcap = require("dpkt.pcap"),
    Ethernet = require("dpkt.ethernet"),
    ARP = require("dpkt.arp"),
    IP = require("dpkt.ip"),
    TCP = require("dpkt.tcp"),
    UDP = require("dpkt.udp"),
    Radiotap = require("dpkt.radiotap"),
    Dot11 = require("dpkt.ieee80211"),
    LLC = require("dpkt.llc"),
    EAPOL = require("dpkt.eapol")
}
