#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>
#include<net/ethernet.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<unistd.h>
#include<signal.h>

#define XML_HEADER "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
 
void PrintPacket(unsigned char* buff, int size);

volatile int exiting = 0;
FILE *output;

void intHandler(int sig) {
    exiting = 1;
    printf("\nexiting...\n");
    fprintf(output , "</packets>\n");
    fclose(output);
    exit(0);
}


int main() {
    
    int data_size;

    struct sigaction act;
    act.sa_handler = intHandler;
         
    unsigned char *buffer = (unsigned char *) malloc(65536);
     
    output=fopen("out.xml","w");
    if(output==NULL){
        printf("Failed to create out.xml file.\n");
    }

    fprintf(output, XML_HEADER);
    fprintf(output , "<packets>\n");

    sigaction(SIGINT, &act, NULL);
     
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
     
    if(sock_raw < 0){
        perror("Failed to create socket.\n");
        return 1;
    }
    for(;;){
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , NULL, NULL);
        if(data_size <0 ){
            printf("Failed to receive packets.\n");
            close(sock_raw);
            fclose(output);
            return 1;
        }
        PrintPacket(buffer , data_size);
    }
    return 0;
}

void PrintPacket(unsigned char* buffer, int size)
{
    struct sockaddr_in source, dest;
    
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct iphdr  *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    if(!exiting){
        // Print packet to xml file
        fprintf(output , "\t<packet>\n");
        // IP source and destination
        fprintf(output , "\t\t<source-IP>%s</source-IP>\n",inet_ntoa(source.sin_addr));
        fprintf(output , "\t\t<destination-IP>%s</destination-IP>\n",inet_ntoa(dest.sin_addr));

        // MAC source and destination
        fprintf(output , "\t\t<source-MAC>%.2X-%.2X-%.2X-%.2X-%.2X-%.2X</source-MAC>\n", 
            eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
        fprintf(output , "\t\t<destination-MAC>%.2X-%.2X-%.2X-%.2X-%.2X-%.2X</destination-MAC>\n", 
            eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);

        // IP protocol
        fprintf(output , "\t\t<IP-protocol>%d</IP-protocol>\n",(unsigned int)iph->protocol);

        if(6 == iph->protocol){
            //  TCP
            struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
            // ports
            fprintf(output , "\t\t<source-port>%u</source-port>\n",ntohs(tcph->source));
            fprintf(output , "\t\t<destination-port>%u</destination-port>\n",ntohs(tcph->dest));
            // flags
            fprintf(output , "\t\t<urg>%d</urg>\n",(unsigned int)tcph->urg);
            fprintf(output , "\t\t<ack>%d</ack>\n",(unsigned int)tcph->ack);
            fprintf(output , "\t\t<psh>%d</psh>\n",(unsigned int)tcph->psh);
            fprintf(output , "\t\t<rst>%d</rst>\n",(unsigned int)tcph->rst);
            fprintf(output , "\t\t<syn>%d</syn>\n",(unsigned int)tcph->syn);
            fprintf(output , "\t\t<fin>%d</fin>\n",(unsigned int)tcph->fin);
            if( (80 == ntohs(tcph->dest)) || (443 == ntohs(tcph->dest)) ) {
                //HTTP(S)
                char hbuf[NI_MAXHOST];
                struct sockaddr_in sin;

                memset(&sin, 0, sizeof(sin)); 
                sin.sin_family      = AF_INET; 
                sin.sin_addr.s_addr = iph->daddr;
                //sin.sin_port        = 0; 

                if (getnameinfo((struct sockaddr*)&sin, sizeof(struct sockaddr), hbuf, sizeof(hbuf), NULL, 0, 0) == 0){
                    fprintf(output , "\t\t<destination-host>%s</destination-host>\n",hbuf);
                }else printf("\nFailed to het host name\n");
            }         
        } else if(17 == iph->protocol){
            // UDP
            struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
            fprintf(output , "\t\t<source-port>%u</source-port>\n",ntohs(udph->source));
            fprintf(output , "\t\t<destination-port>%u</destination-port>\n",ntohs(udph->dest));
        }  

        // IP packet size
        fprintf(output , "\t\t<IP-size>%d</IP-size>\n",ntohs(iph->tot_len));
        fprintf(output , "\t</packet>\n");
    }
}