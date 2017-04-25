#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>   //strlen
   
 
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
#include<gtk/gtk.h>

/*With GUI*/ 
struct sockaddr_in source,dest;
int tcp=0,udp=0,http = 0, dns = 0,others=0,total=0,othera = 0,abc=1,i,j,row=2;
char *srccport[1000];
char *desttport[1000];
FILE *logfile;

char Sr[5], SrcAddr[50], DestAddr[50],Prot[50];
char iodest[50],iosrc[50];
int filterflag1 = 0, filterflag2 = 0;
char *srcip;
char *ethdest[1000];
char *ethsrc[1000];
char *ethprot[1000];
char *ipvr[1000];
char *iphdlen[1000];
char *tos[1000];
char *iptlen[1000];

// char* ppp;

GtkWidget *sourceIP;
GtkWidget *destIP;
GtkWidget *protocol;
GtkWidget *srcIpbtn;
GtkWidget *destIpbtn;
GtkWidget *Protbtn;
GtkWidget *entry;

GtkTextBuffer *buffer;
GtkTextIter start, end;
GtkTextIter iter;

GtkWidget* window;
GtkWidget* textArea;
GtkWidget* scrolledwindow;
// GtkWidget* textEntry = gtk_entry_new();
GtkWidget* btn1;
GtkWidget* btn2;
GtkWidget* console;
guint timertag;
int timerunning;

int createSocket();
void processDataLinkLayer(unsigned char* , int);
void processNetworkLayer(unsigned char*, int);
void processTransportLayer(unsigned char* Buffer, int data_size,unsigned int protocol,unsigned int iphdrlen);
void processTCP(unsigned char* Buffer, int data_size,unsigned int iphdrlen);
void processUDP(unsigned char *Buffer , int data_size, unsigned int iphdrlen);
void processApplicationLayer(unsigned char*, int, int,int,int);
void PrintData(unsigned char* , int);
void startTimer();
void stopTimer();
GtkWidget* createConsoleBox();

int main(int argc, char *argv[])
{

  gtk_init(&argc, &argv);

  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(window), "Assign2");
  gtk_window_set_default_size(GTK_WINDOW(window), 1050,500);
  gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
  gtk_container_set_border_width(GTK_CONTAINER(window), 5);


    GtkWidget* textArea = gtk_text_view_new();
    GtkWidget* scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
    // GtkWidget* textEntry = gtk_entry_new();
    GtkWidget* btn1 = gtk_button_new_with_label("start Sniffing");
    g_signal_connect(G_OBJECT(btn1), "clicked", G_CALLBACK(startTimer), NULL);
    
    GtkWidget* btn2 = gtk_button_new_with_label("stop sniffing");
    g_signal_connect(G_OBJECT(btn2), "clicked", G_CALLBACK(stopTimer), NULL);

    GtkWidget* console = gtk_table_new(100, 3, FALSE);

    gtk_container_add(GTK_CONTAINER(scrolledwindow), textArea);
    gtk_table_attach_defaults(GTK_TABLE(console),btn1,0,1,0,1);
    gtk_table_attach_defaults(GTK_TABLE(console),btn2,1,2,0,1);
    gtk_table_attach_defaults(GTK_TABLE(console), scrolledwindow, 0, 2, 1, 99);
    gtk_container_add(GTK_CONTAINER(window),console);

    buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textArea));

    gtk_text_buffer_create_tag(buffer, "gap",
            "pixels_above_lines", 30, NULL);

    gtk_text_buffer_create_tag(buffer, "lmarg", 
        "left_margin", 5, NULL);
    gtk_text_buffer_create_tag(buffer, "blue_fg", 
        "foreground", "blue", NULL); 
    gtk_text_buffer_create_tag(buffer, "gray_bg", 
        "background", "gray", NULL); 
    gtk_text_buffer_create_tag(buffer, "italic", 
        "style", PANGO_STYLE_ITALIC, NULL);
    gtk_text_buffer_create_tag(buffer, "bold", 
        "weight", PANGO_WEIGHT_BOLD, NULL);

    gtk_text_buffer_get_iter_at_offset(buffer, &iter, 0);

    gtk_text_buffer_insert(buffer, &iter, "Destination Address   Source Address     Protocol        Ipversion   IpHeaderLength     SourceIP     DestinationIP    Protocol     Source port     Destination port\n", -1);
    //add heading here for source address IP address and stuff like that.
    

    
    gtk_widget_show_all(window);

    g_signal_connect_swapped(G_OBJECT(window), "destroy", G_CALLBACK(gtk_main_quit), NULL);

    gtk_main();

  return 0;
}

void startTimer()
{
        if(!timerunning)
        {
            printf("starting timer.....\n");
            timertag = g_timeout_add(1000, (GSourceFunc) createSocket, NULL);
            timerunning = 1;
        }
}

void stopTimer()
{
    if(timerunning)    
    {   
        printf("stopping timer.....\n");
        g_source_remove(timertag);
        timerunning = 0;
    }
}

int createSocket()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    int flag2;
    unsigned char *Buffer = (unsigned char *) malloc(65536); //Its Big!
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    //setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
     
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 0;
    }
    
    saddr_size = sizeof saddr;  //******size of socket??
    //Receive a packet
    data_size = recvfrom(sock_raw , Buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);

    if(data_size <0 )
    {
        printf("Recvfrom error , failed to get packets\n");
        return 0;
    }
    //Now process the packet


    processDataLinkLayer(Buffer , data_size);
    
    
    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    ethdest, -1, "blue_fg", "lmarg",  NULL);
    
    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    "    ", -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    ethsrc, -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    "     ", -1, "blue_fg", "lmarg",  NULL);

    sprintf(ethprot,"%-25s",ethprot);
    

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    ethprot, -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    "         ", -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    ipvr, -1, "blue_fg", "lmarg",  NULL);
    
    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    "          ", -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    iphdlen, -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    "    ", -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    SrcAddr, -1, "blue_fg", "lmarg",  NULL);
    
    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    "      ", -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    DestAddr, -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    "      ", -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    Prot, -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    "      ", -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    srccport, -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    "      ", -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    desttport, -1, "blue_fg", "lmarg",  NULL);

    gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, 
    "\n", -1, "blue_fg", "lmarg",  NULL);

    // printf("%d",srcport);

    close(sock_raw);
    return 1;
}


void processDataLinkLayer(unsigned char* Buffer, int data_size)
{
 strcpy(Prot,"Ethernet");
  struct ethhdr *eth = (struct ethhdr *)Buffer;
  total++;

  sprintf(ethdest , "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
  sprintf(ethsrc  , "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
  sprintf(ethprot , "%u ",(unsigned short)eth->h_proto);

	processNetworkLayer(Buffer,data_size);
}

void processNetworkLayer(unsigned char* Buffer, int data_size)
{
    strcpy(Prot,"IP");
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );  
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr= iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    sprintf(ipvr , "%d ",(unsigned int)iph->version);
    sprintf(iphdlen , " %d Bytes ",((unsigned int)(iph->ihl))*4);
    sprintf(tos, " %d ",(unsigned int)iph->tos);
    
    //int s1=sizeof(inet_ntoa(source.sin_addr));
    strcpy(SrcAddr,inet_ntoa(source.sin_addr));
    
    strcpy(DestAddr,inet_ntoa(dest.sin_addr));

	  unsigned int protocol = (unsigned int)iph->protocol;
	  processTransportLayer(Buffer, data_size, protocol,iphdrlen);
    return;
}

void processTransportLayer(unsigned char* Buffer, int data_size,unsigned int protocol,unsigned int iphdrlen)
{
	switch(protocol)
	{
		case 6: tcp++;
      strcpy(Prot,"TCP");
			processTCP(Buffer,data_size,iphdrlen);
			break;
		case 17: udp++;
      strcpy(Prot,"UDP");
			processUDP(Buffer,data_size,iphdrlen);
			break;
		default: others++;
			break;
	}
  return;
}
			
void processTCP(unsigned char* Buffer, int data_size,unsigned int iphdrlen)
{
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr)); 
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    
    sprintf(srccport , "%u ",ntohs(tcph->source));
    sprintf(desttport , "%u ",ntohs(tcph->dest));
    int destport = ntohs(tcph->dest);
	int tcpudp = 1;
	processApplicationLayer(Buffer, data_size, tcpudp,destport,header_size);
    return;
}

void processUDP(unsigned char *Buffer , int data_size, unsigned int iphdrlen)
{  
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;   // ******** sizeof updh??
    
    sprintf(srccport , "%u ",ntohs(udph->source));
    sprintf(desttport , "%u ",ntohs(udph->dest));
    
    int destport = ntohs(udph->dest);
	int tcpudp = 0;
	processApplicationLayer(Buffer, data_size, tcpudp, destport,header_size);
    return;
}

void processApplicationLayer(unsigned char* Buffer, int data_size, int tcpudp, int destport,int header_size)
{
	switch(tcpudp)
	{
        case 0: 
            switch(destport)
            {
                case 53:
                    dns++;
                    strcpy(Prot,"DNS(UDP)");
                    break;
                default: 
                    othera++;
                    break;
            }
            break;
        case 1: 
            switch(destport)
            {
                case 53: 
                    dns++;
                    strcpy(Prot,"DNS(TCP)");	
                    break;
                case 80: 
                    http++;
                    strcpy(Prot,"HTTP");	
                    break;
                default: 
                    othera++;
            }
            break;
        default: 
            break;
	}
  return;
}



