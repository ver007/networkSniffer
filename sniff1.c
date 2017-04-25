/*
    Packet sniffer using libpcap library
*/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <pthread.h>
#include <semaphore.h>

#define BYTES_IN_MB		(1024*1024)
#define MB_IN_GB		(1024)
#define MAX_MAC_COUNT 	(50)
#define MAC_LENGTH    	(6)
/*
  Synchronization declarations
*/
typedef struct{
  unsigned int dataGB;
  unsigned int dataMB;
  unsigned int dataBYTES;
}dataHolder;

typedef struct{
  u_char mac[MAC_LENGTH];
  dataHolder data;
}DestMACDataHolder;

typedef struct{
  char mac[MAC_LENGTH];
  dataHolder data;
}SrcMACDataHolder;

DestMACDataHolder destMACs[MAX_MAC_COUNT] = {0};
SrcMACDataHolder srcMACs[MAX_MAC_COUNT] = {0};

int destMacTotal = 0;
int srcMacTotal = 0;
int killSwitch = 0;
sem_t bin_sem;
FILE *backUpFile;
char backUpFileName[] = "";
char killSwitchFileName[] = "";
int savesize;


pcap_t *handle; //Handle of the device that shall be sniffed


void *storeData_thread(void *arg);
void *backUp_thread(void *arg);
void *killSwitch_thread(void *arg);
void readMacFromFile(void);

/*
  Networking declarations
*/
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );
void PrintData (const u_char * , int);
 
//FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
u_int allData[2] = {0,0}; 
 
int main(int argc, char *argv[])
{
    pcap_if_t *alldevsp , *device;
 
    char errbuf[100] , *devname , devs[100][100];
    int count = 1 , n;
     

  /*
    Setup synchronization elements
  */
    int res;
    pthread_t store_thread, kill_thread;
    void *thread_result;

    res = sem_init(&bin_sem, 0, 1);
    if (res != 0) {
        perror("Semaphore initialization failed");
        exit(EXIT_FAILURE);
    }
    res = pthread_create(&store_thread, NULL, storeData_thread, NULL);
    if (res != 0) {
        perror("Thread creation failed");
        exit(EXIT_FAILURE);
    }
    res = pthread_create(&kill_thread, NULL, killSwitch_thread, NULL);
    if (res != 0) {
        perror("Thread creation failed");
        exit(EXIT_FAILURE);
    }

  /*
    Setup synchrnization elements
  */
    //First get the list of available devices
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done\n");
     
    //Print the available devices
    //printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        // printf("%d. %s - %s\n" , count , device->name , device->description);
        // if(device->name != NULL)
        // {
        //     strcpy(devs[count] , device->name);
        // }
        // count++;
        if(strcmp(device->name, argv[1]) == 0){
            break;
        }
    }
     
     if(device == NULL){
        printf("Unable to find the device! Exiting ...");
        exit(EXIT_FAILURE);
     }
    //Ask user which device to sniff
    //printf("Enter the number of the device you want to sniff : ");
    //scanf("%d" , &n);
    devname = argv[1];
     
    //Open the device for sniffing
    printf("Opening device %s for sniffing ... " , devname);
    handle = pcap_open_live(devname , 1000 , 1 , 0 , errbuf);
     
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    printf("Done\n");

    pcap_loop(handle , -1 , process_packet , NULL);
    
    printf("\nWaiting for thread to finish...\n");
    res = pthread_join(kill_thread, &thread_result);
    if (res != 0) {
        perror("Thread join failed");
        exit(EXIT_FAILURE);
    }
    printf("Thread joined\n");

    res = pthread_join(store_thread, &thread_result);
    if (res != 0) {
        perror("Thread join failed");
        exit(EXIT_FAILURE);
    }

    sem_destroy(&bin_sem);
    printf("Exiting program\n");
    exit(EXIT_SUCCESS);
    //return 0;   
}

/*
    Api to read the contents of the file and populate the MAC address database variable
*/
void readMacFromFile(void)
{
    char ch, strTemp[20] = {0};
    int i, j_ParseIndex = 0, k_MacIndex = 0;
    uint32_t totalMac;
    DestMACDataHolder tempMac;

    FILE * rf = fopen(backUpFileName,"r");

    /*
        If there's no file, we have to start building database. So return to the calling
        and resume normal operation.
    */
    if (rf == NULL)
        return;

    fscanf(rf, "Total MACs: %d\n\n", &totalMac);
    destMacTotal = totalMac;

    //printf ("Total number of MACs are: %d", totalMac);

    for ( i = 0 ; i < totalMac ; i++ )
    {
        /*
            Parse MAC address.
        */
        while (1){
            ch = fgetc(rf);
            strTemp[j_ParseIndex ++] = ch;
            if( ch == '-')
            {

                destMACs[i].mac[k_MacIndex ++] = strtoul(strTemp, NULL, 16);
                j_ParseIndex = 0;
            }

            if( ch == ':')
            {
                destMACs[i].mac[k_MacIndex ++] = strtoul(strTemp, NULL, 16);
                break;
            }
        }
        //printf("***%.2X-%.2X-%.2X-%.2X-%.2X-%.2X:***\n",destMACs[i].mac[0],destMACs[i].mac[1],destMACs[i].mac[2],destMACs[i].mac[3],destMACs[i].mac[4],destMACs[i].mac[5]);
        j_ParseIndex = 0;
        k_MacIndex = 0;

        /*
            Parse GB.
        */
        while ((ch = fgetc(rf)) == ' ')
            ;

        strTemp[j_ParseIndex ++] = ch;

        while((ch = fgetc(rf)) != '|')
        {
            strTemp[j_ParseIndex ++] = ch;
        }

        destMACs[i].data.dataGB = strtoul(strTemp, NULL, 10);
        //printf("***GB: %d***\t", destMACs[i].data.dataGB);
        j_ParseIndex = 0;

        /*
            Parse MB.
        */
        while ((ch = fgetc(rf)) == ' ')
            ;
        strTemp[j_ParseIndex ++] = ch;

        while((ch = fgetc(rf)) != '|')
        {
            strTemp[j_ParseIndex ++] = ch;
        }

        destMACs[i].data.dataMB = strtoul(strTemp, NULL, 10);
        //printf("***MB: %d***\t", destMACs[i].data.dataMB);
        j_ParseIndex = 0;

        /*
            Parse Bytes.
        */
        while ((ch = fgetc(rf)) == ' ')
            ;
        strTemp[j_ParseIndex ++] = ch;

        while((ch = fgetc(rf)) != 'B')
        {
            strTemp[j_ParseIndex ++] = ch;
        }

        destMACs[i].data.dataBYTES = strtoul(strTemp, NULL, 10);
        //printf("***Bytes: %d***\t", destMACs[i].data.dataBYTES);
        j_ParseIndex = 0;

        /*
            Drop the remaining characters in a line.
        */
        while ((ch = fgetc(rf)) != '\n')
            ;

    }
    fclose(rf);
}

void *killSwitch_thread(void *arg) 
{

    char ch;
    FILE *rf = NULL;

    /*
        If the switch is already on, open the file and write 1 to flip it off.
    */
    rf = fopen(killSwitchFileName,"w");
    fprintf(rf,"0");
    fclose(rf);
    rf = NULL;

    while(1)
    {
        sleep(5);
        rf = fopen(killSwitchFileName,"r");

        /*
            This is to make sure that file is read only if it exists.
        */
        if (rf == NULL)
            continue;

        if(fgetc(rf) == '1')
        {
                //printf("Kill Switch Flipped!!\n");
                pcap_breakloop(handle);
                killSwitch = 1;
                break;   
        }
        fclose(rf);
        rf = NULL;
    }

    pthread_exit(NULL);
}

void *storeData_thread(void *arg) {
    int i;


    /*
        Before anything, read the usage history to sync with the last
        saved data usage.
    */
    sem_wait(&bin_sem);
    
    readMacFromFile();
    
    sem_post(&bin_sem);


    while(1)
    {
      sleep(3);

    /*
        Enter critical section: Updating the global database variable that stores 
        MAC addresses and its data attributes.
    */
      sem_wait(&bin_sem);

      /*
            Open the usage history file for writing current data usage.
      */
      backUpFile=fopen(backUpFileName,"w");

      // printf("Total MACs: %d\n", destMacTotal);
      fprintf(backUpFile,"Total MACs: %d\n\n", destMacTotal);
      for(i = 0 ; i < destMacTotal ; i++)
      {
        //fprintf(backUpFile, "%s\t", destMACs[i].mac, MAC_LENGTH);
        fprintf(backUpFile,"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X:\t",destMACs[i].mac[0],destMACs[i].mac[1],destMACs[i].mac[2],destMACs[i].mac[3],destMACs[i].mac[4],destMACs[i].mac[5]);
        fprintf(backUpFile,"%d GB | %d MB | %d Bytes\n",destMACs[i].data.dataGB, destMACs[i].data.dataMB, destMACs[i].data.dataBYTES);

      }
      
    /*
        Exit critical section: Updating the global database variable that stores 
        MAC addresses and its data attributes.
    */
      sem_post(&bin_sem);

      /*
            Current usage written. Close the usage history file.
      */
      fclose(backUpFile);

      if(killSwitch == 1)
        break;
    }
    
    pthread_exit(NULL);
}

int isMACExists(u_char *mac)
{
    int i, j;

   // printf("%x,%x,%x\n",mac[0],mac[1],mac[2]);

    if((mac[0] == 0x33) && (mac[1] == 0x33) && (mac[2] == 0xff))
	{
//		printf("N");
		j = -1;
	}
    else
	{
//		printf("V");
	        for( j = 0; j < destMacTotal ; j++)
	        {
	          for(i = 0; i < MAC_LENGTH ; i++)
        	  {
	              if((destMACs[j].mac[i] ^ mac[i]) != 0)
        	          break;
	          }
        	  if(i == MAC_LENGTH)
	              break;
        	}
	}
    return j;
}
 
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    //sleep(2);
    int index;
    u_char mac[MAC_LENGTH];
	
	/*
		Store the size of the packet received.
	*/
    int size = header->len;
	
	
    allData[1] += (size + allData[0]) / BYTES_IN_MB;
    allData[0] = (size + allData[0]) % BYTES_IN_MB;

    struct ethhdr *eth = (struct ethhdr *)buffer;
    //printf("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    //printf("%d-%d-%d-%d-%d-%d***\n",eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    
	/*
		Get the MAC address from the packet header.
	*/
	strncpy(mac,eth->h_dest,MAC_LENGTH);
	/*
		Check if the MAC exists in the global database variable.
	*/
	index = isMACExists(mac);
    
	/*
		Enter critical section: Updating the global database variable that stores 
		MAC addresses and its data attributes.
	*/
    if(index > -1)
    {
    sem_wait(&bin_sem);
    if(index < destMacTotal)
    {
		/*
			If the MAC exists, update its data attributes.
		*/
        destMACs[index].data.dataMB += (destMACs[index].data.dataBYTES + size) / BYTES_IN_MB;
		destMACs[index].data.dataGB += (destMACs[index].data.dataMB) / MB_IN_GB;
		destMACs[index].data.dataMB = (destMACs[index].data.dataMB ) % MB_IN_GB;
		destMACs[index].data.dataBYTES = (destMACs[index].data.dataBYTES + size) % BYTES_IN_MB;
    }
    else
    {
        /*
			Adding new MAC to the global database variable. Also initialize the data
			attributes with the size of the first packet.
		*/
        strncpy(destMACs[index].mac,mac,MAC_LENGTH);
        destMACs[index].data.dataMB += (destMACs[index].data.dataBYTES + size) / BYTES_IN_MB;
		destMACs[index].data.dataGB += (destMACs[index].data.dataMB) / MB_IN_GB;
		destMACs[index].data.dataMB = (destMACs[index].data.dataMB ) % MB_IN_GB;
        destMACs[index].data.dataBYTES = (destMACs[index].data.dataBYTES + size) % BYTES_IN_MB;
        destMacTotal++;
    }
	
	/*
		Exit critical section: Updating the global database variable that stores 
		MAC addresses and its data attributes.
	*/
    sem_post(&bin_sem);
    }
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            //print_icmp_packet( buffer , size);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
            //print_tcp_packet(buffer , size);
            break;
         
        case 17: //UDP Protocol
            ++udp;
            //print_udp_packet(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    //printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d   Data:%d\r", tcp , udp , icmp , igmp , others , total, allData[1]);
    //printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Total : %d   Data:%d\r", tcp , udp , icmp , igmp , total, allData[1]);
}
 
void print_ethernet_header(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    // fprintf(logfile , "\n");
    // fprintf(logfile , "Ethernet Header\n");
    // fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    // fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    // fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}
 
void print_ip_header(const u_char * Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    // fprintf(logfile , "\n");
    // fprintf(logfile , "IP Header\n");
    // fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    // fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    // fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    // fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    // fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    // //fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    // //fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    // //fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    // fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    // fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    // fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
    // fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    // fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}
 
void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
   // fprintf(logfile , "\n\n***********************TCP Packet*************************\n");  
         
    print_ip_header(Buffer,Size);
         
    // fprintf(logfile , "\n");
    // fprintf(logfile , "TCP Header\n");
    // fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
    // fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    // fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    // fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    // fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    // //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    // //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    // fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    // fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    // fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    // fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    // fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    // fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    // fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    // fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    // fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    // fprintf(logfile , "\n");
    // fprintf(logfile , "                        DATA Dump                         ");
    // fprintf(logfile , "\n");
         
    // fprintf(logfile , "IP Header\n");
    // PrintData(Buffer,iphdrlen);
         
    // fprintf(logfile , "TCP Header\n");
    // PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    // fprintf(logfile , "Data Payload\n");    
    // PrintData(Buffer + header_size , Size - header_size );
                         
    // fprintf(logfile , "\n###########################################################");
}
 
void print_udp_packet(const u_char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    // fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
     
    // print_ip_header(Buffer,Size);           
     
    // fprintf(logfile , "\nUDP Header\n");
    // fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    // fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    // fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    // fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    // fprintf(logfile , "\n");
    // fprintf(logfile , "IP Header\n");
    // PrintData(Buffer , iphdrlen);
         
    // fprintf(logfile , "UDP Header\n");
    // PrintData(Buffer+iphdrlen , sizeof udph);
         
    // fprintf(logfile , "Data Payload\n");    
     
    // //Move the pointer ahead and reduce the size of string
    // PrintData(Buffer + header_size , Size - header_size);
     
    // fprintf(logfile , "\n###########################################################");
}
 
void print_icmp_packet(const u_char * Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    // fprintf(logfile , "\n\n***********************ICMP Packet*************************\n"); 
     
    // print_ip_header(Buffer , Size);
             
    // fprintf(logfile , "\n");
         
    // fprintf(logfile , "ICMP Header\n");
    // fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));
             
    // if((unsigned int)(icmph->type) == 11)
    // {
    //     fprintf(logfile , "  (TTL Expired)\n");
    // }
    // else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    // {
    //     fprintf(logfile , "  (ICMP Echo Reply)\n");
    // }
     
    // fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
    // fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
    // //fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
    // //fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
    // fprintf(logfile , "\n");
 
    // fprintf(logfile , "IP Header\n");
    // PrintData(Buffer,iphdrlen);
         
    // fprintf(logfile , "UDP Header\n");
    // PrintData(Buffer + iphdrlen , sizeof icmph);
         
    // fprintf(logfile , "Data Payload\n");    
     
    // //Move the pointer ahead and reduce the size of string
    // PrintData(Buffer + header_size , (Size - header_size) );
     
    // fprintf(logfile , "\n###########################################################");
}
 
void PrintData (const u_char * data , int Size)
{
    int i , j;
    // for(i=0 ; i < Size ; i++)
    // {
    //     if( i!=0 && i%16==0)   //if one line of hex printing is complete...
    //     {
    //         fprintf(logfile , "         ");
    //         for(j=i-16 ; j<i ; j++)
    //         {
    //             if(data[j]>=32 && data[j]<=128)
    //                 fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
    //             else fprintf(logfile , "."); //otherwise print a dot
    //         }
    //         fprintf(logfile , "\n");
    //     } 
         
    //     if(i%16==0) fprintf(logfile , "   ");
    //         fprintf(logfile , " %02X",(unsigned int)data[i]);
                 
    //     if( i==Size-1)  //print the last spaces
    //     {
    //         for(j=0;j<15-i%16;j++) 
    //         {
    //           fprintf(logfile , "   "); //extra spaces
    //         }
             
    //         fprintf(logfile , "         ");
             
    //         for(j=i-i%16 ; j<=i ; j++)
    //         {
    //             if(data[j]>=32 && data[j]<=128) 
    //             {
    //               fprintf(logfile , "%c",(unsigned char)data[j]);
    //             }
    //             else
    //             {
    //               fprintf(logfile , ".");
    //             }
    //         }
             
    //         fprintf(logfile ,  "\n" );
    //     }
    // }
}
