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
char backUpFileName[] = "/home/codex/developer/networkSniffer/log.txt";
char killSwitchFileName[] = "/home/codex/developer/networkSniffer/kill.swt";
int savesize;


pcap_t *handle; //Handle of the device that shall be sniffed


void *storeData_thread(void *arg);
void *dummyProcess_thread(void *arg);
void *backUp_thread(void *arg);
void *killSwitch_thread(void *arg);
void readMacFromFile(void);

/*
  Networking declarations
*/
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

 
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
    pthread_t store_thread, kill_thread, dummy_thread;
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
    res = pthread_create(&dummy_thread, NULL, dummyProcess_thread, NULL);
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

    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        if(strcmp(device->name, argv[1]) == 0){
            break;
        }
    }
     
     if(device == NULL){
        printf("Unable to find the device! Exiting ...");
        exit(EXIT_FAILURE);
     }

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
    printf("Kill Thread joined\n");

    res = pthread_join(store_thread, &thread_result);
    if (res != 0) {
        perror("Thread join failed");
        exit(EXIT_FAILURE);
    }
    printf("Store Thread joined\n");

    res = pthread_join(dummy_thread, &thread_result);
    if (res != 0) {
        perror("Thread join failed");
        exit(EXIT_FAILURE);
    }
    printf("Dummy Thread joined\n");

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

void *dummyProcess_thread(void * arg)
{

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
}
 