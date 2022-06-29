// find libraries used in linux OS at usr/glibc/sysdeps/unix/sysv/linux/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <search.h>
#include <linux/limits.h>

#define IPSTR_ADDR_LEN 16
#define IPCIDRSTR_ADDR_LEN 20
#define MACSTR_ADDR_LEN 18
#define LINE_LEN 200

#define IP_ADDR_LEN 4

#define ACCEPT_ANY 0x01
#define PRINT_REQ  0x02
#define VERBOSE    0x04
#define HASH       0x08
#define NON_ROOT   0x20

void usage();

void macarray_to_str(uint8_t array[ETHER_ADDR_LEN], char dest[MACSTR_ADDR_LEN]);
void iparray_to_str(uint8_t array[IP_ADDR_LEN], char dest[IPSTR_ADDR_LEN]);
int split_cidr_range(const char * target, struct in_addr * ip_range, uint32_t * ip_count);
int loadMAClist(const char * filename, char ** mac_list, struct hsearch_data *htab);
void freeMAClist(char * mac_list, struct hsearch_data *htab);

int getMACs(int fd, int interface_index, char mac[ETHER_ADDR_LEN], char * ip, char * target, int flags, struct hsearch_data *htab);

int main(int argc, char ** argv)
{
  int c, fd = 0, list_count = 0, flags = 0, matches = 0;
  struct timeval tv;
  char target[IPCIDRSTR_ADDR_LEN] = "";
  char interface_name[IFNAMSIZ] = "";
  int interface_index;
  unsigned char interface_mac[ETHER_ADDR_LEN];
  char interface_ip[IPSTR_ADDR_LEN];
  char list_filename[PATH_MAX] = "";
  struct ifreq ifr;
  struct hsearch_data mac_list_hash;
  char * mac_list = NULL;

  tv.tv_sec = 0;
  tv.tv_usec = 950000;

  opterr = 0;

  while ((c = getopt (argc, argv, "hVapvixr:l:t:")) != -1)
    switch (c)
    {
      case 'h':
        usage();
        return 0;
        break;
      case 'a':
        flags |= ACCEPT_ANY;
        break;
      case 'p':
        flags |= PRINT_REQ;
        break;
      case 'v':
        flags |= VERBOSE;
        break;
      case 'i':
        flags |= HASH_DENY;
        break;
      case 'x':
        flags |= NON_ROOT;
        break;
      case 'r':
        strncpy(target, optarg, IPCIDRSTR_ADDR_LEN);
        break;
      case 'l':
        strncpy(list_filename, optarg, PATH_MAX);
        break;
      case 't': {
        uint32_t n = atol(optarg);
        tv.tv_sec = n/1000;
        tv.tv_usec = (n%1000) * 1000;
        }
        break;
      case '?':
        if (optopt == 'r')
          fprintf (stderr, "Option -r requires an IP range IP/CIDR.\n");
        else if (optopt == 'l')
          fprintf (stderr, "Option -l requires a filename.\n");
        else if (optopt == 't')
          fprintf (stderr, "Option -t requires a timeout in milliseconds.\n");
        else if (isprint(optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
        return -1;
      default:
        abort ();
    }

  if (getuid() != 0 && !(flags & NON_ROOT))
  {
    fprintf(stderr, "You have to be root!\n");
    return -1;
  }

  if (strlen(target) && split_cidr_range(target, NULL, NULL))
  {
    fprintf(stderr, "You must enter IP/CIDR range. For example: 10.0.0.1/24\n");
    return -1;
  }

  if (strlen(list_filename) && (list_count = loadMAClist(list_filename, &mac_list, &mac_list_hash)) < 0)
  {
    fprintf(stderr, "There was a problem load MAC addresses from: %s\n", list_filename);
    return -1;
  }
  if (list_count > 0)
    flags |= HASH;

  if (optind < argc) {
    strncpy(interface_name, argv[optind], IFNAMSIZ-1);
    interface_name[IFNAMSIZ-1]=0; // We don't want a buffer overrun here
  }

  if (interface_name[0] == 0)
  {
    fprintf(stderr, "You must specify an interface\n");
    return -1;
  }

  fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
  if (fd < 0) {
    perror("creting socket");
    return -1;
  }
  memcpy(ifr.ifr_name, interface_name, strlen(interface_name));
  ifr.ifr_name[strlen(interface_name)]=0;

  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    perror("setting socket timeout");
    return -1;
  }

  if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
  {
    perror("getting interface index");
    return -1;
  }
  interface_index = ifr.ifr_ifindex;

  if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1)
  {
    perror("getting interface MAC address");
    return -1;
  }
  memcpy(interface_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

  if (ioctl(fd, SIOCGIFADDR, &ifr)==-1)
  {
    perror("getting interface IP address");
    return -1;
  }
  struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
  memcpy(interface_ip, inet_ntoa(ipaddr->sin_addr), IPSTR_ADDR_LEN);

  if (!strlen(target))
  {
    sprintf(target, "%s/24", interface_ip);
  }

  if (flags & VERBOSE) {
    printf("Interface %s\n", interface_name);
    printf("Local IP %s\n", interface_ip);
    printf("Local MAC %02x:%02x:%02x:%02x:%02x:%02x\n", interface_mac[0], interface_mac[1], interface_mac[2], interface_mac[3], interface_mac[4], interface_mac[5]);
    printf("Scan range %s\n", target);
    if (list_count > 0)
      printf("Loaded %d MAC addresses from %s\n", list_count, list_filename);
    printf("\n");
  }

  matches = getMACs(fd, interface_index, interface_mac, interface_ip, target, flags, &mac_list_hash);

  close(fd);

  if (list_count > 0)
    freeMAClist(mac_list, &mac_list_hash);

  return (matches > 0); 
}

int getMACs(int fd, int interface_index, char mac[ETHER_ADDR_LEN], char * ip, char * target, int flags, struct hsearch_data *htab)
{
  const unsigned char ether_broadcast_addr[] = {0xff,0xff,0xff,0xff,0xff,0xff};
  struct sockaddr_ll addr = {0}, r_addr = {0};
  struct ether_arp req, *rep;
  struct in_addr source_ip_addr = {0};
  struct in_addr target_ip_addr = {0};
  struct in_addr ip_range = {0};
  struct iovec iov[1];
  struct msghdr message;
  struct msghdr reply;
  ssize_t reply_len;
  char buffer[512];
  struct iovec r_iov[1];
  int p, show = 0, matches = 0;
  ENTRY e, *ep;
  uint32_t ip_count, i, found;
  char macstr[MACSTR_ADDR_LEN];
  char macstr_dest[MACSTR_ADDR_LEN];
  char ipstr[IPSTR_ADDR_LEN];
  char ipstr_dest[IPSTR_ADDR_LEN];

  bzero(&message, sizeof(message));
  bzero(&reply, sizeof(reply));

  split_cidr_range(target, &ip_range, &ip_count);
  
  addr.sll_family   = AF_PACKET;
  addr.sll_ifindex  = interface_index;
  addr.sll_halen    = ETHER_ADDR_LEN;
  addr.sll_protocol = htons(ETH_P_ARP);
  memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);

  req.arp_hrd = htons(ARPHRD_ETHER);
  req.arp_pro = htons(ETH_P_IP);
  req.arp_hln = ETHER_ADDR_LEN;
  req.arp_pln = sizeof(in_addr_t);
  req.arp_op  = htons(ARPOP_REQUEST);
  memset(&req.arp_tha, 0, sizeof(req.arp_tha));

  if (!inet_aton(ip, &source_ip_addr)) {
    fprintf(stderr, "%s is not a valid IP address", ip);
    return -2;
  }
  memcpy(&req.arp_spa, &source_ip_addr.s_addr, sizeof(req.arp_spa));
  memcpy(req.arp_sha, mac, ETHER_ADDR_LEN);

  for(i=0; i<ip_count; ++i) {

    memcpy(&req.arp_tpa, &ip_range.s_addr, sizeof(req.arp_tpa));
    if (flags & PRINT_REQ)
      printf("Sending ARP request for %s\n", inet_ntoa(ip_range));
  
    iov[0].iov_base=&req;
    iov[0].iov_len=sizeof(req);
    
    message.msg_name=&addr;
    message.msg_namelen=sizeof(addr);
    message.msg_iov=iov;
    message.msg_iovlen=1;
    message.msg_control=0;
    message.msg_controllen=0;
    
    if (sendmsg(fd, &message, 0) == -1) {
      perror("sending ARP request");
      return -3;
    }
  
  
    r_iov[0].iov_base = buffer;
    r_iov[0].iov_len  = sizeof(req);
    reply.msg_name    = &r_addr;
    reply.msg_namelen = sizeof(r_addr);
    reply.msg_iov     = r_iov;
    reply.msg_iovlen  = 1;
    reply.msg_control = 0;
    reply.msg_controllen = 0;

    found = 0; 
    do { 
      if ((reply_len = recvmsg(fd, &reply, 0)) < 0) {
        if (errno != EAGAIN) {
          perror("receiving ARP request");
          return -4;
        }
        else {
          break;
        }
      }
    
      rep = (struct ether_arp*)buffer;
      macarray_to_str(rep->arp_sha, macstr);
      iparray_to_str(rep->arp_spa, ipstr);
  
      if (flags & HASH)
      {
        ep = NULL;
        e.key = macstr;
        hsearch_r(e, FIND, &ep, htab);
        show = ((ep != NULL) && (flags & HASH_DENY)) || ((ep == NULL) && !(flags & HASH_DENY));
      }

      found = (*(uint32_t*)rep->arp_spa == *(uint32_t*)req.arp_tpa);
      
      if (ntohs(rep->arp_op) == ARPOP_REPLY 
          && (found || (flags & ACCEPT_ANY))
          && (show || !(flags & HASH))
      ) {
        printf("%s\t", macstr);
        printf("%s", ipstr);
	++matches;
  
        if (flags & VERBOSE) {
          macarray_to_str(rep->arp_tha, macstr_dest);
          iparray_to_str(rep->arp_tpa, ipstr_dest);
          printf("\t->\t");
          printf("%s\t", macstr_dest);
          printf("%s", ipstr_dest);
        }
        printf("\n");
      }

    }
    while(!found);

    ip_range.s_addr = inc_netorder(ip_range.s_addr); 

  } 

  return matches;
}

int split_cidr_range(const char * target, struct in_addr * ip_range, uint32_t * ip_count)
{
  char tmp[IPCIDRSTR_ADDR_LEN];
  int count;
  struct in_addr range;
  char * cidr;
  uint32_t mask = 0xFFFFFFFF;

  strncpy(tmp, target, IPCIDRSTR_ADDR_LEN);

  cidr = strchr(tmp, '/');
  if (cidr == NULL)
    return 1; 

  ++cidr;
  if (cidr == NULL)
    return 1;

  count = atoi(cidr);
  if (count < 1 || count > 32)
    return 1; 

  --cidr;
  *cidr = 0; 

  mask = mask << 32-count;

  if (inet_aton(tmp, &range) == 0)
    return 2; 

 
  range.s_addr &= htonl(mask);

  if (ip_range)
    memcpy(ip_range, &range, sizeof(range)); 

  if (ip_count)
    *ip_count = ~mask + 1;

  return 0;
}

uint32_t inc_netorder(uint32_t value)
{
  return ntohl(htonl(value)+1);
}

void macarray_to_str(uint8_t array[ETHER_ADDR_LEN], char dest[MACSTR_ADDR_LEN])
{
  sprintf(dest, "%02x:%02x:%02x:%02x:%02x:%02x", array[0], array[1], array[2], array[3], array[4], array[5]);
}
void iparray_to_str(uint8_t array[IP_ADDR_LEN], char dest[IPSTR_ADDR_LEN])
{
  sprintf(dest, "%u.%u.%u.%u", array[0], array[1], array[2], array[3]);
}
void usage()
{
  printf("Usage: findmacs [-apxvhV] [-t time] [-r IP/CIDR] [-l filename [-i]] interface\n\n");
  printf("  -r IP/CIDR      Scan this IP range. If not given <localIP>/24 is used\n");
  printf("  -l filename     Load MAC addresses listed in <filename> and use them as allowed.\n");
  printf("                  Only addresses found in network and not in list will be reported.\n");
  printf("  -t time         Set wait-for-reply timeout to <time> milliseconds. Default is 950 ms\n");
  printf("  -i              Report MAC addresses found in list (invert report)\n");
  printf("  -a              Accept ANY reply, even if it wasn't triggered by us\n");
  printf("  -p              Print IP address being queried\n");
  printf("  -x              Don't check root privileges\n");
  printf("  -v              Increase verbosity level\n");
  printf("  -h              Print this help\n");
}


int loadMAClist(const char * filename, char ** mac_list, struct hsearch_data *htab)
{
  FILE * f = fopen(filename, "rt");
  char line[LINE_LEN];
  ENTRY e, *ep;
  int ch;
#if defined(__LP64__) || defined(_LP64)
  uint64_t lines = 0;
#else
  uint32_t lines = 0;
#endif

  bzero(htab, sizeof(struct hsearch_data));

  if (f == NULL)
  {
    perror("loading MAC list");
    return -1;
  }

  while (EOF != (ch=fgetc(f)))
    if (ch=='\n')
        ++lines;

  rewind(f);

  *mac_list = malloc(MACSTR_ADDR_LEN*lines);
  hcreate_r(lines*2, htab);

  lines = 1;
  while(!feof(f)) {
    if (fgets(line, LINE_LEN, f) != NULL)
    {
      line[strlen(line)-1] = 0;
      char * mac = *mac_list + (MACSTR_ADDR_LEN*(lines-1));
      strncpy(mac, line, MACSTR_ADDR_LEN);
      e.key = mac;
      e.data = (void*)lines;
      hsearch_r(e, ENTER, &ep, htab);
      ++lines;
    }
  }

  fclose(f);

  return lines-1;
}

void freeMAClist(char * mac_list, struct hsearch_data *htab)
{
  free(mac_list);
  hdestroy_r(htab);
}