
#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
//#include <net/if.h>
#include <linux/if.h>

#include "gdp.h"

/*
 * for simplicity, this is the maximum size 
 * of all 0 terminated strings
 */
#define _NAMESIZE				    48

/*
 * This is a two way structure.  Some variables are filled in by
 * the caller and some are returned back by the function.  Some
 * are both set by the caller and changed back by the function.
 */
typedef struct interface_addresses_s {

    /* specified by caller */
    char interface_name [32];
    int interface_number;

    /* updated by function */
    int interface_exists;

    /* updated by function */
    int mac_address_retreived;
    byte mac_address [6];
    char mac_address_printable_string [24];

    /* updated by function */
    int ipv4_address_retreived;
    unsigned int ipv4_address;
    char ipv4_address_printable_string [24];
    
    /* updated by function */
    int ipv6_address_retreived;
    byte ipv6_address [16];
    char ipv6_address_printable_string [64];

} interface_addresses_t;

/*
 * chassis related information, gdp uses fields of this data structure
 */
typedef struct chassis_gdp_info_s {

    /* unique host id */
    int unique_id_string_changed;
    char unique_id_string [_NAMESIZE];
    int unique_id_string_length;

    int boxid_string_changed;
    char boxid_string [_NAMESIZE];
    int boxid_string_length;

    /* hostname of chassis, MAY change during runtime */
    int hostname_string_changed;
    char hostname_string [_NAMESIZE];
    int hostname_string_length;

    /* serial number of chassis, stays constant during runtime */
    int serial_number_string_changed;
    char serial_number_string [_NAMESIZE];
    int serial_number_string_length;

    /* product code of chassis, stays constant during runtime */
    int product_code_string_changed;
    char product_code_string [_NAMESIZE];
    int product_code_string_length;

    /* current management interface, MAY change during runtime */
    interface_addresses_t *designated_mgmt_interface;

} chassis_gdp_info_t;

/*
 * The TLVs conform to the definitions specified in the 802.1AB spec
 *
 * A very lazy but EXTREMELY convenient way of defining a fixed 
 * size LLDP packet and its TLVs.  Let the compiler do all offset
 * calculations and the work.
 *
 * In the structures below, strings are all 0 terminated.
 * I designed the tlv sizes fixed to make it much easier
 * to program.  This makes it much less error prone and 
 * VERY easy to access the structures.
 */

/*
 * LLDP tlvs are such that type is only 7 bits & length is 9 bits
 * The compiler is having some issues working with a bitfield
 * extending 8 bits so for this specific implementation I have
 * restricted each to a byte (255 max value).  This is ok since
 * no tlv we have used needs to be larger than 255 bytes so far.
 */
typedef struct type_len_s {
    byte type;
    byte len;
} __attribute__((packed)) type_len_t;

/***************************************************************************
 ***************************************************************************
 *
 * lldp chassis id tlv structure as per 802.1AB spec
 *
 */
typedef struct chassis_id_tlv_value_s {
    byte chassis_id_subtype;
    char chassis_printable_name [_NAMESIZE];
}  __attribute__((packed)) chassis_id_tlv_value_t;

typedef struct lldp_chassis_id_tlv_s {
    type_len_t tl;
    chassis_id_tlv_value_t chassis_id_value;
} __attribute__((packed)) lldp_chassis_id_tlv_t;

/***************************************************************************
 ***************************************************************************
 *
 * lldp port id tlv structure as per 802.1AB spec
 *
 */
typedef struct lldp_port_id_tlv_value_s {
    byte port_id_subtype;
    char port_printable_name [_NAMESIZE];
} __attribute__((packed)) lldp_port_id_tlv_value_t;

typedef struct lldp_port_id_tlv_s {
    type_len_t tl;
    lldp_port_id_tlv_value_t port_id_value;
} __attribute__((packed)) lldp_port_id_tlv_t;

/***************************************************************************
 ***************************************************************************
 *
 * lldp ttl tlv structure as per 802.1AB spec
 *
 */
typedef struct lldp_ttl_tlv_s {
    type_len_t tl;
    unsigned short value;
} __attribute__((packed)) lldp_ttl_tlv_t;

/***************************************************************************
 ***************************************************************************
 *
 * lldp management address tlv structure as per 802.1AB spec
 *
 */
typedef union {
    byte mac_address [6];
    unsigned int ipv4_address;
    byte ipv6_address [16];
} __attribute__((packed)) management_address_t;

typedef struct lldp_management_address_tlv_s {
    type_len_t tl;
    byte management_address_string_length;  // 6 (mac), 4 (ipv4), 16 (ipv6)
    byte management_address_subtype;        // 1 (ipv4), 2 (ipv6), 6 (mac)
    management_address_t address;
    byte interface_numbering_subtype;       // 3 (interface exists)
    int interface_number;
    byte oid_string_length;
} __attribute__((packed)) lldp_management_address_tlv_t;

#define MANAGEMENT_ADDRESS_STRING_LENGTH        (sizeof(management_address_t) + 1)

/* as defined by IANA */
#define MANAGEMENT_ADDRESS_SUBTYPE_NONE         0
#define MANAGEMENT_ADDRESS_SUBTYPE_MAC          6
#define MANAGEMENT_ADDRESS_SUBTYPE_IPV4         1
#define MANAGEMENT_ADDRESS_SUBTYPE_IPV6         2    

#define INTERFACE_NUMBERING_SUBTYPE_UNKNOWN     1   /* unkown, does not exist */
#define INTERFACE_NUMBERING_SUBTYPE_EXISTS      3   /* system port number */

#define MGMT_ADDRESS_TLV_LENGTH \
    (sizeof(lldp_management_address_tlv_t) - \
     offsetof(lldp_management_address_tlv_t, management_address_string_length))

/***************************************************************************
 ***************************************************************************
 *
 * company specific integer/string tlv structure as per 802.1AB spec.
 * 'company_subtype' determines the data type intended.
 *
 */

typedef struct company_oui_and_rest_s {

    byte oui [3];
    byte company_subtype;
    union {
	int integer;
	char string [_NAMESIZE];
    } u;

} __attribute__((packed)) company_oui_and_rest_t;

typedef struct company_specific_tlv_s {

    type_len_t tl;
    company_oui_and_rest_t goui;

} __attribute__((packed)) company_specific_tlv_t;

#define COMPANY_SPECIFIC_TLV_LENGTH \
    (sizeof(company_specific_tlv_t) - \
     offsetof(company_specific_tlv_t, goui))

/***************************************************************************
 ***************************************************************************
 *
 * lldp end of packet tlv structure as per 802.1AB spec
 *
 */
typedef struct {
    type_len_t tl;
} __attribute__((packed)) lldp_end_tlv_t;

/***************************************************************************
 ***************************************************************************
 *
 * actual gdp packet data section (INCLUDING ethertype)
 *
 */
typedef struct gdp_packet_data_s {

    byte dst_mac [6];
    byte src_mac [6];
    byte ethertype [2];

    /* mandatory lldp tlvs */
    lldp_chassis_id_tlv_t chassis_id_tlv;
    lldp_port_id_tlv_t port_id_tlv;
    lldp_ttl_tlv_t ttl_tlv;

    /* optional standard tlv */
    lldp_management_address_tlv_t mgmt_address_tlv;

    /* company specific tlvs */
    company_specific_tlv_t company_hostname_tlv;
    company_specific_tlv_t company_chassis_serial_number_tlv;
    company_specific_tlv_t company_chassis_product_code_tlv;
    company_specific_tlv_t company_port_type_tlv;

    /* end of packet */
    lldp_end_tlv_t end_tlv;

} __attribute__((packed)) gdp_packet_t;

/************************ Global Variables ************************/

int gdp_packet_size = sizeof(gdp_packet_t);
int designated_mgmt_interface_number = 0;

/*
 * choose bytes 4 - 6 to be all FF's otherwise
 * the pattern also seems to match the heartbeat filter
 * and packets end up in the wrong process.
 */
byte company_source_mac [6] = { 0x00, 0x1D, 0xAC, 0xFF, 0xFF, 0xFF };
byte company_source_mac_mask [6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/************************ Static Variables ************************/

static interface_addresses_t eth0_addresses = {
    interface_name: "eth0",
    interface_number: 0,
};

static interface_addresses_t eth1_addresses = {
    interface_name: "eth1",
    interface_number: 1,
};

static interface_addresses_t eth2_addresses = {
    interface_name: "eth2",
    interface_number: 2,
};

static interface_addresses_t eth3_addresses = {
    interface_name: "eth3",
    interface_number: 3,
};

/*
 * statically initialize this here since gdp_library_init
 * gets invoked too late to do it and some fields would
 * not be ready on time otherwise.
 */
static chassis_gdp_info_t this_chassis = {

    unique_id_string_changed: 1,
    unique_id_string: "",
    unique_id_string_length: 0,

    boxid_string_changed: 1,
    boxid_string: "",
    boxid_string_length: 0,

    hostname_string_changed: 1,
    hostname_string: "",
    hostname_string_length: 0,

    serial_number_string_changed: 1,
    serial_number_string: "",
    serial_number_string_length: 0,

    product_code_string_changed: 1,
    product_code_string: "",
    product_code_string_length: 0,

    designated_mgmt_interface: &eth0_addresses,
};

static chassis_gdp_info_t *chsp = &this_chassis;

static const char *
no_hostname = "NAMELESS_HOST";

static byte
lldp_destination_mac_address [6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };

/************************ Functions **************************************/

PUBLIC int 
interface_name_2_number (char *interface_name)
{
    if (interface_name && isdigit(interface_name[3])) {
        return
            interface_name[3] - '0';
    }
    return -1;
}

PUBLIC char *
interface_number_2_name (int interface_number)
{
    switch (interface_number) {
    case 0: return (char*) "eth0";
    case 1: return (char*) "eth1";
    case 2: return (char*) "eth2";
    case 3: return (char*) "eth3";
    default: return (char*) "INVALID_INTERFACE";
    }
}

static void
clear_mac_address (interface_addresses_t *addrs)
{
    int i;

    addrs->mac_address_retreived = 0;
    for (i = 0; i < 6; i++) addrs->mac_address[i] = 0;
    strcpy(addrs->mac_address_printable_string, "000000000000");
}

static void
clear_ipv4_address (interface_addresses_t *addrs)
{
    addrs->ipv4_address_retreived = 0;
    addrs->ipv4_address = 0;
    strcpy(addrs->ipv4_address_printable_string, "0.0.0.0");
}

static void
clear_ipv6_address (interface_addresses_t *addrs)
{
    int i;

    addrs->ipv6_address_retreived = 0;
    for (i = 0; i < 16; i++) addrs->ipv6_address[i] = 0;
    strcpy(addrs->ipv6_address_printable_string, "0:0:0:0:0:0:0:0");
}

static void
clear_interface_addresses (interface_addresses_t *addrs)
{
    addrs->interface_exists = 0;

    clear_mac_address(addrs);
    clear_ipv4_address(addrs);
    clear_ipv6_address(addrs);
}

/********** obtain mac & ip addresses given interface name ***********/

static void
get_interface_mac_address (interface_addresses_t *addrs)
{
    struct ifreq netif;
    unsigned char *mac;
    int fd;

    /* assume failure */
    addrs->mac_address_retreived = 0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    strcpy(netif.ifr_name, addrs->interface_name);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &netif)) {
        mac = (unsigned char*) netif.ifr_addr.sa_data;
        addrs->mac_address[0] = mac[0];
        addrs->mac_address[1] = mac[1];
        addrs->mac_address[2] = mac[2];
        addrs->mac_address[3] = mac[3];
        addrs->mac_address[4] = mac[4];
        addrs->mac_address[5] = mac[5];

        /* make a printable string version of it */
        sprintf(addrs->mac_address_printable_string,
            "%02X%02X%02X%02X%02X%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    /* not needed any more */
    close(fd);
}

static void
get_all_interface_addresses (interface_addresses_t *addrs)
{
    struct ifaddrs *ifa_list, *ifa;
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;

    /* assume everything failed */
    clear_interface_addresses(addrs);

    /* get the mac address first */
    get_interface_mac_address(addrs);

    if (getifaddrs(&ifa_list) < 0) return;
    ifa = ifa_list;
    while (ifa) {
        if (0 == strcmp(ifa->ifa_name, addrs->interface_name)) {
            addrs->interface_exists = 1;
            if (ifa->ifa_addr) {
                switch (ifa->ifa_addr->sa_family) {
                case AF_INET:
                    in = (struct sockaddr_in*) ifa->ifa_addr;
                    addrs->ipv4_address = ntohl(in->sin_addr.s_addr);
                    inet_ntop(AF_INET, &in->sin_addr,
                            addrs->ipv4_address_printable_string,
                            sizeof(addrs->ipv4_address_printable_string));
                    addrs->ipv4_address_retreived = 1;
                    break;
                case AF_INET6:
                    in6 = (struct sockaddr_in6*) ifa->ifa_addr;
                    memcpy(addrs->ipv6_address, in6->sin6_addr.s6_addr, 16);
                    inet_ntop(AF_INET6, &in6->sin6_addr,
                            addrs->ipv6_address_printable_string,
                            sizeof(addrs->ipv6_address_printable_string));
                    addrs->ipv6_address_retreived = 1;
                    break;
                default:;
                }
            }
        }
        ifa = ifa->ifa_next;
    }
    freeifaddrs(ifa_list);
}

/********** init ***********************************************************/

static void
stash_new_hostname (char *new_hostname)
{
    if (NULL == new_hostname) {
	if (gethostname(chsp->hostname_string, _NAMESIZE)) {
	    strncpy(chsp->hostname_string, no_hostname, _NAMESIZE);
	}
    } else {
	strncpy(chsp->hostname_string, new_hostname, _NAMESIZE);
    }

    chsp->hostname_string[_NAMESIZE - 1] = 0;

    /* for mem copy, include the zero termination byte */
    chsp->hostname_string_length = strlen(chsp->hostname_string) + 1;
}

/*
 * A NULL pointer or a null string represents an empty string.
 */
static void
set_string_variable (char *new_string,
    char destination[], int *length, int *changed)
{
    if (new_string && new_string[0]) {
	*changed = (strcmp(new_string, destination) != 0);
	*length = strlen(new_string) + 1;
	strcpy(destination, new_string);
    } else {
	*changed = (destination[0] != 0);
	*length = 0;
	destination[0] = 0;
    }
}

PUBLIC void
notify_gdp_about_guid_change (char *new_guid)
{
    set_string_variable(new_guid,
	chsp->unique_id_string, 
	&chsp->unique_id_string_length,
	&chsp->unique_id_string_changed);
}

PUBLIC void
notify_gdp_about_boxid_change (char *new_boxid)
{

static const char *star = "*";

    if ((NULL == new_boxid) || (new_boxid[0] == 0)) {
	new_boxid = (char*) star;
    }
    set_string_variable(new_boxid,
	chsp->boxid_string, 
	&chsp->boxid_string_length,
	&chsp->boxid_string_changed);
}

PUBLIC void
notify_gdp_about_hostname_change (char *new_hostname)
{
    stash_new_hostname(new_hostname);
    chsp->hostname_string_changed = 1;
}

PUBLIC void
notify_gdp_about_serial_number_change (char *new_serial_no)
{
    set_string_variable(new_serial_no,
	chsp->serial_number_string,
	&chsp->serial_number_string_length,
	&chsp->serial_number_string_changed);
}

PUBLIC void
notify_gdp_about_product_code_change (char *new_product_code)
{
    set_string_variable(new_product_code,
	chsp->product_code_string,
	&chsp->product_code_string_length,
	&chsp->product_code_string_changed);
}

PUBLIC void
notify_gdp_about_mgmt_interface_change (int new_mgmt_interface)
{
#if 0
    /* no real change */
    if (new_mgmt_interface == designated_mgmt_interface_number) {
	return;
    }
#endif // 0

    if (new_mgmt_interface == 0) {
        chsp->designated_mgmt_interface = &eth0_addresses;
    } else if (new_mgmt_interface == 1) {
        chsp->designated_mgmt_interface = &eth1_addresses;
    } else if (new_mgmt_interface == 2) {
        chsp->designated_mgmt_interface = &eth2_addresses;
    } else if (new_mgmt_interface == 3) {
        chsp->designated_mgmt_interface = &eth3_addresses;
    } else {
        return;
    }
    designated_mgmt_interface_number = new_mgmt_interface;
    get_all_interface_addresses(chsp->designated_mgmt_interface);
}

PUBLIC void
notify_gdp_about_an_ip_address_change (void)
{
    get_all_interface_addresses(chsp->designated_mgmt_interface);
}

/*
 * These 2 parameters do not change once the box boots up
 */
PUBLIC void
gdp_library_init (char *serial_number, char *product_code)
{
    /* get current addresses of all possibly existing interfaces */
    get_all_interface_addresses(&eth0_addresses);
    get_all_interface_addresses(&eth1_addresses);
    get_all_interface_addresses(&eth2_addresses);
    get_all_interface_addresses(&eth3_addresses);

    /* zero these out, they will come in later */
    notify_gdp_about_guid_change(NULL);
    notify_gdp_about_boxid_change(NULL);
    notify_gdp_about_hostname_change(NULL);

    /* these are passed in */
    notify_gdp_about_serial_number_change(serial_number);
    notify_gdp_about_product_code_change(product_code);
}

static void
set_type_length (type_len_t *tlp, int type, int len)
{
    /* type is only 7 bits */
    tlp->type = type;
    tlp->type <<= 1;

    /* length is 9 bits but we never exceed 255 in this code */
    tlp->len = len;
}

static void
get_type_length (type_len_t *tlp, int *type, int *len)
{
    *type = tlp->type >> 1;
    *len = tlp->len;
}

/*
 * Generic function to set a company tlv's common
 * fields for both integer & string type values.
 */
static void
set_company_specific_tlv_common (company_specific_tlv_t *tlv,
    int subtype)
{
    memset(tlv, 0, sizeof(company_specific_tlv_t));
    set_type_length(&tlv->tl, 127, COMPANY_SPECIFIC_TLV_LENGTH);
    tlv->goui.oui[0] = company_source_mac[0];
    tlv->goui.oui[1] = company_source_mac[1];
    tlv->goui.oui[2] = company_source_mac[2];
    tlv->goui.company_subtype = subtype;
}

/*
 * Generic function to set a company tlv to a specified 
 * subtype and an integer value
 */
static void
set_company_integer_tlv (company_specific_tlv_t *tlv,
    int subtype, int value)
{
    set_company_specific_tlv_common(tlv, subtype);
    tlv->goui.u.integer = htonl(value);
}

/*
 * Generic function to set a company tlv to a specified 
 * subtype and a 0 terminated string
 *
 * ASSUMES LENGTH DOES NOT EXCEED TLV SPACE.
 */
static void
set_company_string_tlv (company_specific_tlv_t *tlv,
    int subtype, char *string, int string_length)
{
    set_company_specific_tlv_common(tlv, subtype);
    memcpy(tlv->goui.u.string, string, string_length);
}

static void
gdp_packet_set_company_hostname_tlv (gdp_packet_t *pak,
    char *hostname_string, int hostname_string_length)
{
    set_company_string_tlv(&pak->company_hostname_tlv, 
        COMPANY_CHASSIS_HOSTNAME_SUBTYPE,
	hostname_string, hostname_string_length);
}

static void
gdp_packet_set_company_chassis_serial_number_tlv (gdp_packet_t *pak,
    char *serial_number_string, int serial_number_string_length)
{
    set_company_string_tlv(&pak->company_chassis_serial_number_tlv, 
        COMPANY_CHASSIS_SERIAL_NUMBER_SUBTYPE,
	serial_number_string, serial_number_string_length);
}

static void
gdp_packet_set_company_chassis_product_code_tlv (gdp_packet_t *pak,
    char *product_code_string, int product_code_string_length)
{
    set_company_string_tlv(&pak->company_chassis_product_code_tlv, 
        COMPANY_CHASSIS_PRODUCT_CODE_SUBTYPE,
	product_code_string, product_code_string_length);
}

static void
gdp_packet_set_company_port_type_tlv (gdp_packet_t *pak,
    char *port_type_string, int port_type_string_length)
{
    set_company_string_tlv(&pak->company_port_type_tlv, 
        COMPANY_PORT_TYPE_SUBTYPE, 
	port_type_string, port_type_string_length);
}

static int 
company_specific_tlv_verified (company_specific_tlv_t *tlv)
{
    int type, len;

    get_type_length(&tlv->tl, &type, &len);
    if ((type != 127) || (len != COMPANY_SPECIFIC_TLV_LENGTH)) {
	return 0;
    }
    return
	(tlv->goui.oui[0] == company_source_mac[0]) &&
	(tlv->goui.oui[1] == company_source_mac[1]) &&
	(tlv->goui.oui[2] == company_source_mac[2]);
}

/*
 * This is a very comprehensive check.  If it slows down
 * gdp packet processing, we may loosen it a bit in the future.
 */
PUBLIC int
packet_is_a_gdp_packet (byte *destination_mac_start, int packet_size)
{
    gdp_packet_t *pak = (gdp_packet_t*) destination_mac_start;

    return
	(packet_size >= gdp_packet_size)
#if 0
	&& company_specific_tlv_verified(&pak->company_hostname_tlv)
	&& company_specific_tlv_verified(&pak->company_chassis_serial_number_tlv)
	&& company_specific_tlv_verified(&pak->company_chassis_product_code_tlv)
	&& company_specific_tlv_verified(&pak->company_port_type_tlv)
#endif // 0
	&& (pak->src_mac[0] == company_source_mac[0])
	&& (pak->src_mac[1] == company_source_mac[1])
	&& (pak->src_mac[2] == company_source_mac[2])
	&& (pak->src_mac[3] == company_source_mac[3])
	&& (pak->src_mac[4] == company_source_mac[4])
	&& (pak->src_mac[5] == company_source_mac[5]);
}

PUBLIC int
get_gdp_tlv_company_specific_subtype (const void *oui_start)
{
    const company_oui_and_rest_t *goui =
	(company_oui_and_rest_t*) oui_start;

    return
	goui->company_subtype;
}

PUBLIC void
get_company_specific_tlv_string_value (const void *oui_start,
    char *string_returned)
{
    const company_oui_and_rest_t *goui =
	(company_oui_and_rest_t*) oui_start;

    strcpy(string_returned, goui->u.string);
}

PUBLIC void
get_company_specific_tlv_integer_value (const void *oui_start,
    int *integer_returned)
{
    const company_oui_and_rest_t *goui =
	(company_oui_and_rest_t*) oui_start;

    *integer_returned = ntohl(goui->u.integer);
}

/********** chassis id tlv processing **************************************/

static void
gdp_packet_set_chassis_id_tlv (gdp_packet_t *pak,
    char *chassis_id_string, int chassis_id_string_length)
{
    lldp_chassis_id_tlv_t *tlv = &pak->chassis_id_tlv;

    memset(tlv, 0, sizeof(lldp_chassis_id_tlv_t));
    set_type_length(&tlv->tl, 1, sizeof(chassis_id_tlv_value_t));
    tlv->chassis_id_value.chassis_id_subtype = 6;
    memcpy(tlv->chassis_id_value.chassis_printable_name, 
	chassis_id_string, chassis_id_string_length);
}

/********** port id tlv processing **************************************/

static void 
gdp_packet_set_port_id_tlv (gdp_packet_t *pak,
    char *port_name, int port_name_length)
{
    lldp_port_id_tlv_t *tlv = &pak->port_id_tlv;

    memset(tlv, 0, sizeof(lldp_port_id_tlv_t));
    set_type_length(&tlv->tl, 2, sizeof(lldp_port_id_tlv_value_t));
    tlv->port_id_value.port_id_subtype = 5;
    memcpy(&tlv->port_id_value.port_printable_name[0],
	    port_name, port_name_length);
}

/********** ttl tlv processing **************************************/

static void
gdp_packet_set_ttl_tlv (gdp_packet_t *pak, int seconds)
{
    set_type_length(&pak->ttl_tlv.tl, 3, sizeof(pak->ttl_tlv.value));
    pak->ttl_tlv.value = htons(seconds);
}

/********** lldp management address tlv processing *******************/

/*
 * This function sets the management addresses of ONE interface (specified
 * by 'addrs'), into the GDP packet.  It writes both the ipv4 and ipv6
 * information.  This will be called for all interfaces to populate
 * all the tlvs defined in our packet structure.
 *
 * THE ENCODING HERE IS VERY IMPORTANT.
 *
 * If an interface does not exist, the 'interface_numbering_subtype'
 * is set to 1 (Unknown).  This should always be the FIRST parameter
 * that should be checked on the receiver side.  It gives an indication
 * whether a certain interface (depicted by 'interface_number') exists
 * on a specific node or not.  If the interface exists, this field will
 * be set to 3 (system port number).
 *
 * If an interface does indeed exist (as deduced from the check above),
 * then the field 'management_address_subtype' determines whether an
 * address is assigned to this interface.  These values are taken from the
 * 'IANA Address Family Numbers'.  The value 1 represents an ipv4
 * address and the value 2 represents an ipv6 address.  If neither
 * an ipv4 nor an ipv6 address is assigned to the interface, LLDP
 * spec stipulates that the mac address is placed in the field instead.
 * The value is 6 used for this.  If even the mac address could
 * not be obtained (usually a fault condition), then the value of 0
 * will be placed in this field.  0 is meant to be reserved but in this
 * situation, it will be overloaded to mean 'nothing'.
 *
 * Finally, the field 'interface_number' represents interfaces
 * eth0, eth1, eth2 and eth3 for values 0, 1, 2 and 3 respectively.
 * Since the tlv's in the packet are actually positionally fixed,
 * this distinction is not really needed but is present for completeness.
 */
static void 
gdp_packet_set_mgmt_addrs_tlv (gdp_packet_t *pak, 
        interface_addresses_t *addrs)
{
    lldp_management_address_tlv_t *tlv = &pak->mgmt_address_tlv;

    set_type_length(&tlv->tl, 8, MGMT_ADDRESS_TLV_LENGTH);
    tlv->interface_number = htonl(addrs->interface_number);
    tlv->management_address_string_length = MANAGEMENT_ADDRESS_STRING_LENGTH;
    tlv->oid_string_length = 0;
    tlv->interface_numbering_subtype =
        addrs->interface_exists ?
            INTERFACE_NUMBERING_SUBTYPE_EXISTS :
            INTERFACE_NUMBERING_SUBTYPE_UNKNOWN;
    if (addrs->ipv4_address_retreived) {
        tlv->management_address_subtype = MANAGEMENT_ADDRESS_SUBTYPE_IPV4;
        tlv->address.ipv4_address = htonl(addrs->ipv4_address);
    } else if (addrs->ipv6_address_retreived) {
        tlv->management_address_subtype = MANAGEMENT_ADDRESS_SUBTYPE_IPV6;
        memcpy(tlv->address.ipv6_address, addrs->ipv6_address, 16);
    } else if (addrs->mac_address_retreived) {
        tlv->management_address_subtype = MANAGEMENT_ADDRESS_SUBTYPE_MAC;
        memcpy(tlv->address.mac_address, addrs->mac_address, 6);
    } else {
        /* we could not even obtain the mac address */
        tlv->management_address_subtype = MANAGEMENT_ADDRESS_SUBTYPE_NONE;
        memset(&tlv->address, 0, sizeof(management_address_t));
    }
}

#if 0

/*
 * reverse of the above, it extracts the required interface information
 * from the gdp packet.  The information is placed into 'addrs'.
 * The user fills in the 'interface_number' in the 'addrs' structure
 * to extract it from the packet.
 */
void
gdp_packet_get_mgmt_addrs (byte *destination_mac_start,
    interface_addresses_t *addrs)
{
    gdp_packet_t *pak = (gdp_packet_t*) destination_mac_start;
    lldp_management_address_tlv_t *tlv;
    int type, length;
    byte *mac;

    /* start fresh */
    clear_interface_addresses(addrs);

    tlv = &pak->mgmt_address_tlv;
    get_type_length(&tlv->tl, &type, &length);
    if ((8 != type) || (MGMT_ADDRESS_TLV_LENGTH != length))
        return;

    /* interface does not exist on the peer */
    if (tlv->interface_numbering_subtype != INTERFACE_NUMBERING_SUBTYPE_EXISTS)
        return;

    /* if we are here, interface exists */
    addrs->interface_exists = 1;

    /* does it have an ip v4 address assigned ? */
    if (MANAGEMENT_ADDRESS_SUBTYPE_IPV4 == tlv->management_address_subtype) {
        addrs->ipv4_address = ntohl(tlv->address.ipv4_address);
        addrs->ipv4_address_retreived = 1;
        inet_ntop(AF_INET, &addrs->ipv4_address,
            addrs->ipv4_address_printable_string,
            sizeof(addrs->ipv4_address_printable_string));
    } else if (MANAGEMENT_ADDRESS_SUBTYPE_IPV6 == 
		tlv->management_address_subtype) {
        memcpy(addrs->ipv6_address, tlv->address.ipv6_address, 16);
        addrs->ipv6_address_retreived = 1;
        inet_ntop(AF_INET6, addrs->ipv6_address,
            addrs->ipv6_address_printable_string,
            sizeof(addrs->ipv6_address_printable_string));
    } else if (MANAGEMENT_ADDRESS_SUBTYPE_MAC ==
		tlv->management_address_subtype) {
        mac = tlv->address.mac_address;
        addrs->mac_address_retreived = 1;
        memcpy(addrs->mac_address, mac, 6);
        sprintf(addrs->mac_address_printable_string,
            "%02X%02X%02X%02X%02X%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

#endif // 0

/********** gdp packet creation/check ********************************/

/*
 * This function initializes a packet with the tlvs which
 * will NOT change.  For other tlvs which will/may change
 * call 'update_gdp_packet' function before transmitting it.
 */
PUBLIC void
gdp_packet_init (byte *bytes)
{
    gdp_packet_t *pak = (gdp_packet_t*) bytes;

    /* zero out the packet first */
    memset(pak, 0, sizeof(pak));

    /* mac addresses */
    memcpy(pak->dst_mac, lldp_destination_mac_address, 6);
    memcpy(pak->src_mac, company_source_mac, 6);

    /* lldp ethertype */
    pak->ethertype[0] = 0x88;
    pak->ethertype[1] = 0xCC;

    /* time to live tlv */
    gdp_packet_set_ttl_tlv(pak, GDP_PEER_TIMEOUT);
}

/*
 * This function updates what MAY change from one transmission to the next.
 * This will DEFINITELY be the port id tlv since we use the same packet
 * repetitevly for each port.  But it MAY also be the chassis id tlv (in case
 * hostname or mac address changed) and the management addresses tlv (in case
 * ip addresses on management interfaces changed).
 */
PUBLIC void
update_gdp_packet (byte *bytes,
	char *port_name_string, char *port_type_string)
{
    gdp_packet_t *pak = (gdp_packet_t*) bytes;
    char port_name_with_boxid [_NAMESIZE];

    /* company specific unique chassis hostid */
    gdp_packet_set_chassis_id_tlv(pak,
	chsp->unique_id_string,
	chsp->unique_id_string_length);

    sprintf(port_name_with_boxid,
	"%s/%s", chsp->boxid_string, port_name_string);
    gdp_packet_set_port_id_tlv(pak,
	port_name_with_boxid, (strlen(port_name_with_boxid) + 1));

    gdp_packet_set_mgmt_addrs_tlv(pak, chsp->designated_mgmt_interface);

    gdp_packet_set_company_hostname_tlv(pak,
	chsp->hostname_string, chsp->hostname_string_length);

    gdp_packet_set_company_chassis_serial_number_tlv(pak,
	chsp->serial_number_string,
	chsp->serial_number_string_length);

    /* company specific chassis product code tlv */
    gdp_packet_set_company_chassis_product_code_tlv(pak,
	chsp->product_code_string,
	chsp->product_code_string_length);

    gdp_packet_set_company_port_type_tlv(pak,
	port_type_string, (strlen(port_type_string) + 1));
}

#ifdef __cplusplus
} // end of extern C
#endif







