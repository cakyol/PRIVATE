

static boolean 
linux_network_interface_flag_set (char *ifname, int flag) 
{
    int dummy_fd;
    struct ifreq ifr;
    int rv;
    
    dummy_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (dummy_fd < 0) return false;

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);
    rv = ioctl(dummy_fd, SIOCGIFFLAGS, &ifr);
    close(dummy_fd);
    if (rv == -1) return false;
    return ifr.ifr_flags & flag;
}

boolean
linux_network_interface_admin_state_up (char *ifname)
{
    return
        linux_network_interface_flag_set(ifname, IFF_UP);
}

boolean
linux_network_interface_link_up (char *ifname)
{
    return
        linux_network_interface_flag_set(ifname, IFF_LOWER_UP);
}


