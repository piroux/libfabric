
char *
get_devname(uint32_t version, struct usd_device_attrs *dap)
{
	char *bufp;
	struct in_addr in;
	char *addrnetw;
	size_t size;

	if (FI_VERSION_GE(version, FI_VERSION(1, 4))) {
		in.s_addr = dap->uda_ipaddr_be & dap->uda_netmask_be;
		addrnetw = inet_ntoa(in);
		size = snprintf(NULL, 0, "%s/%d", addrnetw, dap->uda_prefixlen) + 1;
		bufp = calloc(1, size);
		sprintf(bufp, "%s/%d", addrnetw, dap->uda_prefixlen);
	} else {
		bufp = strdup(dap->uda_devname);
	}

	return bufp;
}

void debugme(struct fi_fabric_attr *fattrp, struct usd_device_attrs *dap)
{
	struct in_addr in;
	char *addrnetw;
	//char devname[40];

	USDF_DBG("NOW: ipaddr_be:(%d) prefixlen:(%d)\n",
		  dap->uda_ipaddr_be, dap->uda_prefixlen);

	in.s_addr = dap->uda_ipaddr_be;
	addrnetw = inet_ntoa(in);
	USDF_DBG("NOW: ipaddr_be(converted):(%s)\n",
		 addrnetw);

	uint32_t nmask = (0xFFFFFFFF >> (32 - dap->uda_prefixlen)) & 0xFFFFFFFF; // switch >> to << for LE
	USDF_DBG("NOW: netmask(computed): %#010x\n",
		 nmask);

	in.s_addr = dap->uda_ipaddr_be & nmask;
	addrnetw = inet_ntoa(in);
	USDF_DBG("NOW: ipaddr_be(network):(%s)\n",
		 addrnetw);

	USDF_DBG("NOW: netmask_be (embed): %#010x\n",
		 dap->uda_netmask_be);

	in.s_addr = dap->uda_ipaddr_be & dap->uda_netmask_be;
	addrnetw = inet_ntoa(in);
	USDF_DBG("NOW: ipaddr_be(network2):(%s)\n",
		 addrnetw);
}

enum check_devname_func_t {
	CHECK_DEVNAME_GETINFO,
	CHECK_DEVNAME_FABRIC
};

int
check_devname(uint32_t version, struct usd_device_attrs *dap, struct fi_fabric_attr *fattrp,
		enum check_devname_func_t caller)
{
	int ret;
	char *devname;

	char* devname_1_3 = get_devname(FI_VERSION(1,3), dap);
	char* devname_1_4 = get_devname(FI_VERSION(1,4), dap);

	//fprintf(stderr, "CHECK_DEVNAME (version=%d) (devname='%s')\n", version, fattrp->name);

	switch(caller) {
		case CHECK_DEVNAME_GETINFO:
			devname = get_devname(version, dap);
			if (FI_VERSION_GE(version, FI_VERSION(1, 4))) {
				ret = strcmp(devname, devname_1_4);
			} else {
				ret = strcmp(devname, devname_1_3);
			}
			free(devname);
			break;

		case CHECK_DEVNAME_FABRIC:
			devname = fattrp->name;
			ret = strcmp(devname, devname_1_4);
			if (ret)
				ret = strcmp(devname, devname_1_3);
			break;
	}


	free(devname_1_3);
	free(devname_1_4);
	
	if (ret == 0)
		return 1;
	else
		return 0;
}

