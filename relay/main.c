#include <err.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

struct iface {
	char *name;
	pcap_t *pcap;
};

struct worker_args {
	struct iface *ifaces;
	int cap_index;
	int inj_index;
};

pcap_t *create_pcap(const char *dev, const char *filter) {
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program prog;
	pcap_t *pcap;

	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	pcap = pcap_create(dev, errbuf);
	if (!pcap)
		errx(1, "Could not create pcap handle: %.*s", PCAP_ERRBUF_SIZE, errbuf);

	ret = pcap_set_snaplen(pcap, 65535);
	if (ret != 0)
		errx(1, "Failed to set snapshot length: %s", pcap_geterr(pcap));

	ret = pcap_set_immediate_mode(pcap, true);
	if (ret != 0)
		errx(1, "Failed to set immediate mode: %s", pcap_geterr(pcap));

	ret = pcap_activate(pcap);
	if (ret < 0)
		errx(1, "Failed to activate capture: %s", pcap_geterr(pcap));
	else if (ret > 0)
		warnx("Capture active with warnings: %s", pcap_geterr(pcap));

	ret = pcap_compile(pcap, &prog, filter, /*optimize*/ 1, PCAP_NETMASK_UNKNOWN);
	if (ret != 0)
		errx(1, "Failed to compile filter: %s", pcap_geterr(pcap));

	ret = pcap_setfilter(pcap, &prog);
	if (ret != 0)
		errx(1, "Failed to attach filter: %s", pcap_geterr(pcap));

	return pcap;
}

char *fmt_mac(const u_char buf[6]) {
	static char str[18];
	snprintf(str, sizeof(str),
		"%02X:%02X:%02X:%02X:%02X:%02X",
		buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
	return str;
}

char *whose_mac(const u_char buf[6]) {
	if (memcmp(buf, "\x18\xFD\x74\x71\x50\x0E", 6) == 0)
		return "WindGW";
	if (memcmp(buf, "\x18\xFD\x74\x73\xC5\x3A", 6) == 0)
		return "DuneGW";
	if (memcmp(buf, "\x6C\x3B\x6B\x4C\x3B\x9C", 6) == 0)
		return "EmberGW";
	if (memcmp(buf, "\xD4\xCA\x6D\xDD\x8C\xBA", 6) == 0)
		return "KST AP [ether1]";
	if (memcmp(buf, "\xD4\xCA\x6D\xDD\x8C\xBE", 6) == 0)
		return "KST AP [ether5]";
	if (memcmp(buf, "\x6C\x3B\x6B\xC0\x00\xBA", 6) == 0)
		return "GW-B56 [sfp1]";
	if (memcmp(buf, "\x6C\x3B\x6B\xC0\x00\xBE", 6) == 0)
		return "GW-B56 [ether1]";
	if (memcmp(buf, "\x6C\x3B\x6B\xC0\x00\xBF", 6) == 0)
		return "GW-B56 [ether2]";
	if (memcmp(buf, "\xE4\x8D\x8C\x7B\x5A\x84", 6) == 0)
		return "GW-Mai18 [ether1]";
	if (memcmp(buf, "\xE4\x8D\x8C\x7B\x5A\x85", 6) == 0)
		return "GW-Mai18 [ether2]";
	return "?";
}

#define ETH_ALEN 6

void cap_callback(u_char *data, const struct pcap_pkthdr *hdr, const u_char *buf) {
	pcap_t *inj = (pcap_t *)data;
	int ret;

#if 0
	warnx("Got a packet: %p [%u]", buf, hdr->caplen);
#endif

	if (hdr->caplen < hdr->len)
		warnx("warning: Captured only %u out of %u bytes", hdr->caplen, hdr->len);

#if 0
	ret = pcap_sendpacket(inj, buf, hdr->caplen);
	if (ret != 0)
		warnx("Could not inject packet: %s", pcap_geterr(inj));
#endif

	const u_char *ptr = buf;
	const u_char *end = buf + hdr->caplen;
	const u_char *dst_mac = ptr; ptr += ETH_ALEN;
	const u_char *src_mac = ptr; ptr += ETH_ALEN;
	uint16_t ethertype = (ptr[0] << 8) | (ptr[1]); ptr += 2;
	if (!strcmp(whose_mac(src_mac), "KST AP [ether5]"))
		return;
	//warnx("Dst: %s", fmt_mac(dst_mac));
	warnx("Src: %s (%s)", fmt_mac(src_mac), whose_mac(src_mac));
	warnx("Type: %04x", ethertype);
	warnx("Payload: %lu bytes", end - ptr);

	uint16_t maybe_type = (ptr[0] << 8) | (ptr[1]); ptr += 2;
	warnx("- Maybe type: %04x", maybe_type);
	uint16_t frame_len = (ptr[0] << 8) | (ptr[1]); ptr += 2;
	warnx("- Total frame length: %u (%s)", frame_len,
		frame_len == hdr->len ? "OK" : "not ok");
	for (int i = 0; i < end-ptr; i++) {
		printf("%02x ", ptr[i]);
	}
	printf("\n\n");
}

void *cap_thread_worker(void *args) {
	struct worker_args a = *((struct worker_args *)args);
	struct iface cap = a.ifaces[a.cap_index];
	struct iface inj = a.ifaces[a.inj_index];
	int ret;

	warnx("Capturing on %s, injecting on %s", cap.name, inj.name);

	ret = pcap_loop(cap.pcap, /*count*/ -1, cap_callback, (u_char *) inj.pcap);
	if (ret < 0)
		errx(1, "Failed to start capture loop: %s", pcap_geterr(cap.pcap));

	return NULL;
}

void start_pipe(struct iface *ifaces) {
	int i, ret;
	pthread_t threads[2];
	struct worker_args args[2] = {
		{ifaces, 0, 1},
		{ifaces, 1, 0},
	};

	for (i = 0; i < 2; i++) {
		char name[16];

		ret = pthread_create(&threads[i], NULL,
				cap_thread_worker, &args[i]);
		if (ret < 0)
			err(1, "pthread_create failed");

		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name)-1, "[%.6s>%.6s]",
				ifaces[args[i].cap_index].name,
				ifaces[args[i].inj_index].name);
		ret = pthread_setname_np(threads[i], name);
		if (ret < 0)
			err(1, "pthread_setname_np failed");

	}
	for (i = 0; i < 2; i++) {
		ret = pthread_join(threads[i], NULL);
		if (ret < 0)
			err(1, "pthread_join failed");
	}
}

int main(int argc, char *argv[]) {
	const char *filter = "ether proto 0x88bf";
	int i, opt;
	struct iface ifaces[2];

	while ((opt = getopt(argc, argv, "a:b:")) != -1) {
		switch (opt) {
		case 'a':
			ifaces[0].name = optarg;
			break;
		case 'b':
			ifaces[1].name = optarg;
			break;
		default:
			errx(2, "Usage: %s -a <iface> -b <iface>", argv[0]);
		}
	}

	for (i = 0; i < 2; i++) {
		if (!ifaces[i].name)
			errx(2, "error: Interfaces not specified");

		ifaces[i].pcap = create_pcap(ifaces[i].name, filter);
	}

	start_pipe(ifaces);
	return 0;
}
