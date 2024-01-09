#include <err.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

struct iface {
	char *name;
	pcap_t *cap;
};

struct worker_args {
	struct iface *ifaces;
	int cap_index;
	int inj_index;
};

pcap_t *create_pcap(const char *dev, const char *filter) {
	int ret;
	char cap_eb[PCAP_ERRBUF_SIZE];
	struct bpf_program prog;
	pcap_t *cap;

	memset(cap_eb, 0, PCAP_ERRBUF_SIZE);

	cap = pcap_create(dev, cap_eb);
	if (!cap)
		errx(1, "Could not create pcap handle: %.*s", PCAP_ERRBUF_SIZE, cap_eb);

	ret = pcap_set_immediate_mode(cap, true);
	if (ret != 0)
		errx(1, "Failed to set immediate mode: %s", pcap_geterr(cap));

	ret = pcap_activate(cap);
	if (ret < 0)
		errx(1, "Failed to activate capture: %s", pcap_geterr(cap));
	else if (ret > 0)
		warnx("Capture active with warnings: %s", pcap_geterr(cap));

	ret = pcap_compile(cap, &prog, filter, /*optimize*/ 1, PCAP_NETMASK_UNKNOWN);
	if (ret != 0)
		errx(1, "Failed to compile filter: %s", pcap_geterr(cap));

	ret = pcap_setfilter(cap, &prog);
	if (ret != 0)
		errx(1, "Failed to attach filter: %s", pcap_geterr(cap));

	return cap;
}

void cap_callback(u_char *data, const struct pcap_pkthdr *hdr, const u_char *bytes) {
	pcap_t *inj = (pcap_t *)data;
	int ret;

#if 0
	warnx("Got a packet: %p [%u]", bytes, hdr->caplen);
#endif

	if (hdr->caplen < hdr->len)
		warnx("warning: Captured only %u out of %u bytes", hdr->caplen, hdr->len);

	ret = pcap_sendpacket(inj, bytes, hdr->caplen);
	if (ret != 0)
		warnx("Could not inject packet: %s", pcap_geterr(inj));
}

void *cap_thread_worker(void *args) {
	struct worker_args a = *((struct worker_args *)args);
	struct iface cap = a.ifaces[a.cap_index];
	struct iface inj = a.ifaces[a.inj_index];
	int ret;

	warnx("Capturing on %s, injecting on %s", cap.name, inj.name);

	ret = pcap_loop(cap.cap, /*count*/ -1, cap_callback, (u_char *) inj.cap);
	if (ret < 0)
		errx(1, "Failed to start capture loop: %s", pcap_geterr(cap.cap));

	return NULL;
}

void start_pipe(char *devs[], pcap_t *pcaps[]) {
	int i, ret;
	pthread_t threads[2];
	struct iface ifaces[2] = {
		{devs[0], pcaps[0]},
		{devs[1], pcaps[1]},
	};
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
	int opt;
	char *devs[2];
	pcap_t *pcaps[2];

	while ((opt = getopt(argc, argv, "a:b:")) != -1) {
		switch (opt) {
		case 'a':
			devs[0] = optarg;
			break;
		case 'b':
			devs[1] = optarg;
			break;
		default:
			errx(2, "Usage: %s -a <iface> -b <iface>", argv[0]);
		}
	}

	if (!devs[0] || !devs[1])
		errx(2, "error: Interfaces not specified");

	pcaps[0] = create_pcap(devs[0], filter);
	pcaps[1] = create_pcap(devs[1], filter);
	
	start_pipe(devs, pcaps);
	return 0;
}
