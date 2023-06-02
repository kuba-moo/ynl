#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <ynl.h>

#include "psp-user.h"

static unsigned long long now_usec(void)
{
	struct timeval now;

	gettimeofday(&now, 0);
	return now.tv_sec * 1000 * 1000 + now.tv_usec;
}

static int sock_with_rxassoc(struct ynl_sock *ys, unsigned int dev_id)
{
	struct psp_rx_assoc_rsp *rsp;
	struct psp_rx_assoc_req *req;
	int sock;

	sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock < 0)
		return 1;

	req = calloc(1, sizeof(*req));
	psp_rx_assoc_req_set_dev_id(req, dev_id);
	psp_rx_assoc_req_set_sock_fd(req, sock);
	psp_rx_assoc_req_set_version(req, PSP_VERSION_HDR0_AES_GCM_128);

	rsp = psp_rx_assoc(ys, req);
	free(req);

	if (!rsp) {
		close(sock);
		return 2;
	}

	psp_rx_assoc_rsp_free(rsp);

	close(sock);
	return 0;
}

int main(int argc, char **argv)
{
	struct psp_dev_get_list *dev_list;
	unsigned long long start, end;
	struct ynl_error yerr;
	struct ynl_sock *ys;
	unsigned int total;
	int first_id = 0;
	int i;

	ys = ynl_sock_create(&ynl_psp_family, &yerr);
	if (!ys) {
		fprintf(stderr, "YNL: %s\n", yerr.msg);
		return 1;
	}

	dev_list = psp_dev_get_dump(ys);
	if (ynl_dump_empty(dev_list)) {
		if (ys->err.code)
			goto err_close;
		printf("No PSP devices\n");
		goto exit_close;
	}
	printf("PSP devices:\n");
	ynl_dump_foreach(dev_list, d) {
		if (!first_id)
			first_id = d->id;
		printf(" [%d]: ifindex %d versions [cap:%d ena:%d]\n",
		       d->id, d->ifindex,
		       d->psp_versions_cap, d->psp_versions_ena);
	}
	psp_dev_get_list_free(dev_list);

	start = end = now_usec();
	total = 0;
	while (end - start < 1000 * 1000) {
		total += 4000;
		for (i = 0; i < 4000; i++)
			if (sock_with_rxassoc(ys, first_id))
				goto err_close;
		end = now_usec();
	}

	printf("Rx alloc: %.2lf\n", (double)total / (end - start) * 1000 * 1000);

exit_close:
	ynl_sock_destroy(ys);

	return 0;

err_close:
	fprintf(stderr, "YNL: %s\n", ys->err.msg);
	ynl_sock_destroy(ys);
	return 2;
}
