/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <rte_malloc.h>
#include <rte_net.h>

#define DEBUG_MODE 0

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define TIMER_PERIOD 10 /* Time period for port statistics printing, in seconds. To diable statistics printing, set this value to 0*/


/* mirrorfwd.c: DPDK forwarding app acting like a mirror */


static uint32_t my_ip = RTE_IPV4(143, 248, 41, 17);
static uint32_t target_ip_1 = RTE_IPV4(143, 248, 47, 98);
static uint32_t target_ip_2 = RTE_IPV4(143, 248, 47, 99);

/* Needed if using hard-coded IP-to-MAC resolution */
static struct rte_ether_addr target_ip_1_mac = {
	.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};
static struct rte_ether_addr target_ip_2_mac = {
	.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};

static uint64_t timer_period_tsc;

// #define PKT_IS_IP_HDR(m) (RTE_ETH_IS_IPV4_HDR(m->packet_type) || RTE_ETH_IS_IPV6_HDR(m->packet_type))
#define IS_UDP_HDR(ptype) ((ptype) & RTE_PTYPE_L4_UDP)
#define IS_TCP_HDR(ptype) ((ptype) & RTE_PTYPE_L4_TCP)

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

/* Per-port statistics struct */
struct mirrorfwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct mirrorfwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

/* Print out statistics on each port */
static void
print_stats(void)
{
	uint64_t total_packets_droppped, total_packets_tx, total_packets_rx;
	unsigned portid;

	total_packets_droppped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ========================================");

	RTE_ETH_FOREACH_DEV(portid) {
		printf("\nStatistics for port %u ------------------------------"
				"\nPackets sent: %24"PRIu64
				"\nPackets received: %20"PRIu64
				"\nPackets dropped: %21"PRIu64,
				portid,
				port_statistics[portid].tx,
				port_statistics[portid].rx,
				port_statistics[portid].dropped);
		
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
		total_packets_droppped += port_statistics[portid].dropped;
	}

	printf("\nAggregate statistics =============================="
			"\nTotal packets sent: %18"PRIu64
			"\nTotal packets received: %14"PRIu64
			"\nTotal packets dropped: %15"PRIu64,
			total_packets_tx,
			total_packets_rx,
			total_packets_droppped);
	printf("\n==================================================");

	fflush(stdout);
}

/* Hard-coded IP-to-MAC resolution function */
struct rte_ether_addr get_mac_from_ip(uint32_t ip) {
	if (ip == target_ip_1)
		return target_ip_1_mac;

	else if (ip == target_ip_2)
		return target_ip_2_mac;

	else
		rte_exit(EXIT_FAILURE, "get_mac_from_ip() only works for the two target IP addresses!\n");
}

// /* Check if a given packet is a RoCEv2 packet */
// int is_rocev2_pkt(struct rte_mbuf *m) {
// 	if (!(RTE_ETH_IS_IPV4_HDR(m->packet_type) || RTE_ETH_IS_IPV6_HDR(m->packet_type)))
// 		return 0;
// 	if (!(IS_UDP_HDR(m->packet_type)))
// 		return 0;
	
// 	uint16_t dst_port;
// 	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

// 	if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) {
// 		struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
// 		struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
// 		dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
// 	}
// 	else if (RTE_ETH_IS_IPV6_HDR(m->packet_type)) {
// 		struct rte_ipv6_hdr *ip_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
// 		struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
// 		dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
// 	}

// 	if (dst_port != 4791)
// 		return 0;

// 	return 1;
// }

/* Check if given packet's src IP matches target IP(v4) */
uint32_t is_target_pkt(struct rte_mbuf *m) {

	if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) {
		struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + m->l2_len);
		uint32_t src_ip = rte_be_to_cpu_32(ip_hdr->src_addr);
		uint32_t dst_ip = rte_be_to_cpu_32(ip_hdr->dst_addr);

		if (src_ip == target_ip_1 && dst_ip == my_ip)
			return target_ip_2;
		else if (src_ip == target_ip_2 && dst_ip == my_ip)
			return target_ip_1;
		else
			return 0;
	}
	
	else
		return 0;
}


/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Initialize TX buffers */
	tx_buffer[port] = rte_zmalloc_socket("tx_buffer",
			RTE_ETH_TX_BUFFER_SIZE(BURST_SIZE), 0,
			rte_eth_dev_socket_id(port));
	if (tx_buffer[port] == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n", port);
	rte_eth_tx_buffer_init(tx_buffer[port], BURST_SIZE);
	retval = rte_eth_tx_buffer_set_err_callback(tx_buffer[port],
			rte_eth_tx_buffer_count_callback,
			&port_statistics[port].dropped);
	if (retval < 0)
		rte_exit(EXIT_FAILURE, "Cannot set error callback for tx buffer on port %u\n", port);
	
	/* End of Initializing TX buffers */


	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));


	/* If this port is virtio port, then pass..*/
	char portname[32];
	char virtio_user[] = "virtio_user";
	rte_eth_dev_get_name_by_port(port, portname);
	if (strncmp(virtio_user, portname, 11) == 0)
		return 0;
	/* Q. Why is setting promiscous mode for virtio ports not working..? */

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and taking proper actions.
 */

 /* Mirror forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(void)
{
	uint16_t port;
	int i;
	struct rte_mbuf *m;
	struct rte_ether_hdr *eth_hdr;
	uint16_t eth_type;
	unsigned nb_ports, nb_pports;
	struct rte_eth_dev_tx_buffer *buffer;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	uint16_t sent;
	unsigned lcore_id;

	prev_tsc = 0;
	timer_tsc = 0;
	timer_period_tsc = TIMER_PERIOD * rte_get_timer_hz();

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	lcore_id = rte_lcore_id();
	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			lcore_id);

	/* Check the number of available ports. It should be even number. */
	nb_ports = rte_eth_dev_count_avail();
	printf("%u ports are available.\n", nb_ports);
	if (nb_ports % 2 != 0)
		rte_exit(EXIT_FAILURE, "The number of available ports are not even!\n");

	nb_pports = nb_ports / 2;
	printf("%u ports are physical ones.\n", nb_pports);

	/* Main work of application loop. 8< */
	for (;;) {

		/* Drains TX queues. 8< */
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;

		if (unlikely(diff_tsc > drain_tsc)) {
			RTE_ETH_FOREACH_DEV(port) {
				buffer = tx_buffer[port];
				sent = rte_eth_tx_buffer_flush(port, 0, buffer);
				if (sent) {
					port_statistics[port].tx += sent;
#ifdef DEBUG_MODE
					printf("lcore_main(): %u pkts were flushed to port %u!\n", sent, port);
#endif
				}
			}

			/* if timer is enabled */
			if (timer_period_tsc > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timeout */
				if (unlikely(timer_tsc >= timer_period_tsc)) {

					/* print stats only on main core */
					if (lcore_id == rte_get_main_lcore()) {
						print_stats();

						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}
		/* >8 End of draining TX queues. */

		/*
		 * Receive packets on a port.
		 * For physical ports:
		 *   Packets of interest (srcIP-matched pkts) are mirrored.
		 *   Other packets are passed to kernel stack via virtio port.
		 * For virtio ports:
		 *   Read packets and forward them back to corresponding physical port
		 */
		RTE_ETH_FOREACH_DEV(port) {

			/* for physical ports 8< */
			if (port < nb_pports) {
				
				/* Get burst of RX packets */
				struct rte_mbuf *bufs[BURST_SIZE];
				const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
						bufs, BURST_SIZE);

				if (unlikely(nb_rx == 0))
					continue;

				port_statistics[port].rx += nb_rx;
#ifdef DEBUG_MODE
				printf("lcore_main(): %u pkts were received on port %u!\n", nb_rx, port);
#endif

				for (i = 0; i < nb_rx; i++) {
					m = bufs[i];

					// /* if packet is RoCEv2 */
					// if (is_rocev2_pkt(m)) {
					// 	printf("Received RoCEv2 pkt!\n");
					// }

					/* if packet type recognition by HW is not working, get packet type in SW */
					if (m->packet_type == 0) {
						uint32_t packet_type;
						struct rte_net_hdr_lens hdr_lens;

						packet_type = rte_net_get_ptype(m, &hdr_lens, RTE_PTYPE_ALL_MASK);
						m->packet_type = packet_type;
						m->l2_len = hdr_lens.l2_len;
						m->l3_len = hdr_lens.l3_len;
					}

					/* if packet is target pkt 8< */
					uint32_t new_dst_ip = is_target_pkt(m);
					if (new_dst_ip) {
#ifdef DEBUG_MODE
						printf("lcore_main(): Received target pkt!\n");
#endif

						/* Modify src MAC and dst MAC 8< */
						struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

						// simple way: just swap the MACs
						struct rte_ether_addr tmp;
						rte_ether_addr_copy(&eth_hdr->src_addr, &tmp);
						rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
						rte_ether_addr_copy(&tmp, &eth_hdr->dst_addr);

						// // advanced: get corresponding MAC for given IP on demand
						// rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
						// struct rte_ether_addr new_dst_mac = get_mac_from_ip(new_dst_ip);
						// rte_ether_addr_copy(&new_dst_mac, &eth_hdr->dst_addr);

#ifdef DEBUG_MODE						
						printf("lcore_main(): for new pkt to send, srcMAC="
							RTE_ETHER_ADDR_PRT_FMT
							", dstMAC="
							RTE_ETHER_ADDR_PRT_FMT "\n",
							RTE_ETHER_ADDR_BYTES(&eth_hdr->src_addr),
							RTE_ETHER_ADDR_BYTES(&eth_hdr->dst_addr));
#endif
						/* >8 End of modifying MACs */

						/* Modify src IP and dst IP 8< */
						struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
						ip_hdr->src_addr = rte_cpu_to_be_32(my_ip);
						ip_hdr->dst_addr = rte_cpu_to_be_32(new_dst_ip);

#ifdef DEBUG_MODE
						printf("lcore_main(): for new pkt to send, srcIP=%u.%u.%u.%u, dstIP=%u.%u.%u.%u\n",
								(my_ip>>24)&0xff, (my_ip>>16)&0xff, (my_ip>>8)&0xff, my_ip&0xff,
								(new_dst_ip>>24)&0xff, (new_dst_ip>>16)&0xff, (new_dst_ip>>8)&0xff, new_dst_ip&0xff);
#endif
						/* >8 End of modifying IPs */

						ip_hdr->hdr_checksum = 0;

						/* calculate IPv4 cksum in SW if needed */
						if ((m->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) == 0)
							ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

						/* if packet is UDP */
						if ((IS_UDP_HDR(m->packet_type))) {
							struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((char *)ip_hdr + m->l3_len);
							udp_hdr->dgram_cksum = 0;

							/* calculate UDP cksum in SW if needed */
							if ((m->ol_flags & RTE_MBUF_F_TX_UDP_CKSUM) == 0)
								udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hdr);
						}

						/* if packet is TCP */
						if ((IS_TCP_HDR(m->packet_type))) {
							struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((char *)ip_hdr + m->l3_len);
							tcp_hdr->cksum = 0;

							/* calculate TCP cksum in SW if needed */
							if ((m->ol_flags & RTE_MBUF_F_TX_TCP_CKSUM) == 0)
								tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr, tcp_hdr);
						}

						/* Transmit the pkt to the same port it arrived */
						buffer = tx_buffer[port];
						sent = rte_eth_tx_buffer(port, 0, buffer, m);
						if (sent) {
							port_statistics[port].tx += sent;
#ifdef DEBUG_MODE
							printf("lcore_main(): %u pkts were sent to port %u!\n", sent, port);
#endif
						}
					}
					/* >8 End of handling target pkt */

					/* Otherwise, pass the packet to kernel stack via virtio port */
					else {
						buffer = tx_buffer[port + nb_pports];
						sent = rte_eth_tx_buffer(port + nb_pports, 0, buffer, m);
						if (sent){
							port_statistics[port + nb_pports].tx += sent;
#ifdef DEBUG_MODE
							printf("lcore_main(): %u pkts were sent to port %u!\n", sent, port + nb_pports);
#endif
						} 
					}
				}
			}
			/* >8 End of physical port case */

			/* for virtio ports 8< */
			else {
				/* Get burst of RX packets */
				struct rte_mbuf *bufs[BURST_SIZE];
				const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
						bufs, BURST_SIZE);

				if (unlikely(nb_rx == 0))
					continue;

				port_statistics[port].rx += nb_rx;
				
				/* Forward read packets to corresponding physical port */
				const uint16_t nb_tx = rte_eth_tx_burst(port - nb_pports, 0,
						bufs, nb_rx);
					
				port_statistics[port].tx += nb_tx;

				/* Free any unsent packets. */
				if (unlikely(nb_tx < nb_rx)) {
					uint16_t buf;
					for (buf = nb_tx; buf < nb_rx; buf++)
						rte_pktmbuf_free(bufs[buf]);
				}
			}
			/* >8 End of virtio port case */
		}
	}
	/* >8 End of loop. */
}
/* >8 End Mirror forwarding application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
	uint16_t portid_new;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is any available port to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports <= 0)
		rte_exit(EXIT_FAILURE, "Error: no available port\n");
	printf("mirrorfwd: fouond %d port(s)\n", (int) nb_ports);

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Create a vhost_user port for each physical port */
	unsigned port_count = 0;
	RTE_ETH_FOREACH_DEV(portid) {
		char portname[32];
		char portargs[256];
		struct rte_ether_addr addr = {0};

		/* once we have created a virtio port for each physical port, stop creating more */
		if (++port_count > nb_ports)
			break;

		/* get MAC address of physical port to use as MAC of virtio_user port */
		rte_eth_macaddr_get(portid, &addr);

		/* set the name and arguments */
		snprintf(portname, sizeof(portname), "virtio_user%u", portid);
		snprintf(portargs, sizeof(portargs), "path=/dev/vhost-net,queues=1,queue_size=%u,iface=%s,mac=" RTE_ETHER_ADDR_PRT_FMT, RX_RING_SIZE, portname, RTE_ETHER_ADDR_BYTES(&addr));

		/* add the vdev for virtio_user */
		if (rte_eal_hotplug_add("vdev", portname, portargs) < 0)
			rte_exit(EXIT_FAILURE, "Cannot create paired port for port %u\n", portid);

		rte_eth_dev_get_port_by_name(portname, &portid_new);
		printf("Created virtio port: %s (port %u)\n", portname, portid_new);
	}
	/* >8 End of creating vhost_user port */

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main();
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
