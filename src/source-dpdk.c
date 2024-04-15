/* Copyright (C) 2021 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 *  \defgroup dpdk DPDK running mode
 *
 *  @{
 */

/**
 * \file
 *
 * \author Lukas Sismis <lukas.sismis@gmail.com>
 *
 * DPDK capture interface
 *
 */

#include "suricata-common.h"
#include "runmodes.h"
#include "decode.h"
#include "packet.h"
#include "source-dpdk.h"
#include "suricata.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "tmqh-packetpool.h"
#include "util-privs.h"
#include "action-globals.h"

// Fago
#define	MPOOL_NB_BUF		0x20000
#include "tldk/netbe.h"
#include "tldk/parse.h"
#define	MAX_RULES	0x100
#define	MAX_TBL8	0x800

#define	RX_RING_SIZE	0x400
#define	TX_RING_SIZE	0x800

#define	MPOOL_CACHE_SIZE	0x100
#define	MPOOL_NB_BUF		0x20000

#define FRAG_MBUF_BUF_SIZE	(RTE_PKTMBUF_HEADROOM + TLE_DST_MAX_HDR)
#define FRAG_TTL		MS_PER_S
#define	FRAG_TBL_BUCKET_ENTRIES	16

#define	FIRST_PORT	0x8000
#define RX_CSUM_OFFLOAD	(DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_UDP_CKSUM)
#define TX_CSUM_OFFLOAD	(DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM)

RTE_DEFINE_PER_LCORE(struct netbe_lcore *, _be);
RTE_DEFINE_PER_LCORE(struct netfe_lcore *, _fe);
#include "tldk/fwdtbl.h"

/**
 * Location to be modified to create the IPv4 hash key which helps
 * to distribute packets based on the destination TCP/UDP port.
 */
#define RSS_HASH_KEY_DEST_PORT_LOC_IPV4 15

/**
 * Location to be modified to create the IPv6 hash key which helps
 * to distribute packets based on the destination TCP/UDP port.
 */
#define RSS_HASH_KEY_DEST_PORT_LOC_IPV6 39

/**
 * Size of the rte_eth_rss_reta_entry64 array to update through
 * rte_eth_dev_rss_reta_update.
 */
#define RSS_RETA_CONF_ARRAY_SIZE (ETH_RSS_RETA_SIZE_512/RTE_RETA_GROUP_SIZE)

static volatile int force_quit;
static struct netbe_cfg becfg = {.mpool_buf_num=MPOOL_NB_BUF};
static struct rte_mempool *mpool[RTE_MAX_NUMA_NODES + 1];
static struct rte_mempool *frag_mpool[RTE_MAX_NUMA_NODES + 1];
static struct lcore_prm prm[RTE_MAX_LCORE];
static uint8_t be_init = 0;
static char proto_name[3][10] = {"udp", "tcp", ""};

static const struct rte_eth_conf port_conf_default;

struct tx_content tx_content = {
	.sz = 0,
	.data = NULL,
};

/* function pointers */
static TLE_RX_BULK_FUNCTYPE tle_rx_bulk;
static TLE_TX_BULK_FUNCTYPE tle_tx_bulk;
static TLE_STREAM_RECV_FUNCTYPE tle_stream_recv;
static TLE_STREAM_CLOSE_FUNCTYPE tle_stream_close;

static LCORE_MAIN_FUNCTYPE lcore_main;
#include "tldk/common.h"
#include "tldk/parse.h"
#include "tldk/lcore.h"
#include "tldk/port.h"
#include "tldk/tcp.h"
#include "tldk/udp.h"
int verbose = VERBOSE_NONE;
//////////////////////////////////////////////////////////////////////
#ifndef HAVE_DPDK

TmEcode NoDPDKSupportExit(ThreadVars *, const void *, void **);

void TmModuleReceiveDPDKRegister(void)
{
    tmm_modules[TMM_RECEIVEDPDK].name = "ReceiveDPDK";
    tmm_modules[TMM_RECEIVEDPDK].ThreadInit = NoDPDKSupportExit;
    tmm_modules[TMM_RECEIVEDPDK].Func = NULL;
    tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEDPDK].cap_flags = 0;
    tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodeDPDK.
 */
void TmModuleDecodeDPDKRegister(void)
{
    tmm_modules[TMM_DECODEDPDK].name = "DecodeDPDK";
    tmm_modules[TMM_DECODEDPDK].ThreadInit = NoDPDKSupportExit;
    tmm_modules[TMM_DECODEDPDK].Func = NULL;
    tmm_modules[TMM_DECODEDPDK].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEDPDK].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEDPDK].cap_flags = 0;
    tmm_modules[TMM_DECODEDPDK].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief this function prints an error message and exits.
 */
TmEcode NoDPDKSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    FatalError("Error creating thread %s: you do not have "
               "support for DPDK enabled, on Linux host please recompile "
               "with --enable-dpdk",
            tv->name);
}

#else /* We have DPDK support */

#include "util-affinity.h"
#include "util-dpdk.h"
#include "util-dpdk-i40e.h"
#include "util-dpdk-bonding.h"
#include <numa.h>

#define BURST_SIZE 32
static struct timeval machine_start_time = { 0, 0 };

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct DPDKThreadVars_ {
    /* counters */
    uint64_t pkts;
    ThreadVars *tv;
    TmSlot *slot;
    LiveDevice *livedev;
    ChecksumValidationMode checksum_mode;
    /* references to packet and drop counters */
    uint16_t capture_dpdk_packets;
    uint16_t capture_dpdk_rx_errs;
    uint16_t capture_dpdk_imissed;
    uint16_t capture_dpdk_rx_no_mbufs;
    uint16_t capture_dpdk_ierrors;
    uint16_t capture_dpdk_tx_errs;
    unsigned int flags;
    int threads;
    /* for IPS */
    DpdkCopyModeEnum copy_mode;
    uint16_t out_port_id;
    /* Entry in the peers_list */

    uint64_t bytes;
    uint64_t accepted;
    uint64_t dropped;
    uint16_t port_id;
    uint16_t queue_id;
    int32_t port_socket_id;
    struct rte_mempool *pkt_mempool;
    struct rte_mbuf *received_mbufs[BURST_SIZE];
    bool is_tx;
    uint64_t mac_addr;
    uint64_t host_mac_addr;
    struct netbe_lcore* be;
    /* for data diode */

} DPDKThreadVars;

static TmEcode ReceiveDPDKThreadInit(ThreadVars *, const void *, void **);
static void ReceiveDPDKThreadExitStats(ThreadVars *, void *);
static TmEcode ReceiveDPDKThreadDeinit(ThreadVars *, void *);
static TmEcode ReceiveDPDKLoop(ThreadVars *tv, void *data, void *slot);

static TmEcode DecodeDPDKThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodeDPDKThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodeDPDK(ThreadVars *, Packet *, void *);

static uint64_t CyclesToMicroseconds(uint64_t cycles);
static uint64_t CyclesToSeconds(uint64_t cycles);
static void DPDKFreeMbufArray(struct rte_mbuf **mbuf_array, uint16_t mbuf_cnt, uint16_t offset);
static uint64_t DPDKGetSeconds(void);

static void DPDKFreeMbufArray(struct rte_mbuf **mbuf_array, uint16_t mbuf_cnt, uint16_t offset)
{
    for (int i = offset; i < mbuf_cnt; i++) {
        rte_pktmbuf_free(mbuf_array[i]);
    }
}

static uint64_t CyclesToMicroseconds(const uint64_t cycles)
{
    const uint64_t ticks_per_us = rte_get_tsc_hz() / 1000000;
    if (ticks_per_us == 0) {
        return 0;
    }
    return cycles / ticks_per_us;
}

static uint64_t CyclesToSeconds(const uint64_t cycles)
{
    const uint64_t ticks_per_s = rte_get_tsc_hz();
    if (ticks_per_s == 0) {
        return 0;
    }
    return cycles / ticks_per_s;
}

static void CyclesAddToTimeval(
        const uint64_t cycles, struct timeval *orig_tv, struct timeval *new_tv)
{
    uint64_t usec = CyclesToMicroseconds(cycles) + orig_tv->tv_usec;
    new_tv->tv_sec = orig_tv->tv_sec + usec / 1000000;
    new_tv->tv_usec = (usec % 1000000);
}

void DPDKSetTimevalOfMachineStart(void)
{
    gettimeofday(&machine_start_time, NULL);
    machine_start_time.tv_sec -= DPDKGetSeconds();
}

/**
 * Initializes real_tv to the correct real time. Adds TSC counter value to the timeval of
 * the machine start
 * @param machine_start_tv - timestamp when the machine was started
 * @param real_tv
 */
static SCTime_t DPDKSetTimevalReal(struct timeval *machine_start_tv)
{
    struct timeval real_tv;
    CyclesAddToTimeval(rte_get_tsc_cycles(), machine_start_tv, &real_tv);
    return SCTIME_FROM_TIMEVAL(&real_tv);
}

/* get number of seconds from the reset of TSC counter (typically from the machine start) */
static uint64_t DPDKGetSeconds(void)
{
    return CyclesToSeconds(rte_get_tsc_cycles());
}

static void DevicePostStartPMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name)
{
    if (strcmp(driver_name, "net_bonding") == 0) {
        driver_name = BondingDeviceDriverGet(ptv->port_id);
    }

    // The PMD Driver i40e has a special way to set the RSS, it can be set via rte_flow rules
    // and only after the start of the port
    if (strcmp(driver_name, "net_i40e") == 0)
        i40eDeviceSetRSS(ptv->port_id, ptv->threads);
}

static void DevicePreStopPMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name)
{
    if (strcmp(driver_name, "net_bonding") == 0) {
        driver_name = BondingDeviceDriverGet(ptv->port_id);
    }

    if (strcmp(driver_name, "net_i40e") == 0) {
#if RTE_VERSION > RTE_VERSION_NUM(20, 0, 0, 0)
        // Flush the RSS rules that have been inserted in the post start section
        struct rte_flow_error flush_error = { 0 };
        int32_t retval = rte_flow_flush(ptv->port_id, &flush_error);
        if (retval != 0) {
            SCLogError("%s: unable to flush rte_flow rules: %s Flush error msg: %s",
                    ptv->livedev->dev, rte_strerror(-retval), flush_error.message);
        }
#endif /* RTE_VERSION > RTE_VERSION_NUM(20, 0, 0, 0) */
    }
}

/**
 * Attempts to retrieve NUMA node id on which the caller runs
 * @return NUMA id on success, -1 otherwise
 */
static int GetNumaNode(void)
{
    int cpu = 0;
    int node = -1;

#if defined(__linux__)
    cpu = sched_getcpu();
    node = numa_node_of_cpu(cpu);
#else
    SCLogWarning("NUMA node retrieval is not supported on this OS.");
#endif

    return node;
}

/**
 * \brief Registration Function for ReceiveDPDK.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveDPDKRegister(void)
{
    tmm_modules[TMM_RECEIVEDPDK].name = "ReceiveDPDK";
    tmm_modules[TMM_RECEIVEDPDK].ThreadInit = ReceiveDPDKThreadInit;
    tmm_modules[TMM_RECEIVEDPDK].Func = NULL;
    tmm_modules[TMM_RECEIVEDPDK].PktAcqLoop = ReceiveDPDKLoop;
    tmm_modules[TMM_RECEIVEDPDK].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = ReceiveDPDKThreadExitStats;
    tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = ReceiveDPDKThreadDeinit;
    tmm_modules[TMM_RECEIVEDPDK].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodeDPDK.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeDPDKRegister(void)
{
    tmm_modules[TMM_DECODEDPDK].name = "DecodeDPDK";
    tmm_modules[TMM_DECODEDPDK].ThreadInit = DecodeDPDKThreadInit;
    tmm_modules[TMM_DECODEDPDK].Func = DecodeDPDK;
    tmm_modules[TMM_DECODEDPDK].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEDPDK].ThreadDeinit = DecodeDPDKThreadDeinit;
    tmm_modules[TMM_DECODEDPDK].cap_flags = 0;
    tmm_modules[TMM_DECODEDPDK].flags = TM_FLAG_DECODE_TM;
}

static inline void DPDKDumpCounters(DPDKThreadVars *ptv)
{
    /* Some NICs (e.g. Intel) do not support queue statistics and the drops can be fetched only on
     * the port level. Therefore setting it to the first worker to have at least continuous update
     * on the dropped packets. */
    if (ptv->queue_id == 0) {
        struct rte_eth_stats eth_stats;
        int retval = rte_eth_stats_get(ptv->port_id, &eth_stats);
        if (unlikely(retval != 0)) {
            SCLogError("%s: failed to get stats: %s", ptv->livedev->dev, rte_strerror(-retval));
            return;
        }

        StatsSetUI64(ptv->tv, ptv->capture_dpdk_packets,
                ptv->pkts + eth_stats.imissed + eth_stats.ierrors + eth_stats.rx_nombuf);
        SC_ATOMIC_SET(ptv->livedev->pkts,
                eth_stats.ipackets + eth_stats.imissed + eth_stats.ierrors + eth_stats.rx_nombuf);
        StatsSetUI64(ptv->tv, ptv->capture_dpdk_rx_errs,
                eth_stats.imissed + eth_stats.ierrors + eth_stats.rx_nombuf);
        StatsSetUI64(ptv->tv, ptv->capture_dpdk_imissed, eth_stats.imissed);
        StatsSetUI64(ptv->tv, ptv->capture_dpdk_rx_no_mbufs, eth_stats.rx_nombuf);
        StatsSetUI64(ptv->tv, ptv->capture_dpdk_ierrors, eth_stats.ierrors);
        StatsSetUI64(ptv->tv, ptv->capture_dpdk_tx_errs, eth_stats.oerrors);
        SC_ATOMIC_SET(
                ptv->livedev->drop, eth_stats.imissed + eth_stats.ierrors + eth_stats.rx_nombuf);
    } else {
        StatsSetUI64(ptv->tv, ptv->capture_dpdk_packets, ptv->pkts);
    }
}

static void
l2fwd_mac_updating(struct rte_mbuf *m, uint64_t src_addr, uint64_t dst_addr)
{
	struct rte_ether_hdr *eth;
	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	memcpy(&eth->d_addr.addr_bytes[0], &dst_addr, RTE_ETHER_ADDR_LEN);
    memcpy(&eth->s_addr.addr_bytes[0], &src_addr, RTE_ETHER_ADDR_LEN);
}

static void DPDKReleasePacket(Packet *p)
{
    int retval;
    ////////////////////////////////////// TCP PROXY //////////////////////////////////////
    
    
    printf("DPDKReleasePacket %u %d %d\n", p->dpdk_v.port_id, p->proto, PacketCheckAction(p, ACTION_DROP));

    /* Need to be in copy mode and need to detect early release
       where Ethernet header could not be set (and pseudo packet)
       When enabling promiscuous mode on Intel cards, 2 ICMPv6 packets are generated.
       These get into the infinite cycle between the NIC and the switch in some cases */
    if ((p->dpdk_v.copy_mode == DPDK_COPY_MODE_TAP ||
                (p->dpdk_v.copy_mode == DPDK_COPY_MODE_IPS && PacketCheckAction(p, ACTION_ALERT)))
#if defined(RTE_LIBRTE_I40E_PMD) || defined(RTE_LIBRTE_IXGBE_PMD) || defined(RTE_LIBRTE_ICE_PMD)
            && !(PKT_IS_ICMPV6(p) && p->icmpv6h->type == 143)
#endif
            && p->is_tx) 
    {
        BUG_ON(PKT_IS_PSEUDOPKT(p));
        // Update MAC for l2fw
        l2fwd_mac_updating(p->dpdk_v.mbuf, p->dpdk_v.mac_addr, p->dpdk_v.host_mac_addr);
        retval =
                rte_eth_tx_burst(p->dpdk_v.out_port_id, p->dpdk_v.out_queue_id, &p->dpdk_v.mbuf, 1);
        // rte_eth_tx_burst can return only 0 (failure) or 1 (success) because we are only
        // transmitting burst of size 1 and the function rte_eth_tx_burst returns number of
        // successfully sent packets.
        if (unlikely(retval < 1)) {
            // sometimes a repeated transmit can help to send out the packet
            rte_delay_us(DPDK_BURST_TX_WAIT_US);
            retval = rte_eth_tx_burst(
                    p->dpdk_v.out_port_id, p->dpdk_v.out_queue_id, &p->dpdk_v.mbuf, 1);
            if (unlikely(retval < 1)) {
                SCLogDebug("Unable to transmit the packet on port %u queue %u",
                        p->dpdk_v.out_port_id, p->dpdk_v.out_queue_id);
                rte_pktmbuf_free(p->dpdk_v.mbuf);
                p->dpdk_v.mbuf = NULL;
            }
        }
    } else if ((p->proto == IPPROTO_TCP)/* && !PacketCheckAction(p, ACTION_DROP)*/) {
        uint32_t j, k, n;
        struct rte_mbuf *pkt[MAX_PKT_BURST];
        struct rte_mbuf *rp[MAX_PKT_BURST];
        int32_t rc[MAX_PKT_BURST];
        struct pkt_buf *abuf;
        struct netbe_lcore *lc = p->dpdk_v.be;
        uint32_t port_id = p->dpdk_v.port_id;
        uint32_t out_port_id = p->dpdk_v.out_port_id;
        n = 1;
        printf("TCP proxy recv packet on pidx %u\n", port_id);
        for (int pidx = 0; pidx < lc->prtq_num; pidx++)
        {
            if (lc->prtq[pidx].port.id == port_id)
            {
                lc->prtq[pidx].rx_stat.in += n;
                NETBE_TRACE("%s(%u): rte_eth_rx_burst(%u, %u) returns %u\n",
                    __func__, lc->id, lc->prtq[pidx].port.id,
                    lc->prtq[pidx].rxqid, n);
                k = tle_tcp_rx_bulk(lc->prtq[pidx].dev, pidx, out_port_id, &p->dpdk_v.mbuf, rp, rc, n);

                lc->prtq[pidx].rx_stat.up += k;
                lc->prtq[pidx].rx_stat.drop += n - k;
                NETBE_TRACE("%s(%u): tle_%s_rx_bulk(%p, %u) returns %u\n",
                    __func__, lc->id, proto_name[lc->proto],
                    lc->prtq[pidx].dev, n, k);

                for (j = 0; j != n - k; j++) {
                    NETBE_TRACE("%s:%d(port=%u) rp[%u]={%p, %d};\n",
                        __func__, __LINE__, lc->prtq[pidx].port.id,
                        j, rp[j], rc[j]);
                    rte_pktmbuf_free(rp[j]);
                }
            }
        }
        /* respond to incoming arp requests */
        // abuf = &lc->prtq[pidx].arp_buf;
        // if (abuf->num == 0)
        //     return;

        // send_arp_reply(&lc->prtq[pidx], abuf);
    } 
    else {
        rte_pktmbuf_free(p->dpdk_v.mbuf);
        p->dpdk_v.mbuf = NULL;
    }

    PacketFreeOrRelease(p);
}

/**
 *  \brief Main DPDK reading Loop function
 */
static TmEcode ReceiveDPDKLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();
    Packet *p;
    int rc;
    uint16_t nb_rx;
    time_t last_dump = 0;
    time_t current_time;
    bool segmented_mbufs_warned = 0;
    SCTime_t t = DPDKSetTimevalReal(&machine_start_time);
    uint64_t last_timeout_msec = SCTIME_MSECS(t);

    DPDKThreadVars *ptv = (DPDKThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;
    ptv->slot = s->slot_next;
    // if (ptv->port_id == 0)
    // {
    
    // struct lcore_prm* prm = ptv->lc;
    // printf("************** %d ****************\n", prm->fe.max_streams);
    // /* lcore FE init. */
	// if (prm->fe.max_streams != 0)
	// 	rc = netfe_lcore_init_tcp(&prm->fe);
    // /* lcore FE init. */
	// if (rc == 0 && prm->be.lc != NULL)
	// 	rc = netbe_lcore_setup(prm->be.lc);

	// if (rc != 0)
	// 	sig_handle(SIGQUIT);

    // printf("========\n");
    // }
    // Indicate that the thread is actually running its application level code (i.e., it can poll
    // packets)
    TmThreadsSetFlag(tv, THV_RUNNING);
    PacketPoolWait();
    while (1) {
        if (unlikely(suricata_ctl_flags != 0)) {
            SCLogDebug("Stopping Suricata!");
            DPDKDumpCounters(ptv);
            break;
        }
        
        nb_rx = rte_eth_rx_burst(ptv->port_id, ptv->queue_id, ptv->received_mbufs, BURST_SIZE);
        
        if (unlikely(nb_rx == 0)) {
            t = DPDKSetTimevalReal(&machine_start_time);
            uint64_t msecs = SCTIME_MSECS(t);
            if (msecs > last_timeout_msec + 100) {
                TmThreadsCaptureHandleTimeout(tv, NULL);
                last_timeout_msec = msecs;
            }
            continue;
        }

        ptv->pkts += (uint64_t)nb_rx;
        for (uint16_t i = 0; i < nb_rx; i++) {
            p = PacketGetFromQueueOrAlloc();
            if (unlikely(p == NULL)) {
                continue;
            }
            PKT_SET_SRC(p, PKT_SRC_WIRE);
            p->datalink = LINKTYPE_ETHERNET;
            if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            }

            p->ts = DPDKSetTimevalReal(&machine_start_time);
            p->dpdk_v.mbuf = ptv->received_mbufs[i];
            p->ReleasePacket = DPDKReleasePacket;
            p->dpdk_v.copy_mode = ptv->copy_mode;
            p->dpdk_v.out_port_id = ptv->out_port_id;
            p->dpdk_v.port_id = ptv->port_id;
            p->dpdk_v.out_queue_id = ptv->queue_id;
            p->livedev = ptv->livedev;
            // for data diode
            p->is_tx = ptv->is_tx;
            p->dpdk_v.mac_addr = ptv->mac_addr;
            p->dpdk_v.host_mac_addr = ptv->host_mac_addr;
            p->dpdk_v.be = ptv->be;

            if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            } else if (ptv->checksum_mode == CHECKSUM_VALIDATION_OFFLOAD) {
                uint64_t ol_flags = ptv->received_mbufs[i]->ol_flags;
                if ((ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_GOOD &&
                        (ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) == RTE_MBUF_F_RX_L4_CKSUM_GOOD) {
                    SCLogDebug("HW detected GOOD IP and L4 chsum, ignoring validation");
                    p->flags |= PKT_IGNORE_CHECKSUM;
                } else {
                    if ((ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_BAD) {
                        SCLogDebug("HW detected BAD IP checksum");
                        // chsum recalc will not be triggered but rule keyword check will be
                        p->level3_comp_csum = 0;
                    }
                    if ((ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) == RTE_MBUF_F_RX_L4_CKSUM_BAD) {
                        SCLogDebug("HW detected BAD L4 chsum");
                        p->level4_comp_csum = 0;
                    }
                }
            }

            if (!rte_pktmbuf_is_contiguous(p->dpdk_v.mbuf) && !segmented_mbufs_warned) {
                char warn_s[] = "Segmented mbufs detected! Redmine Ticket #6012 "
                                "Check your configuration or report the issue";
                enum rte_proc_type_t eal_t = rte_eal_process_type();
                if (eal_t == RTE_PROC_SECONDARY) {
                    SCLogWarning("%s. To avoid segmented mbufs, "
                                 "try to increase mbuf size in your primary application",
                            warn_s);
                } else if (eal_t == RTE_PROC_PRIMARY) {
                    SCLogWarning("%s. To avoid segmented mbufs, "
                                 "try to increase MTU in your suricata.yaml",
                            warn_s);
                }

                segmented_mbufs_warned = 1;
            }

            PacketSetData(p, rte_pktmbuf_mtod(p->dpdk_v.mbuf, uint8_t *),
                    rte_pktmbuf_pkt_len(p->dpdk_v.mbuf));
            if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
                TmqhOutputPacketpool(ptv->tv, p);
                DPDKFreeMbufArray(ptv->received_mbufs, nb_rx - i - 1, i + 1);
                SCReturnInt(EXIT_FAILURE);
            }
        }

        /* Trigger one dump of stats every second */
        current_time = DPDKGetSeconds();
        if (current_time != last_dump) {
            DPDKDumpCounters(ptv);
            last_dump = current_time;
        }
        StatsSyncCountersIfSignalled(tv);
    }

    SCReturnInt(TM_ECODE_OK);
}
static int
netbe_dest_init(const char *fname, struct netbe_cfg *cfg)
{
	int32_t rc;
	uint32_t f, i, p;
	uint32_t k, l, cnt;
	struct netbe_lcore *lc;
	struct netbe_dest_prm prm;

	rc = netbe_parse_dest(fname, &prm);
	if (rc != 0)
		return rc;

	rc = 0;
    printf("Dest %u\n",prm.nb_dest);
	for (i = 0; i != prm.nb_dest; i++) {

		p = prm.dest[i].port;
		f = prm.dest[i].family;

		cnt = 0;
        printf("Cpu %u\n",cfg->cpu_num);
		for (k = 0; k != cfg->cpu_num; k++) {
			lc = cfg->cpu + k;
            printf("Core %u\n",lc->prtq_num);
			for (l = 0; l != 2; l++)
				if (lc->prtq[l].port.id == p) {
					rc = netbe_add_dest(lc, l, f,
							prm.dest + i, 1);
					if (rc != 0) {
						RTE_LOG(ERR, USER1,
							"%s(lc=%u, family=%u) "
							"could not add "
							"destinations(%u)\n",
							__func__, lc->id, f, i);
						return -ENOSPC;
					}
					cnt++;
				}
		}

		if (cnt == 0) {
			RTE_LOG(ERR, USER1, "%s(%s) error at line %u: "
				"port %u not managed by any lcore;\n",
				__func__, fname, prm.dest[i].line, p);
			break;
		}
	}

	free(prm.dest);
	return rc;
}

/**
 * \brief Init function for ReceiveDPDK.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with DPDKThreadVars
 *
 */
static TmEcode ReceiveDPDKThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    int retval, thread_numa, rc;
    DPDKThreadVars *ptv = NULL;
    DPDKIfaceConfig *dpdk_config = (DPDKIfaceConfig *)initdata;
    uint32_t proxy_pidx[dpdk_config->num_proxies];
    if (initdata == NULL) {
        SCLogError("DPDK configuration is NULL in thread initialization");
        goto fail;
    }

    ptv = SCCalloc(1, sizeof(DPDKThreadVars));
    if (unlikely(ptv == NULL)) {
        SCLogError("Unable to allocate memory");
        goto fail;
    }

    ptv->tv = tv;
    ptv->pkts = 0;
    ptv->bytes = 0;
    ptv->livedev = LiveGetDevice(dpdk_config->iface);

    ptv->capture_dpdk_packets = StatsRegisterCounter("capture.packets", ptv->tv);
    ptv->capture_dpdk_rx_errs = StatsRegisterCounter("capture.rx_errors", ptv->tv);
    ptv->capture_dpdk_tx_errs = StatsRegisterCounter("capture.tx_errors", ptv->tv);
    ptv->capture_dpdk_imissed = StatsRegisterCounter("capture.dpdk.imissed", ptv->tv);
    ptv->capture_dpdk_rx_no_mbufs = StatsRegisterCounter("capture.dpdk.no_mbufs", ptv->tv);
    ptv->capture_dpdk_ierrors = StatsRegisterCounter("capture.dpdk.ierrors", ptv->tv);

    ptv->copy_mode = dpdk_config->copy_mode;
    ptv->checksum_mode = dpdk_config->checksum_mode;

    ptv->threads = dpdk_config->threads;
    ptv->port_id = dpdk_config->port_id;
    ptv->out_port_id = dpdk_config->out_port_id;
    ptv->port_socket_id = dpdk_config->socket_id;
    // pass the pointer to the mempool and then forget about it. Mempool is freed in thread deinit.
    ptv->pkt_mempool = dpdk_config->pkt_mempool;
    dpdk_config->pkt_mempool = NULL;

    // For data diode
    
    ptv->is_tx = dpdk_config->is_tx;
    ptv->mac_addr = dpdk_config->mac_addr;
    ptv->host_mac_addr = dpdk_config->host_mac_addr;


    struct tle_ctx_param ctx_prm;
    tle_rx_bulk = tle_tcp_rx_bulk;
	tle_tx_bulk = tle_tcp_tx_bulk;
	tle_stream_recv = tle_tcp_stream_recv;
	tle_stream_close = tle_tcp_stream_close;
    if (be_init == 0)
    {
        be_init = 1;
        
        memset(&ctx_prm, 0, sizeof(ctx_prm));
        ctx_prm.timewait = TLE_TCP_TIMEWAIT_DEFAULT;
        becfg.promisc = 1;
        becfg.proto = 1;
        becfg.server = 1;
        becfg.arp = 0;
        becfg.cpu_num = 0;
        becfg.mpool_buf_num = MPOOL_NB_BUF;
        becfg.prt_num = 0;

        ctx_prm.proto = 0;
        ctx_prm.max_streams = 256;
        ctx_prm.max_stream_rbufs = 256;
        ctx_prm.max_stream_sbufs = 256;
        ctx_prm.send_bulk_size = 0;
        ctx_prm.flags = 0;
        ctx_prm.icw = 0;
        ctx_prm.timewait = 4294967295;
        ctx_prm.hash_alg = 0;
    }
    
    // becfg.prt->id = 0;
    // becfg.prt->nb_lcore = 1;
    // becfg.prt->mtu = 1514;
    // becfg.prt->rx_offload = 0xf;
    // becfg.prt->tx_offload = 0x0;
    // becfg.prt->ipv4 = 134873354;
    // becfg.prt->hash_key_size = 0;
    
    if (ptv->is_tx)
    {
        becfg.prt = rte_zmalloc(NULL, sizeof(struct netbe_port) * dpdk_config->num_proxies,	RTE_CACHE_LINE_SIZE);
    }
    for (int i = 0; i < dpdk_config->num_proxies; i++)
    {
        rte_cpuset_t cpuset;
        char be_config[1000];
        sprintf(be_config, "port=%u,lcore=2,rx_offload=0,tx_offload=0,ipv4=%s", ptv->port_id, dpdk_config->proxies[i]);
        rc = parse_netbe_arg(&becfg.prt[becfg.prt_num], be_config, &cpuset);
        proxy_pidx[i] = becfg.prt_num;
        becfg.prt_num++;
    }
        // rc = parse_netbe_arg(&becfg.prt[0], "port=0,lcore=2,rx_offload=0,tx_offload=0,ipv4=10.1.10.8", &cpuset);
        // rc = parse_netbe_arg(&becfg.prt[1], "port=1,lcore=2,rx_offload=0,tx_offload=0,ipv4=10.1.10.6", &cpuset);
        // rc = parse_netbe_arg(&becfg.prt[2], "port=0,lcore=2,rx_offload=0,tx_offload=0,ipv4=10.1.10.7", &cpuset);
    if (ptv->is_tx)
    {        
        printf("End BE parser\n");
        if (rc != 0) {
                RTE_LOG(ERR, USER1,
                    "%s: processing of failed with error "
                    "code: %d\n", __func__, rc);
                rte_free(becfg.prt[0].lcore_id);
                rte_free(becfg.prt);
                return rc;
        }
        becfg.cpu = rte_zmalloc(NULL, sizeof(struct netbe_lcore), RTE_CACHE_LINE_SIZE);
        rc = netbe_port_init(&becfg);
        if (rc != 0)
            rte_exit(EXIT_FAILURE,
                "%s: netbe_port_init failed with error code: %d\n",
                __func__, rc);
        rc = netbe_lcore_init(&becfg, &ctx_prm);
        if (rc != 0)
            sig_handle(SIGQUIT);
    }
    struct netfe_lcore_prm feprm;
    feprm.max_streams = ctx_prm.max_streams * becfg.cpu_num;
    feprm.stream = rte_zmalloc(NULL, sizeof(struct netfe_stream_prm) * dpdk_config->num_proxies, RTE_CACHE_LINE_SIZE);
    feprm.nb_streams = 0;
    for (int i = 0; i < dpdk_config->num_proxies; i++)
    {
        struct netbe_dest dest;
        dest.port = dpdk_config->out_port_id;
        dest.mtu = 1500;
        dest.prfx = 24;
        dest.family = AF_INET;
        inet_aton(dpdk_config->proxies[i], &dest.ipv4);
        rte_ether_unformat_addr(dpdk_config->mac_proxy, &dest.mac);
        rc = netbe_add_dest(becfg.cpu, proxy_pidx[i], dest.family, &dest, 1);
        if (rc != 0)
            sig_handle(SIGQUIT);
        struct netfe_stream_prm *sp = &feprm.stream[feprm.nb_streams];
        sp->line = feprm.nb_streams + 1;
        sp->lcore = 2;
        sp->op = FWD;
        struct sockaddr_in sin;
        memset (&sin, 0, sizeof (sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(dpdk_config->port[i]);
        sin.sin_addr.s_addr = inet_addr(dpdk_config->proxies[i]);
        memcpy (&sp->sprm.local_addr, &sin, sizeof (sin));
        memcpy (&sp->fprm.remote_addr, &sin, sizeof (sin));

        memset (&sin, 0, sizeof (sin));
        sin.sin_family = AF_INET;
        sin.sin_port = 0;
        sin.sin_addr.s_addr = inet_addr("0.0.0.0");
        memcpy (&sp->sprm.remote_addr, &sin, sizeof (sin));
        sin.sin_addr.s_addr = inet_addr("10.1.10.6");
        sin.sin_port = htons(9999);
        memcpy (&sp->fprm.local_addr, &sin, sizeof (sin));
        feprm.nb_streams++;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    thread_numa = GetNumaNode();
    if (thread_numa >= 0 && ptv->port_socket_id != SOCKET_ID_ANY &&
            thread_numa != ptv->port_socket_id) {
        SC_ATOMIC_ADD(dpdk_config->inconsitent_numa_cnt, 1);
        SCLogPerf("%s: NIC is on NUMA %d, thread on NUMA %d", dpdk_config->iface,
                ptv->port_socket_id, thread_numa);
    }

    uint16_t queue_id = SC_ATOMIC_ADD(dpdk_config->queue_id, 1);
    ptv->queue_id = queue_id;

    // the last thread starts the device
    if (queue_id == dpdk_config->threads - 1) {
        retval = rte_eth_dev_start(ptv->port_id);
        if (retval < 0) {
            SCLogError("%s: error (%s) during device startup", dpdk_config->iface,
                    rte_strerror(-retval));
            goto fail;
        }

        struct rte_eth_dev_info dev_info;
        retval = rte_eth_dev_info_get(ptv->port_id, &dev_info);
        if (retval != 0) {
            SCLogError("%s: error (%s) when getting device info", dpdk_config->iface,
                    rte_strerror(-retval));
            goto fail;
        }

        // some PMDs requires additional actions only after the device has started
        DevicePostStartPMDSpecificActions(ptv, dev_info.driver_name);

        uint16_t inconsistent_numa_cnt = SC_ATOMIC_GET(dpdk_config->inconsitent_numa_cnt);
        if (inconsistent_numa_cnt > 0 && ptv->port_socket_id != SOCKET_ID_ANY) {
            SCLogWarning("%s: NIC is on NUMA %d, %u threads on different NUMA node(s)",
                    dpdk_config->iface, ptv->port_socket_id, inconsistent_numa_cnt);
        } else if (ptv->port_socket_id == SOCKET_ID_ANY) {
            SCLogNotice(
                    "%s: unable to determine NIC's NUMA node, degraded performance can be expected",
                    dpdk_config->iface);
        }
    }
    // FE
    if (dpdk_config->num_proxies > 0)
    {
        printf("Frone end ---------------\n");
        int i;
        printf("CPU %d\n", becfg.cpu_num);
        for (i = 0; rc == 0 && i != becfg.cpu_num; i++)
            prm[becfg.cpu[i].id].be.lc = becfg.cpu + i;
        printf("i = %d\n", i);
        uint32_t cid;
        rc = (rc != 0) ? rc : netfe_lcore_fill(prm, &feprm);
        if (rc != 0)
            sig_handle(SIGQUIT);
        /* launch all slave lcores. */
        // RTE_LCORE_FOREACH_SLAVE(i) {
        // 	if (prm[i].be.lc != NULL || prm[i].fe.max_streams != 0)
        
        rte_eal_remote_launch(lcore_main_tcp, &prm[2], 2);
	// }
    // rc = netfe_lcore_init_tcp(&prm[2].fe);
    // rc = netbe_lcore_setup(prm[2].be.lc);
    }
    ptv->be = prm[2].be.lc;
    
    ////////////////////////////////////////////////////////////////////////////////////
    *data = (void *)ptv;
    dpdk_config->DerefFunc(dpdk_config);
    SCReturnInt(TM_ECODE_OK);

fail:
    if (dpdk_config != NULL)
        dpdk_config->DerefFunc(dpdk_config);
    if (ptv != NULL)
        SCFree(ptv);
    SCReturnInt(TM_ECODE_FAILED);
}

static void PrintDPDKPortXstats(uint32_t port_id, const char *port_name)
{
    struct rte_eth_xstat *xstats;
    struct rte_eth_xstat_name *xstats_names;

    int32_t len = rte_eth_xstats_get(port_id, NULL, 0);
    if (len < 0)
        FatalError("Error (%s) getting count of rte_eth_xstats failed on port %s",
                rte_strerror(-len), port_name);

    xstats = SCCalloc(len, sizeof(*xstats));
    if (xstats == NULL)
        FatalError("Failed to allocate memory for the rte_eth_xstat structure");

    int32_t ret = rte_eth_xstats_get(port_id, xstats, len);
    if (ret < 0 || ret > len) {
        SCFree(xstats);
        FatalError("Error (%s) getting rte_eth_xstats failed on port %s", rte_strerror(-ret),
                port_name);
    }
    xstats_names = SCCalloc(len, sizeof(*xstats_names));
    if (xstats_names == NULL) {
        SCFree(xstats);
        FatalError("Failed to allocate memory for the rte_eth_xstat_name array");
    }
    ret = rte_eth_xstats_get_names(port_id, xstats_names, len);
    if (ret < 0 || ret > len) {
        SCFree(xstats);
        SCFree(xstats_names);
        FatalError("Error (%s) getting names of rte_eth_xstats failed on port %s",
                rte_strerror(-ret), port_name);
    }
    for (int32_t i = 0; i < len; i++) {
        if (xstats[i].value > 0)
            SCLogPerf("Port %u (%s) - %s: %" PRIu64, port_id, port_name, xstats_names[i].name,
                    xstats[i].value);
    }

    SCFree(xstats);
    SCFree(xstats_names);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into DPDKThreadVars for ptv
 */
static void ReceiveDPDKThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    int retval;
    DPDKThreadVars *ptv = (DPDKThreadVars *)data;

    if (ptv->queue_id == 0) {
        struct rte_eth_stats eth_stats;
        PrintDPDKPortXstats(ptv->port_id, ptv->livedev->dev);
        retval = rte_eth_stats_get(ptv->port_id, &eth_stats);
        if (unlikely(retval != 0)) {
            SCLogError("%s: failed to get stats (%s)", ptv->livedev->dev, strerror(-retval));
            SCReturn;
        }
        SCLogPerf("%s: total RX stats: packets %" PRIu64 " bytes: %" PRIu64 " missed: %" PRIu64
                  " errors: %" PRIu64 " nombufs: %" PRIu64,
                ptv->livedev->dev, eth_stats.ipackets, eth_stats.ibytes, eth_stats.imissed,
                eth_stats.ierrors, eth_stats.rx_nombuf);
        if (ptv->copy_mode == DPDK_COPY_MODE_TAP || ptv->copy_mode == DPDK_COPY_MODE_IPS)
            SCLogPerf("%s: total TX stats: packets %" PRIu64 " bytes: %" PRIu64 " errors: %" PRIu64,
                    ptv->livedev->dev, eth_stats.opackets, eth_stats.obytes, eth_stats.oerrors);
    }

    DPDKDumpCounters(ptv);
    SCLogPerf("(%s) received packets %" PRIu64, tv->name, ptv->pkts);
}

/**
 * \brief DeInit function closes dpdk at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into DPDKThreadVars for ptv
 */
static TmEcode ReceiveDPDKThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    DPDKThreadVars *ptv = (DPDKThreadVars *)data;

    if (ptv->queue_id == 0) {
        struct rte_eth_dev_info dev_info;
        int retval = rte_eth_dev_info_get(ptv->port_id, &dev_info);
        if (retval != 0) {
            SCLogError("%s: error (%s) when getting device info", ptv->livedev->dev,
                    rte_strerror(-retval));
            SCReturnInt(TM_ECODE_FAILED);
        }

        DevicePreStopPMDSpecificActions(ptv, dev_info.driver_name);
    }

    rte_eth_dev_stop(ptv->port_id);
    if (ptv->copy_mode == DPDK_COPY_MODE_TAP || ptv->copy_mode == DPDK_COPY_MODE_IPS) {
        rte_eth_dev_stop(ptv->out_port_id);
    }

    ptv->pkt_mempool = NULL; // MP is released when device is closed

    SCFree(ptv);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodeDPDK decodes packets from DPDK and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into DPDKThreadVars for ptv
 */
static TmEcode DecodeDPDK(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* If suri has set vlan during reading, we increase vlan counter */
    if (p->vlan_idx) {
        StatsIncr(tv, dtv->counter_vlan);
    }

    /* call the decoder */
    DecodeLinkLayer(tv, dtv, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode DecodeDPDKThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode DecodeDPDKThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_DPDK */
/* eof */
/**
 * @}
 */
