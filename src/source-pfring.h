/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \file
 *
 * \author William Metcalf <william.metcalf@gmail.com>
 */

#ifndef __SOURCE_PFRING_H__
#define __SOURCE_PFRING_H__

#define PFRING_IFACE_NAME_LENGTH 48

#include <config.h>
#ifdef HAVE_PFRING
#include <pfring.h>
#endif

typedef struct PfringThreadVars_ PfringThreadVars;

/* PfringIfaceConfig flags */
#define PFRING_CONF_FLAGS_CLUSTER (1 << 0)
#define PFRING_CONF_FLAGS_BYPASS  (1 << 1)

typedef struct PfringIfaceConfig_
{
    uint32_t flags;

    /* cluster param */
    int cluster_id;
#ifdef HAVE_PFRING
    cluster_type ctype;
#endif
    char iface[PFRING_IFACE_NAME_LENGTH];
    /* number of threads */
    int threads;

    char *bpf_filter;

    ChecksumValidationMode checksum_mode;
    SC_ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} PfringIfaceConfig;

/**
 * \brief per packet Pfring vars
 *
 * This structure is used to pass packet metadata in callbacks.
 */
typedef struct PfringPacketVars_
{
    PfringThreadVars *ptv;
    u_int32_t flow_id;
} PfringPacketVars;

void TmModuleReceivePfringRegister (void);
void TmModuleDecodePfringRegister (void);

int PfringConfGetThreads(void);
void PfringLoadConfig(void);

/* We don't have to use an enum that sucks in our code */
#define CLUSTER_FLOW 0
#define CLUSTER_ROUND_ROBIN 1
#define CLUSTER_FLOW_5_TUPLE 4

/* Bypass data structures */

#define PFRING_OFFLOAD_LEN 13

struct offload_descriptor_rx_packet_data
{
  uint32_t length:16;
  uint32_t protocol:2;
  uint32_t ip:1;
  uint32_t tv:2;
  uint32_t reserved:2;
  uint32_t anyerr:1;
  uint32_t port:3;
  uint32_t reserved2:1;
  uint32_t type:4;
  uint32_t origlength:16;
  uint32_t reserved3:12;
  uint32_t hash:4;
  uint64_t timestamp;
};

struct offload_rx_type4_s {
  union {
    struct {
      uint32_t length          :14; 
      uint32_t rsrvd_0         : 2; 
      uint32_t iptype          : 2; 
      uint32_t vlanflag        : 1; 
      uint32_t ipflag          : 1; 
      uint32_t enetflag        : 1; 
      uint32_t ipv6flag        : 1; 
      uint32_t rsrvd_1         : 1; 
      uint32_t errorflag       : 1; 
      uint32_t port            : 3; 
      uint32_t rsrvd_2         : 1; 
      uint32_t type            : 4; 
      uint32_t origlength      :14; 
      uint32_t rsrvd_3         :18; 
      uint64_t timestamp;
      uint32_t flowid          :24; 
      uint32_t rsrvd_4         : 3; 
      uint32_t flag_rev        : 1; 
      uint32_t flag_error      : 1; 
      uint32_t flag_new        : 1; 
      uint32_t flag_old        : 1; 
      uint32_t flag_classified : 1; 
      uint32_t ipprotocol      : 8; 
      uint32_t l3offset        : 8; 
      uint32_t l4offset        : 8; 
      uint32_t rsrvd_5         : 8; 
    };
    uint32_t dw[6];
  };
};

int pfring_anic_flow_filter(pfring *ring, u_int32_t thread, u_int32_t flowid, u_int32_t drop);

#endif /* __SOURCE_PFRING_H__ */
