#include <linux/types.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/icmp.h>

typedef struct {
    __u16 version: 2;      
    __u16 type: 2;         
    __u16 subtype: 4;      
    __u16 toDs: 1;         
    __u16 fromDs: 1;       
    __u16 moreFrag: 1;     
    __u16 retry: 1;        
    __u16 pwrMgt: 1;       
    __u16 moreData: 1;     
    __u16 wep: 1;         
    __u16 order: 1;       
} __frame_control;


typedef struct {
    __u64 countBeacon;
    __u64 countProbeReq;
    __u64 countProbeRes;
    __u64 countAssocReq;
    __u64 countAssocRes;
    __u64 countAuth;
    
    __u64 countAck;
    __u64 countRts;
    __u64 countPsPoll;
    __u64 countCts;
    
    __u64 countData;
    __u64 countQosData;
    
    __u64 countUnknown;
} __packet_count;

__packet_count count = {};

typedef struct {
    __frame_control frame_control;
    __u8 duration[2];
} __wifi_header;

void classify_subtype(__u8 type, __u16 subtype, __packet_count *count) {
    if (type == 0x00) { // Management frame
        switch (subtype) {
            case 0x00: 
                count->countAssocReq++;
                break;
            case 0x01: 
                count->countAssocRes++;
                break;
            case 0x04: 
                count->countProbeReq++;
                break;
            case 0x05: 
                count->countProbeRes++;
                break;
            case 0x08: 
                count->countBeacon++;
                break;
            case 0x0B: 
                count->countAuth++;
                break;
            default: 
                count->countUnknown++;
                break;
        }
    } else if (type == 0x01) { // Control frame
        switch (subtype) {
            case 0x0A: 
                count->countPsPoll++;
                break;
            case 0x0B: 
                count->countRts++;
                break;
            case 0x0C: 
                count->countCts++;
                break;
            case 0x0D: 
                count->countAck++;
                break;
            default: 
                count->countUnknown++;
                break;
        }
    } else if (type == 0x02) { // Data frame
        switch (subtype) {
            case 0x00: 
                count->countData++;
                break;
            case 0x08: 
                count->countQosData++;
                break;
            default: 
                count->countUnknown++;
                break;
        }
    } else {
        count->countUnknown++;
    }
}
static int print_and_sum_struct(__packet_count *pc) {
    __u64 total = 0;

    bpf_printk("countBeacon: %llu\n", pc->countBeacon);
    total += pc->countBeacon;

    bpf_printk("countProbeReq: %llu\n", pc->countProbeReq);
    total += pc->countProbeReq;

    bpf_printk("countProbeRes: %llu\n", pc->countProbeRes);
    total += pc->countProbeRes;

    bpf_printk("countAssocReq: %llu\n", pc->countAssocReq);
    total += pc->countAssocReq;

    bpf_printk("countAssocRes: %llu\n", pc->countAssocRes);
    total += pc->countAssocRes;

    bpf_printk("countAuth: %llu\n", pc->countAuth);
    total += pc->countAuth;

    bpf_printk("countAck: %llu\n", pc->countAck);
    total += pc->countAck;

    bpf_printk("countRts: %llu\n", pc->countRts);
    total += pc->countRts;

    bpf_printk("countPsPoll: %llu\n", pc->countPsPoll);
    total += pc->countPsPoll;

    bpf_printk("countCts: %llu\n", pc->countCts);
    total += pc->countCts;

    bpf_printk("countData: %llu\n", pc->countData);
    total += pc->countData;

    bpf_printk("countQosData: %llu\n", pc->countQosData);
    total += pc->countQosData;

    bpf_printk("countUnknown: %llu\n", pc->countUnknown);
    total += pc->countUnknown;

    bpf_printk("Total value: %llu\n", total);

    bpf_printk("\n-------------------------------\n");

    return total;

}
static int count_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 26 > data_end) {
        bpf_printk("ERR: Radio tap has a problem");
        return 0;
    }
    data = data + 26; // pass the Radiotap header (for raspberry 26 -> 18 ?)
    if (data + sizeof(__wifi_header) > data_end) {
        bpf_printk("ERR: WiFi header has a problem");
        return 0;
    }
    __wifi_header *header = (__wifi_header*)data;
    classify_subtype(header->frame_control.type,header->frame_control.subtype,&count);
    print_and_sum_struct(&count);
}
SEC("xdp")
int hello(struct xdp_md *ctx) {
    count_packet(ctx);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
