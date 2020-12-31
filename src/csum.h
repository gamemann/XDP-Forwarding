#pragma once

#include <stdint.h>
#include <linux/ip.h>

#ifndef __BPF__

#include <linux/types.h>

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/*
 * Checksums for x86-64
 * Copyright 2002 by Andi Kleen, SuSE Labs
 * with some code from asm-x86/checksum.h
 */

static inline unsigned add32_with_carry(unsigned a, unsigned b)
{
	asm("addl %2,%0\n\t"
	    "adcl $0,%0"
	    : "=r" (a)
	    : "0" (a), "rm" (b));

	return a;
}

static inline unsigned short from32to16(unsigned a) 
{
	unsigned short b = a >> 16; 
	asm("addw %w2,%w0\n\t"
	    "adcw $0,%w0\n" 
	    : "=r" (b)
	    : "0" (b), "r" (a));

	return b;
}

/*
 * Do a 64-bit checksum on an arbitrary memory area.
 * Returns a 32bit checksum.
 *
 * This isn't as time critical as it used to be because many NICs
 * do hardware checksumming these days.
 * 
 * Things tried and found to not make it faster:
 * Manual Prefetching
 * Unrolling to an 128 bytes inner loop.
 * Using interleaving with more registers to break the carry chains.
 */
static unsigned do_csum(const unsigned char *buff, unsigned len)
{
	unsigned odd, count;
	unsigned long result = 0;

	if (unlikely(len == 0))
    {
		return result;
    }

	odd = 1 & (unsigned long) buff;

	if (unlikely(odd)) 
    {
		result = *buff << 8;
		len--;
		buff++;
	}

	count = len >> 1;		/* nr of 16-bit words.. */

	if (count) 
    {
		if (2 & (unsigned long) buff) 
        {
			result += *(unsigned short *)buff;
			count--;
			len -= 2;
			buff += 2;
		}

		count >>= 1;		/* nr of 32-bit words.. */

		if (count) 
        {
			unsigned long zero;
			unsigned count64;

			if (4 & (unsigned long) buff) 
            {
				result += *(unsigned int *) buff;
				count--;
				len -= 4;
				buff += 4;
			}

			count >>= 1;	/* nr of 64-bit words.. */

			/* main loop using 64byte blocks */
			zero = 0;
			count64 = count >> 3;

			while (count64) 
            { 
				asm("addq 0*8(%[src]),%[res]\n\t"
				    "adcq 1*8(%[src]),%[res]\n\t"
				    "adcq 2*8(%[src]),%[res]\n\t"
				    "adcq 3*8(%[src]),%[res]\n\t"
				    "adcq 4*8(%[src]),%[res]\n\t"
				    "adcq 5*8(%[src]),%[res]\n\t"
				    "adcq 6*8(%[src]),%[res]\n\t"
				    "adcq 7*8(%[src]),%[res]\n\t"
				    "adcq %[zero],%[res]"
				    : [res] "=r" (result)
				    : [src] "r" (buff), [zero] "r" (zero),
				    "[res]" (result));
				
                buff += 64;
				count64--;
			}

			/* last up to 7 8byte blocks */
			count %= 8;

			while (count) 
            { 
				asm("addq %1,%0\n\t"
				    "adcq %2,%0\n" 
					    : "=r" (result)
				    : "m" (*(unsigned long *)buff), 
				    "r" (zero),  "0" (result));

				--count; 
					buff += 8;
			}
			
            result = add32_with_carry(result>>32,
						  result&0xffffffff); 

			if (len & 4) 
            {
				result += *(unsigned int *) buff;
				buff += 4;
			}
		}

		if (len & 2) 
        {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}

	if (len & 1)
    {
		result += *buff;
    }

	result = add32_with_carry(result>>32, result & 0xffffffff); 
	
    if (unlikely(odd)) 
    { 
		result = from32to16(result);
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
	}

	return result;
}

/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 64-bit boundary
 */
static inline __wsum csum_partial(const void *buff, int len, __wsum sum)
{
	return (__wsum)add32_with_carry(do_csum((const unsigned char *)buff, len),
						(__u32)sum);
}

/**
 * csum_fold - Fold and invert a 32bit checksum.
 * sum: 32bit unfolded sum
 *
 * Fold a 32bit running checksum to 16bit and invert it. This is usually
 * the last step before putting a checksum into a packet.
 * Make sure not to mix with 64bit checksums.
 */
static inline __sum16 csum_fold(__wsum sum)
{
	asm("  addl %1,%0\n"
	    "  adcl $0xffff,%0"
	    : "=r" (sum)
	    : "r" ((__u32)sum << 16),
	      "0" ((__u32)sum & 0xffff0000));

	return (__sum16)(~(__u32)sum >> 16);
}


/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *
 *	By Jorge Cwik <jorge@laser.satlink.net>, adapted for linux by
 *	Arnt Gulbrandsen.
 */


/**
 * ip_fast_csum - Compute the IPv4 header checksum efficiently.
 * iph: ipv4 header
 * ihl: length of header / 4
 */
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	unsigned int sum;

	asm("  movl (%1), %0\n"
	    "  subl $4, %2\n"
	    "  jbe 2f\n"
	    "  addl 4(%1), %0\n"
	    "  adcl 8(%1), %0\n"
	    "  adcl 12(%1), %0\n"
	    "1: adcl 16(%1), %0\n"
	    "  lea 4(%1), %1\n"
	    "  decl %2\n"
	    "  jne	1b\n"
	    "  adcl $0, %0\n"
	    "  movl %0, %2\n"
	    "  shrl $16, %0\n"
	    "  addw %w2, %w0\n"
	    "  adcl $0, %0\n"
	    "  notl %0\n"
	    "2:"
	/* Since the input registers which are loaded with iph and ihl
	   are modified, we must also specify them as outputs, or gcc
	   will assume they contain their original values. */
	    : "=r" (sum), "=r" (iph), "=r" (ihl)
	    : "1" (iph), "2" (ihl)
	    : "memory");

	return (__sum16)sum;
}

/**
 * csum_tcpup_nofold - Compute an IPv4 pseudo header checksum.
 * @saddr: source address
 * @daddr: destination address
 * @len: length of packet
 * @proto: ip protocol of packet
 * @sum: initial sum to be added in (32bit unfolded)
 *
 * Returns the pseudo header checksum the input data. Result is
 * 32bit unfolded.
 */
static inline __wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr, __u32 len, __u8 proto, __wsum sum)
{
	asm("  addl %1, %0\n"
	    "  adcl %2, %0\n"
	    "  adcl %3, %0\n"
	    "  adcl $0, %0\n"
	    : "=r" (sum)
	    : "g" (daddr), "g" (saddr),
	      "g" ((len + proto)<<8), "0" (sum));
          
	return sum;
}


/**
 * csum_tcpup_magic - Compute an IPv4 pseudo header checksum.
 * @saddr: source address
 * @daddr: destination address
 * @len: length of packet
 * @proto: ip protocol of packet
 * @sum: initial sum to be added in (32bit unfolded)
 *
 * Returns the 16bit pseudo header checksum the input data already
 * complemented and ready to be filled in.
 */
static inline __sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len, __u8 proto, __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

#endif

static __always_inline uint16_t csum_fold_helper(uint32_t csum) 
{
    uint32_t r = csum << 16 | csum >> 16;
    csum = ~csum;
    csum -= r;
    return (uint16_t)(csum >> 16);
}

static __always_inline uint32_t csum_add(uint32_t addend, uint32_t csum) 
{
    uint32_t res = csum;
    res += addend;
    return (res + (res < addend));
}

static __always_inline uint32_t csum_sub(uint32_t addend, uint32_t csum) 
{
    return csum_add(csum, ~addend);
}


static __always_inline void update_iph_checksum(struct iphdr *iph) 
{
#ifndef __BPF__
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
#else
    uint16_t *next_iph_u16 = (uint16_t *)iph;
    uint32_t csum = 0;
    iph->check = 0;
#pragma clang loop unroll(full)
    for (uint32_t i = 0; i < sizeof(*iph) >> 1; i++) {
        csum += *next_iph_u16++;
    }

    iph->check = ~((csum & 0xffff) + (csum >> 16));
#endif
}

static __always_inline uint16_t csum_diff4(uint32_t from, uint32_t to, uint16_t csum) 
{
    uint32_t tmp = csum_sub(from, ~((uint32_t)csum));
    return csum_fold_helper(csum_add(to, tmp));
}