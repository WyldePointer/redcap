/*
 * Copyright (c) 2017, Sohrab Monfared <sohrab.monfared@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the <organization> nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <hiredis/hiredis.h>

/* Arguments for redisConnect() */
redisContext *redis;
struct timeval redis_timeout = { 1, 0 };

/* Supplied via command-line arguments */
char *redis_key_name = NULL;
unsigned int redis_incrby_interval = 0;
unsigned int redis_bgsave_interval = 0;
unsigned int current_unsaved_packets = 0;
unsigned int currently_not_incremented = 0;
unsigned int total_packets_to_capture = 0;
unsigned int bytes_not_incremented = 0;

/* libpcap callback function */
void
redcap_got_packet(
  u_char *args,
  const struct pcap_pkthdr* pkthdr,
  const u_char* packet
)
{

  bytes_not_incremented += pkthdr->caplen;

  currently_not_incremented++;

  if (currently_not_incremented == redis_incrby_interval){

    redisCommand(
      redis,
      "INCRBY %s %d",
      redis_key_name, bytes_not_incremented
    );

    currently_not_incremented = 0;

  }

  if (redis_bgsave_interval > 0) {

    current_unsaved_packets++;

    if (current_unsaved_packets == redis_bgsave_interval){

      redisCommand(redis,"BGSAVE");

      current_unsaved_packets = 0;

    }

  }

}

int main(int argc, char *argv[]){

  pcap_t *handle;                /* Instance of pcap */
  char errbuf[PCAP_ERRBUF_SIZE]; /* Error string for pcap */
  struct bpf_program filter;     /* Compiled filter expression for pcap */
  bpf_u_int32 ip;                /* IP of the device. (pcap) */
  bpf_u_int32 netmask;           /* Netmask of the device. (pcap) */


  if ( argc < 6 ){

    fprintf(stderr, "Usage: %s <device> <filter_expression> <count>"
      " <redis_key> <redis_incrby_interval>"
      " [redis_bgsave_interval]\n", argv[0]);

    return -1;
  }

  total_packets_to_capture = atoi(argv[3]);

  redis_key_name = argv[4];

  redis_incrby_interval = atoi(argv[5]);

  if ( argc > 6){
    redis_bgsave_interval = atoi(argv[6]);
  }

  if (
    total_packets_to_capture < redis_incrby_interval &&
    total_packets_to_capture > 0
  )
  {

    fprintf(stderr, "[WARNING] supplied packet_count(%d)"
      "is smaller than incrby interval(%d)."
      " (Redis won't be updated)\n",
      total_packets_to_capture, redis_incrby_interval);

  }

  redis = redisConnectWithTimeout("127.0.0.1", 6379, redis_timeout);

  if (redis == NULL || redis->err) {

      if (redis) {

          printf("Redis connection error: %s. (redis-server is running?)\n",
            redis->errstr);

          redisFree(redis);

      } else {

          printf("C redis error: can't allocate redis context.\n");

      }

    return -2;
  }

  if (pcap_lookupnet(argv[1], &ip, &netmask, errbuf) == -1) {

    fprintf(stderr, "Can't get netmask for device %s\n", argv[1]);

    ip = 0;

    netmask = 0;

  }

  handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "Failed to open %s: %s\n", argv[1], errbuf);
    return(-3);
  }

  if (pcap_compile(handle, &filter, argv[2], 0, ip) == -1) {

    fprintf(stderr, "%s in \"%s\".\n",
      pcap_geterr(handle), argv[2]);

    return(-4);
  }

  if (pcap_setfilter(handle, &filter) == -1) {

    fprintf(stderr, "Filter \"%s\" set failed: %s\n",
      argv[2], pcap_geterr(handle));

    return(-5);
  }

  printf("Listening on: %s\n", argv[1]);

  if (total_packets_to_capture > 0){
    printf("Packets to capture: %d\n", total_packets_to_capture);
  }

  printf("Expression: %s\n"
    "Redis key: %s\n"
    "INCRBY every %d packets.\n",
    argv[2], argv[4], redis_incrby_interval);

  if (redis_bgsave_interval == 0){

    printf("BGSAVE is disabled.\n");

  } else {

    printf("BGSAVE every %d packets.\n", redis_bgsave_interval);

  }

  pcap_loop(handle, total_packets_to_capture, redcap_got_packet, NULL);

  redisFree(redis);

  return 0;
}
