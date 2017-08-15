# redcap
Lightweight cross-platform packet counter based on `libpcap` and using Redis for storing the statistics.

#### Usage
`./redcap_count <device> <filter> <count> <redis_key> <redis_incrby_interval> [redis_bgsave_interval]`

 - `<device>`: Interface name. (`eth0`, `re0`, `lo`, etc.)
 - `<filter>`: <a href="http://www.tcpdump.org/manpages/pcap-filter.7.html" target="_blank">libpcap expression.</a>
 - `<count>`: How many packets to capture. 0 for infinite.
 - `<redis_key>`: Redis key to store the number.
 - `<redis_incrby_interval>`: Update the Redis data after receiving 'n' packets.
 - `[redis_bgsave_interval]`: If provided, it will run an <a href="https://redis.io/commands/bgsave" target="_blank">asynchronus write-to-disk</a> on redis.

#### Dependencies
 - `libpcap`
 - <a href="https://github.com/redis/hiredis" target="_blank">`hiredis`</a>

#### Compiling
`% cc -o redcap_count redcap_count.c -lpcap -lhiredis -pedantic -Wall`

#### Example
`# ./redcap_count eth0 "icmp[icmptype] == icmp-echo and dst host 8.8.8.8" 100 my_key 5 10`

 - Listening on `eth0`.
 - Filtering the `ICMP Echo Request`(`ping`) packets destinated for `8.8.8.8`.
 - Capturing 100 packets.
 - Storing as `my_key` in Redis.
 - Updating Redis after 5 packets.
 - Store the Redis data on disk after 10 packets. (optional)

 #### TODO
 - `redcap_bytes.c`
 - `verbose` option.
 - `<redis_index_id>`
 - Connecting to Redis via socket. (optional)
 - Remote Redis server. (Default on `127.0.0.1:6379`)
