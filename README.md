# Netflood
Netflow v9 packet generator.

This can extract Netflow v9 packets from pcap and dump template information to json.
And this generates Netflow v9 packets with random values depending on such template information.

# Usage
## Help
```sh
cargo run help
```

## Extract
Extract template information from pcap.

```sh
# extract template flow as json.
cargo run extract template netflows.pcapng > template.json 
# extract option template flow as json.
cargo run extract option netflows.pcapng > option.json
```

This command assumes packets of 2055/udp are Netflow.
I will add port specifying option later.

Extracted json samples are in ./sample/.

## Generate
Netflow v9 packets generation.

```sh
# Send Netflow v9 packets generated with template.json and option.json to 192.168.1.101:2055
cargo run generate 192.168.1.101 -t sample/template.json -o sample/option.json -i 3 -c 1000 -s 10001 -p 2055 -n
```

`-t`: Specify template information
`-o`: Specify option template information
`-i`: Interval to send next packet
`-c`: Num of sending packets
`-s`: Initial Sequence number of a Netflow packet
`-p`: Port
`-n`: Not adding padding. Netflow v9 specification(RFC 3954) saies that the exporter "SHOULD" insert padding, but not "MUST".
