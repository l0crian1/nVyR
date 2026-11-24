# MACsec interfaces

Use MACsec to protect Ethernet frames between adjacent devices. Configure the IP addresses or bridge membership on the secured interface. The source interface carries MKA (EtherType 0x888e) and protected traffic (0x88e5).

Generate one connectivity association on either router and copy the same CKN and CAK to both peers over a trusted channel. The CKN identifies the association. The CAK is secret.

```text
generate macsec preshared-key
generate macsec preshared-key bits 256
```

Each invocation generates a new pair. Paste the output after `mka preshared-key`. For example, configure the first router with:

```text
set interfaces macsec macsec0 source-interface eth2
set interfaces macsec macsec0 mka preshared-key ckn <shared-ckn> cak <shared-cak>
set interfaces macsec macsec0 address 192.0.2.1/30
set interfaces macsec macsec0 replay-protection window 64
commit
```

Configure the peer with its own source interface, the same keys, and `192.0.2.2/30`. Both ends can use the default SCI port of 1. MKA elects the key server and negotiates traffic keys. Set `mka key-server-priority` to influence the election. Lower values take precedence.

The default transmit mode authenticates and encrypts traffic. Use `transmit-mode integrity-only` for authentication with a visible payload. Enabling `replay-protection` by itself selects a zero-packet reordering window. An explicit window permits reordering. The Linux MACsec interface inherits an MTU that accounts for MACsec overhead. To change its source interface or SCI port, delete the MACsec interface, commit, and recreate it.

```text
show macsec
show macsec macsec0 detail
show macsec macsec0 counters
show interfaces macsec
```

Check `Secured` on both peers and compare the key-server SCI. Encrypted traffic increments `OutPktsEncrypted` on the transmitter and validated traffic increments `InPktsOK` on the receiver. The Linux driver in Debian's supplicant uses GCM-AES-128 for traffic with either supported CAK length. Debian maintains the MKA provider in the wpa source package. [Debian wpa security tracker](https://security-tracker.debian.org/tracker/source-package/wpa)
