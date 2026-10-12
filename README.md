# CIP-B103 Lab [#] – Wireless Forensics: WEP Key Recovery, Traffic Decryption & Object Carving

**Student:** Fuseini Imoru Kantuogaa  
**Course:** CIP-B103  
**Lab:** Lab [#] – 802.11 Capture Analysis, WEP Cracking and Decrypted-Traffic Examination

## Overview

This lab demonstrates a wireless-network forensics workflow: acquiring and hashing an 802.11 packet capture, inspecting its protocol structure, identifying the weak-IV behavior that makes WEP crackable, recovering the WEP key with `aircrack-ng`, decrypting the full capture with `airdecap-ng`, and then analyzing the plaintext traffic for hosts, conversations and transferred objects (via HTTP object export and file carving with `foremost`). The goal was to show that a WEP-protected network can be fully broken from a captured file and that doing so exposes the cleartext of everything the client sent.

## Case Folder Structure

```
mkdir -p ~/CIP-B103-Lab9/{evidence,working,exported,reports,screenshots,scripts}
cd ~/CIP-B103-Lab9
```

| Folder | Purpose |
|---|---|
| evidence/ | Original downloaded file, never modified |
| working/ | Working copies: decompressed capture, decrypted capture |
| exported/ | Carved/exported objects (HTTP export, foremost output) |
| reports/ | All command output, hashes and TSV/TXT artifacts |
| screenshots/ | Reserved for screen captures |
| scripts/ | Reserved for helper scripts |

`pwd` confirmed `/home/kali/CIP-B103-Lab9`; `find . -maxdepth 1 -type d -print` confirmed all seven directories were created.

## 1. Tool Setup

```
sudo apt install -y aircrack-ng wireshark tshark foremost binwalk xz-utils
```

wireshark, tshark, foremost and binwalk were already the newest versions; `aircrack-ng`, `liblzma-dev`, `liblzma5` and `xz-utils` were upgraded (aircrack-ng to 1:1.7+git20230807.4bf83f1a-3).

| Tool | Version | Purpose |
|---|---|---|
| tshark / capinfos (Wireshark) | 4.6.6-1 | Capture inspection, field extraction, statistics, object export |
| aircrack-ng | 1.7 (git 20230807) | WEP key recovery (PTW attack) |
| airdecap-ng | bundled with aircrack-ng | Decrypting the WEP-protected capture |
| foremost | 1.5.7-11+b2 | File carving from the decrypted capture |
| binwalk | 2.4.3+dfsg1-2 | Available for signature scanning (installed, not separately invoked below) |
| xz-utils | 5.8.3-1 | Decompressing the downloaded .xz evidence file |
| sha256sum | Linux | Hashing at every stage for chain of custody |

## 2. Acquiring the Evidence

```
wget -O evidence/file.xz 'https://raw.githubusercontent.com/ctfs/write-ups-2015/master/codegate-ctf-2015/programming/good-crypto/file.xz'
ls -lh evidence/
sha256sum evidence/file.xz | tee reports/file_xz_sha256.txt
```

| Property | Value |
|---|---|
| Source | raw.githubusercontent.com (codegate-ctf-2015 write-up repo) |
| Downloaded | 2026-08-11 18:18:00–18:18:11 (9.4 s, 1.31 MB/s) |
| File | evidence/file.xz |
| Size | 12,837,660 bytes (12 M / 13 M on disk) |
| SHA-256 | dd54144caef34f228bfb4b87a9101ca7173969376f7ed357bd068061d4f4b8d6 |

## 3. Preparing a Working Copy and Decompressing

The original was never touched; all analysis used a copy:

```
cp --preserve=timestamps evidence/file.xz working/file_working.xz
unxz -k working/file_working.xz
file working/file_working
sha256sum working/file_working.xz working/file_working | tee reports/working_hashes.txt
```

| File | Identification / Hash |
|---|---|
| working/file_working.xz | SHA-256 dd54144caef34f228bfb4b87a9101ca7173969376f7ed357bd068061d4f4b8d6 (matches evidence/file.xz — copy verified) |
| working/file_working | `file` reports: pcap capture file, microsecond ts (little-endian), version 2.4, 802.11, capture length 65535 |
| working/file_working | SHA-256 c17a3f9b955e84f5befd476dbd55c67286d1e3eea9ab402d5359cac0874ebb2d |

`tree` at this point confirmed the decompressed capture, its hash reports and the untouched evidence file all existed under the expected folders (7 directories, 5 files).

## 4. Capture-Level Identification

```
CAP=working/file_working
capinfos "$CAP" | tee reports/capinfos.txt
```

| Field | Value |
|---|---|
| File type | Wireshark/tcpdump – pcap |
| Encapsulation | IEEE 802.11 Wireless LAN |
| Timestamp precision | microseconds (6) |
| Packet size limit | file hdr: 65535 bytes |
| Number of packets | 45,169 |
| File size / Data size | 14 MB / 13 MB |
| Capture duration | 272.969795 seconds (~4 min 33 s) |
| Earliest packet | 2015-03-06 02:51:54.364525 |
| Latest packet | 2015-03-06 02:56:27.334320 |
| Data byte/bit rate | 49 kBps / 395 kbps |
| Average packet size / rate | 299.13 bytes / 165 packets/s |
| SHA256 / SHA1 (capinfos) | c17a3f9b955e…874ebb2d / cb929fd6e407…788478d3 |
| Strict time order | False |
| Interfaces | 1 (IEEE 802.11, capture length 65535, 1,000,000 ticks/s, 45,169 packets) |

## 5. Protocol Hierarchy

```
tshark -r "$CAP" -q -z io,phs | tee reports/protocol_hierarchy.txt
```

| Layer | Frames | Bytes |
|---|---|---|
| frame | 45,169 | 13,511,274 |
| wlan | 45,169 | 13,511,274 |
| wlan.data | 15,713 | 13,104,128 |

The entire capture is raw 802.11 (wlan) traffic, with 15,713 of 45,169 frames carrying data (the rest are management/control frames such as beacons, RTS/CTS and ACKs).

## 6. 802.11 Frame Sampling

```
tshark -r "$CAP" -Y 'wlan' -T fields \
  -e frame.number -e frame.time -e wlan.fc.type -e wlan.fc.subtype \
  -e wlan.sa -e wlan.da -e wlan.bssid \
  | head -n 100 | tee reports/wlan_frame_sample.tsv
```

The first dozens of frames are almost entirely type 1 / subtype 11 (control-frame RTS/CTS-style signaling with no source/destination shown), timestamped within a sub-millisecond window at 2015-03-06 02:51:54. Frame 54 is a type 0 / subtype 8 management frame (a beacon) with source address, destination (broadcast ff:ff:ff:ff:ff:ff) and BSSID all equal to **00:26:66:55:97:d6** — this is the access point whose network was targeted.

## 7. Identifying WEP-Protected Traffic and IV Reuse

```
tshark -r "$CAP" -Y 'wlan.fc.protected==1' -T fields \
  -e frame.number -e frame.time_epoch -e wlan.sa -e wlan.da -e wlan.bssid \
  -e wlan.wep.iv -e wlan.wep.key \
  | head -n 200 | tee reports/wep_protected_frames.tsv
```

All protected frames share BSSID **00:26:66:55:97:d6**, confirming a single WEP-encrypted network was captured, with multiple client/station MACs (e.g. f0:f6:1c:68:96:7c, 00:26:66:55:97:d4, c8:3a:35:58:c4:ba and others) sending or receiving encrypted data.

```
tshark -r "$CAP" -Y 'wlan.fc.protected==1' -T fields -e wlan.wep.iv \
  | sort | uniq -c | sort -nr | head -n 30 | tee reports/repeated_iv_summary.txt
```

| IV (hex) | Times seen |
|---|---|
| 0x42e8eb | 7 |
| 0x28d3eb | 7 |
| 0x95dfeb | 6 |
| 0x9415ed, 0x86e5eb, 0x7ae5eb, 0x28e7eb, 0x19e5eb | 5 each |
| (several more) | 3–4 each |

WEP's 24-bit Initialization Vector space is small enough that IVs repeat quickly on a busy network. This repeated-IV pattern is the exact weakness the PTW (Pyshkin-Tews-Weinmann) attack exploits to recover the RC4 key from captured ciphertext alone, without needing to inject or deauthenticate.

## 8. WEP Key Recovery

```
aircrack-ng "$CAP" | tee reports/aircrack_output.txt
```

| Field | Value |
|---|---|
| BSSID | 00:26:66:55:97:D6 |
| ESSID | cgnetwork |
| Encryption | WEP (15,477 IVs) |
| Attack | PTW, 15,477/15,000 IVs, 1 potential target |
| **KEY FOUND** | **A4:3D:F6:F3:74** |
| Decrypted correctly | 100% |

```
printf 'A4:3D:F6:F3:74\n' | tee reports/validated_wep40_key_masked.txt
grep -E 'KEY FOUND|Decrypted correctly|BSSID|ESSID|WEP' reports/aircrack_output.txt
```

(The key was re-recorded into its own file by hand after the first `cat` attempt on a not-yet-created `validated_wep40_key_masked.txt` failed with "No such file or directory" — expected, since that file had not been written yet.)

The recovered value is a 40-bit (5-byte) WEP key, cracked in well under a second of CPU time because the PTW attack only needed the ~15,000 IVs already present in the capture.

## 9. Decrypting the Full Capture

```
cd ~/CIP-B103-Lab9/working
airdecap-ng -w A43DF6F374 file_working | tee ../reports/airdecap_output.txt
```

| Metric | Value |
|---|---|
| Stations seen | 10 |
| Packets read | 45,169 |
| WEP data packets | 15,477 |
| WPA data packets | 0 |
| Plaintext data packets | 0 |
| **Decrypted WEP packets** | **15,477** |
| Corrupted WEP packets | 0 |
| Decrypted WPA packets | 0 |
| Bad TKIP / bad CCMP packets | 0 |

Every single WEP data packet in the capture decrypted successfully (0 corrupted), confirming the recovered key `A4:3D:F6:F3:74` is correct.

```
cd ~/CIP-B103-Lab9
find working -maxdepth 1 -type f -ls | tee reports/decrypted_files_inventory.txt
sha256sum working/* | tee reports/all_working_file_hashes.txt
```

| File | Size | SHA-256 |
|---|---|---|
| working/file_working | 14,234,002 bytes | c17a3f9b955e84f5befd476dbd55c67286d1e3eea9ab402d5359cac0874ebb2d |
| working/file_working-dec | 12,784,501 bytes | 167c91994c269777f9048227deb89882caf3cf3c763977f2059604f9a6a40b04 |
| working/file_working.xz | 12,837,660 bytes | dd54144caef34f228bfb4b87a9101ca7173969376f7ed357bd068061d4f4b8d6 |

```
DEC=$(find working -maxdepth 1 -type f -name '*-dec*' | head -n 1)
echo "Decrypted capture: $DEC" | tee reports/decrypted_capture_path.txt
```

`DEC` resolved to `working/file_working-dec` (13 MB, confirmed later with `ls -lh "$DEC"`).

## 10. Analyzing the Decrypted Traffic — Endpoints and Conversations

```
tshark -r "$DEC" -q -z endpoints,eth | tee reports/ethernet_endpoints.txt
tshark -r "$DEC" -q -z endpoints,ip  | tee reports/ip_endpoints.txt
tshark -r "$DEC" -q -z conv,tcp      | tee reports/tcp_conversations.txt
```

| Ethernet endpoint | Packets | Bytes | Role |
|---|---|---|---|
| Apple_68:96:7c | 15,407 | 12 MB | Client device (the wireless station being decrypted) |
| EFMNetworks_55:97:d4 | 15,020 | 12 MB | Access point / gateway side |
| ASUSTekCOMPU_2a:c2:7a | 358 | 281 kB | Second local device |
| Multicast/broadcast groups | small | small | mDNS/SSDP/IGMP background chatter |

| IPv4 endpoint | Packets | Role |
|---|---|---|
| 192.168.0.15 | 15,309 (12 MB) | The decrypted client host — center of nearly all conversations |
| 198.90.20.111 | 8,057 (6.9 MB) | Largest single remote peer (web/TLS host) |
| 192.168.0.9 | 329 | Local peer |
| 173.194.127.x range, 8.8.8.8 | many | Google services and Google Public DNS |
| 199.16.158.186, 173.241.248.x | moderate | CDN/web hosts |

| TCP conversation (top) | Frames | Bytes |
|---|---|---|
| 192.168.0.15:51007 ↔ 198.90.20.111:80 | 2,235 | 1,958 kB |
| 192.168.0.15:50959 ↔ 199.27.79.193:80 | 2,168 | 1,887 kB |
| 192.168.0.15:51008 ↔ 198.90.20.111:80 | 2,106 | 1,810 kB |
| 192.168.0.15:51001 ↔ 199.27.79.193:80 | 2,072 | 1,791 kB |
| 192.168.0.15:51009 ↔ 198.90.20.111:80 | 1,259 | 1,072 kB |

192.168.0.15 is confirmed as the device whose traffic was captured; it was the single largest talker to every one of the top remote IPs.

## 11. IP/Protocol Mapping Sample

```
tshark -r "$DEC" -Y 'ip' -T fields \
  -e frame.number -e wlan.sa -e wlan.da -e ip.src -e ip.dst -e _ws.col.Protocol \
  | head -n 200 | tee reports/ip_mac_mapping_sample.tsv
```

192.168.0.15's traffic pattern, in order, is typical normal device activity once WEP decryption is applied:

| Protocol seen | Example peer |
|---|---|
| DHCP | 192.168.0.1 (initial lease) |
| DNS | 8.8.8.8 (Google Public DNS) |
| IGMPv2 / MDNS | 224.0.0.2, 224.0.0.251 (local discovery) |
| TCP / TLSv1 / TLSv1.2 | 17.172.239.31, 17.172.239.127 (Apple), 31.13.70.1 (Facebook) |
| HTTP | 198.41.209.137, 23.21.196.154, 199.27.79.193 |

This is consistent with a consumer device (Apple-manufactured NIC) doing normal background syncing (Apple push/iCloud-style hosts), DNS lookups, mDNS discovery and web browsing (HTTP/TLS to CDN and ad/analytics-style hosts) — all of it readable in the clear once the WEP key was recovered.

## 12. Extracting Transferred Objects

```
mkdir -p exported/http_objects exported/foremost
tshark -r "$DEC" --export-objects http,exported/http_objects 2>&1 | tee reports/http_export_log.txt
find exported/http_objects -type f -ls
```

HTTP object export pulled out files actually downloaded over the plaintext HTTP sessions, including `logo.png`, `hit.json`, `rss.png`, a web-font (`.woff`), tracking pixels/images (`adc-i-00aecd.png`, `category-strip.png`) and, notably, **`superfish.min.js`** — a JavaScript file matching the name of the Superfish ad-injection/MITM software. Its presence here is a web-traffic artifact (a script served to the browser), not proof of an installed MITM certificate, but it is worth flagging for follow-up.

```
foremost -i "$DEC" -o exported/foremost | tee reports/foremost_log.txt
find exported/foremost -maxdepth 2 -type d -print
find exported/foremost -type f -ls
```

`foremost` carved the decrypted capture independently of HTTP reassembly and recovered JPEG, GIF, PNG and HTM artifacts into `jpg/`, `gif/`, `png/` and `htm/` subfolders (e.g. `jpg/00000104.jpg` at 264,865 bytes, `jpg/00004538.jpg` at 89,458 bytes, several small GIFs).

## 13. Identifying and Hashing Carved/Exported Files

```
find exported -type f -exec file {} \; | tee reports/exported_file_types.txt
find exported -type f -exec sha256sum {} \; | tee reports/exported_file_hashes.txt
```

| File | Type confirmed |
|---|---|
| exported/foremost/jpg/00000104.jpg | JPEG image data, JFIF 1.01, 2492×2492 |
| exported/foremost/jpg/00004538.jpg | JPEG image data, JFIF 1.01, 718×404 |
| exported/foremost/gif/00003653.gif, 00002450.gif, 00001260.gif, 00000406.gif | GIF image data, version 89a, 1×1 (tracking pixels) |
| exported/foremost/audit.txt | ASCII text (foremost's own audit log) |

Several of the carved GIFs are 1×1 pixel images — classic web-beacon/tracking-pixel artifacts, consistent with the ad/analytics-style hosts seen in the IP endpoint list. All exported and carved files were hashed for the evidence record (`reports/exported_file_hashes.txt`).

## Conclusion

**The captured 802.11 traffic was WEP-encrypted on a network with ESSID "cgnetwork" and BSSID 00:26:66:55:97:D6, and the WEP key (A4:3D:F6:F3:74) was fully recovered from the capture alone using aircrack-ng's PTW attack, because WEP's 24-bit IV space caused IVs to repeat within the ~45,000-frame, 4.5-minute capture (IVs observed repeating up to 7 times).** Once decrypted with `airdecap-ng`, all 15,477 WEP data packets decoded cleanly (0 corrupted), proving the key is correct, and the resulting plaintext traffic shows a single client (192.168.0.15, an Apple-NIC device) performing ordinary DHCP, DNS, mDNS, HTTP and TLS activity to Google, Apple, Facebook and various web/ad-tracking hosts — all of which would have been completely opaque had the capture been attacked only passively, but is now fully readable, including recoverable images, scripts and tracking pixels.

This demonstrates, end-to-end, why WEP is considered cryptographically broken: an attacker with only a captured file (no active injection required) and a few minutes of traffic can recover the key and read everything a client sent or received on that network, including files, hostnames and behavioral/tracking data.

## Key Tools Used

| Tool | Purpose |
|---|---|
| wget / sha256sum / unxz | Acquisition, integrity hashing, decompression |
| capinfos (Wireshark) | Capture-level metadata and hash verification |
| tshark | Protocol hierarchy, field extraction, IV/weakness analysis, endpoint/conversation statistics, HTTP object export |
| aircrack-ng | WEP key recovery (PTW attack) |
| airdecap-ng | Decrypting the full capture with the recovered key |
| foremost | File carving of the decrypted capture for images and other file types |
| find / file / sha256sum | Inventorying, identifying and hashing all generated and carved files |

## Forensic Notes

- The original `evidence/file.xz` was never modified; all work was performed on `working/` copies, and the SHA-256 of the working `.xz` was checked against the evidence copy before use (both dd54144c…4b8d6), confirming an exact copy.
- The capture's own hash (`file_working`, c17a3f9b…874ebb2d) matched between `capinfos` and `sha256sum`, and remained referenced consistently through decryption (the pre- and post-decryption files are tracked separately: `file_working` vs. `file_working-dec`).
- The WEP key was recovered passively from stored IVs already present in the capture (PTW attack); no packet injection against a live network occurred as part of this exercise — all analysis is against a static, previously captured file.
- `airdecap-ng` reported 0 corrupted WEP packets and 0 bad TKIP/CCMP packets, which is the standard confirmation that the recovered key is correct and that decryption is reliable across the entire capture, not just a sample.
- `reports/validated_wep40_key_masked.txt` initially did not exist when first `cat`, producing a normal "No such file or directory" error; it was created immediately afterward with `printf`, so the output used subsequently was already correct.
- The presence of `superfish.min.js` among exported HTTP objects is noted as a point worth independent follow-up (script name match only); the capture does not by itself prove a Superfish certificate was installed on the client.
- Capture timestamps (2015-03-06) predate the Kali host's 2026 system clock seen in command prompts; the 2026 dates reflect only when the lab was performed, not when the traffic was captured.
- All reports, hashes, TSVs and carved files were written under `reports/` and `exported/` respectively, keeping the original evidence, working copies and derived output cleanly separated for chain of custody.
