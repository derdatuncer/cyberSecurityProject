#!/usr/bin/env python3
import os, json, csv, random
from collections import Counter, defaultdict
from pathlib import Path
from scapy.all import rdpcap, Ether, ARP, IP, TCP, UDP, ICMP, DNS, DNSRR, DHCP, BOOTP

PCAP_DIR = Path("/home/osboxes/pcaps")
# JSONL yerine standart JSON uzantÄ±sÄ±nÄ± ve yapÄ±sÄ±nÄ± kullanacaÄŸÄ±z
OUT_JSON  = PCAP_DIR / "dataset.json"
OUT_CSV   = PCAP_DIR / "dataset.csv"
OUT_TXT   = PCAP_DIR / "best_50_dataset.txt" # En iyi 50 Ã¶rnek iÃ§in yeni Ã§Ä±ktÄ±

WINDOW_SECONDS = 10
MIN_PACKETS_PER_WINDOW = 5
MAX_NORMAL_WINDOWS = 50
MAX_PER_ATTACK_WINDOWS = 25

PCAP_LABELS = {
    "00_recon_and_scan_extra.pcap": {"label": "malicious", "attack_type": "port_scan_recon"},
    "01_recon_and_scan.pcap": {"label": "malicious", "attack_type": "port_scan_recon"},
    "02_normal.pcap":         {"label": "normal",    "attack_type": None},
    "03_arp_spoof.pcap":      {"label": "malicious", "attack_type": "arp_spoof"},
    "04_dns_spoofing.pcap":   {"label": "malicious", "attack_type": "dns_spoof"},
    "05_dhcp_poisoning.pcap": {"label": "malicious", "attack_type": "dhcp_poison"},
}

KNOWN_HOSTS = {
    "192.168.100.1":  "gateway",
    "192.168.100.50": "kali_attacker",
}

def role_for(ip):
    if ip in KNOWN_HOSTS:
        return KNOWN_HOSTS[ip]
    if ip.startswith("192.168.100."):
        return "internal_host"
    if ip.startswith("224.") or ip.startswith("239."):
        return "multicast"
    if ip == "255.255.255.255":
        return "broadcast"
    return "external"

def ip_label(ip):
    role = role_for(ip)
    if role in ("gateway", "kali_attacker", "internal_host"):
        return f"{ip} ({role})"
    return ip

def safe_qname(dns_layer):
    try:
        return dns_layer.qd.qname.decode(errors="ignore").rstrip(".")
    except Exception:
        return ""

def summarize_window(packets, window_idx, start_t, end_t):
    n = len(packets)
    duration = end_t - start_t
    proto_counts = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    tcp_flag_counts = Counter()
    tcp_dst_ports = Counter()
    udp_dst_ports = Counter()
    arp_request_count = 0
    arp_reply_count = 0
    arp_sender_ip_to_mac = defaultdict(set)
    dns_queries = []
    dns_answers = []
    dhcp_msg_type_counts = Counter()
    dhcp_offer_servers = []
    dhcp_types_map = {1:"DISCOVER",2:"OFFER",3:"REQUEST",4:"DECLINE",
                      5:"ACK",6:"NAK",7:"RELEASE",8:"INFORM"}

    for pkt in packets:
        if ARP in pkt:
            arp = pkt[ARP]
            proto_counts["ARP"] += 1
            if arp.op == 1:
                arp_request_count += 1
            elif arp.op == 2:
                arp_reply_count += 1
            if arp.psrc and arp.hwsrc:
                arp_sender_ip_to_mac[arp.psrc].add(arp.hwsrc)
            continue

        if IP not in pkt:
            continue

        ip = pkt[IP]
        src_ips[ip.src] += 1
        dst_ips[ip.dst] += 1

        if TCP in pkt:
            proto_counts["TCP"] += 1
            tcp = pkt[TCP]
            flags = tcp.flags
            if flags & 0x02: tcp_flag_counts["SYN"] += 1
            if flags & 0x10: tcp_flag_counts["ACK"] += 1
            if flags & 0x04: tcp_flag_counts["RST"] += 1
            if flags & 0x01: tcp_flag_counts["FIN"] += 1
            if flags & 0x08: tcp_flag_counts["PSH"] += 1
            tcp_dst_ports[tcp.dport] += 1

        elif UDP in pkt:
            proto_counts["UDP"] += 1
            udp = pkt[UDP]
            udp_dst_ports[udp.dport] += 1

            if DNS in pkt:
                proto_counts["DNS"] += 1
                dns = pkt[DNS]
                if dns.qr == 0:
                    qname = safe_qname(dns)
                    if qname:
                        dns_queries.append(qname)
                elif dns.qr == 1 and dns.ancount > 0:
                    qname = safe_qname(dns)
                    try:
                        ans = dns.an
                        while ans is not None:
                            if isinstance(ans, DNSRR) and ans.type == 1:
                                rdata = ans.rdata
                                if isinstance(rdata, bytes):
                                    rdata = rdata.decode(errors="ignore")
                                dns_answers.append((qname, str(rdata)))
                            if not hasattr(ans, "payload"):
                                break
                            ans = ans.payload
                            if not isinstance(ans, DNSRR):
                                break
                    except Exception:
                        pass

            if DHCP in pkt:
                proto_counts["DHCP"] += 1
                try:
                    for opt in pkt[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == "message-type":
                            mtype = dhcp_types_map.get(opt[1], f"TYPE_{opt[1]}")
                            dhcp_msg_type_counts[mtype] += 1
                            if mtype == "OFFER" and BOOTP in pkt:
                                dhcp_offer_servers.append(pkt[BOOTP].siaddr)
                except Exception:
                    pass

        elif ICMP in pkt:
            proto_counts["ICMP"] += 1

    # DavranÄ±ÅŸsal sinyaller
    behaviors = []

    if len(tcp_dst_ports) >= 20 and tcp_flag_counts["SYN"] > 30:
        ratio = tcp_flag_counts["ACK"] / max(tcp_flag_counts["SYN"], 1)
        if tcp_flag_counts["RST"] > 10 or ratio < 0.3:
            behaviors.append(
                f"port_scan_signature (distinct_dst_ports={len(tcp_dst_ports)}, "
                f"SYN={tcp_flag_counts['SYN']}, RST={tcp_flag_counts['RST']})"
            )

    conflicting = {ip: list(macs) for ip, macs in arp_sender_ip_to_mac.items() if len(macs) > 1}
    for cip, macs in conflicting.items():
        behaviors.append(f"arp_conflict (IP {cip} announced by MACs {macs})")

    if arp_reply_count >= 20:
        behaviors.append(f"high_arp_reply_rate (count={arp_reply_count})")

    answer_by_qname = defaultdict(set)
    for q, a in dns_answers:
        answer_by_qname[q].add(a)
    for q, a_list in list(answer_by_qname.items())[:3]:
        if len(a_list) > 1:
            behaviors.append(f"dns_answer_conflict ({q} -> {list(a_list)})")

    answer_ip_counter = Counter(a for _, a in dns_answers)
    if answer_ip_counter:
        top_ip, top_n = answer_ip_counter.most_common(1)[0]
        if top_n >= 5 and top_ip.startswith("192.168.100."):
            behaviors.append(
                f"dns_responses_pointing_to_internal_ip "
                f"({top_ip} appears in {top_n} answers)"
            )

    unique_offer_servers = set(s for s in dhcp_offer_servers if s and s != "0.0.0.0")
    if len(unique_offer_servers) >= 2:
        behaviors.append(f"multiple_dhcp_offer_servers ({sorted(unique_offer_servers)})")

    if dhcp_msg_type_counts["DISCOVER"] >= 20:
        behaviors.append(
            f"high_dhcp_discover_rate (count={dhcp_msg_type_counts['DISCOVER']})"
        )

    # Ã–zet metin
    lines = []
    lines.append(f"Time window #{window_idx}: duration={duration:.1f}s, total_packets={n}")
    lines.append("Protocol mix: " + ", ".join(f"{k}={v}" for k, v in proto_counts.most_common()))

    top_src = src_ips.most_common(5)
    top_dst = dst_ips.most_common(5)
    if top_src:
        lines.append("Top source IPs: " + ", ".join(f"{ip_label(i)}={c}" for i, c in top_src))
    if top_dst:
        lines.append("Top dest IPs: " + ", ".join(f"{ip_label(i)}={c}" for i, c in top_dst))

    if proto_counts.get("TCP", 0) > 0:
        lines.append("TCP flags: " + ", ".join(f"{k}={v}" for k, v in tcp_flag_counts.most_common()))
        lines.append(f"TCP distinct_dst_ports={len(tcp_dst_ports)}, "
                     f"top_ports={tcp_dst_ports.most_common(10)}")

    if proto_counts.get("ARP", 0) > 0:
        lines.append(f"ARP: requests={arp_request_count}, replies={arp_reply_count}, "
                     f"distinct_announced_IPs={len(arp_sender_ip_to_mac)}")

    if proto_counts.get("DNS", 0) > 0:
        unique_q = list(dict.fromkeys(dns_queries))[:8]
        lines.append(f"DNS queries: count={len(dns_queries)}, examples={unique_q}")
        if answer_ip_counter:
            lines.append("DNS answer IPs: " + ", ".join(
                f"{ip}({c})" for ip, c in answer_ip_counter.most_common(5)))

    if proto_counts.get("DHCP", 0) > 0:
        lines.append("DHCP types: " + ", ".join(
            f"{k}={v}" for k, v in dhcp_msg_type_counts.most_common()))
        if unique_offer_servers:
            lines.append(f"DHCP OFFER servers: {sorted(unique_offer_servers)}")

    if behaviors:
        lines.append("Behavioral indicators: " + "; ".join(behaviors))
    else:
        lines.append("Behavioral indicators: none")

    return "\n".join(lines)

def split_into_windows(pcap_path):
    print(f"  Reading {pcap_path.name} ...", end=" ", flush=True)
    try:
        pkts = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"(Error reading pcap: {e})")
        return []

    if not pkts:
        print("(empty)")
        return []
    print(f"{len(pkts)} packets")
    t0 = float(pkts[0].time)
    windows = []
    current = []
    current_start = t0
    for pkt in pkts:
        t = float(pkt.time)
        if t - current_start < WINDOW_SECONDS:
            current.append(pkt)
        else:
            if current:
                windows.append((current_start, float(current[-1].time), current))
            while t - current_start >= WINDOW_SECONDS:
                current_start += WINDOW_SECONDS
            current = [pkt]
    if current:
        windows.append((current_start, float(current[-1].time), current))
    return windows

def main():
    if not PCAP_DIR.exists():
        print(f"HATA: {PCAP_DIR} bulunamadÄ±.")
        return

    all_windows = []
    for fname, meta in PCAP_LABELS.items():
        path = PCAP_DIR / fname
        if not path.exists():
            print(f"UYARI: {fname} bulunamadÄ±, atlandÄ±.")
            continue
        print(f"[*] Processing {fname} -> label={meta['label']}, attack={meta['attack_type']}")
        windows = split_into_windows(path)
        windows = [w for w in windows if len(w[2]) >= MIN_PACKETS_PER_WINDOW]
        print(f"  -> {len(windows)} windows after filtering")
        for idx, (s, e, pkts) in enumerate(windows, 1):
            summary = summarize_window(pkts, idx, s, e)
            all_windows.append({
                "label": meta["label"],
                "attack_type": meta["attack_type"],
                "source_pcap": fname,
                "window_index": idx,
                "summary": summary,
            })

    by_bucket = defaultdict(list)
    for w in all_windows:
        key = w["attack_type"] if w["label"] == "malicious" else "normal"
        by_bucket[key].append(w)

    random.seed(42)
    selected = []
    
    # TÃ¼m pencereleri havuzda toplama
    normal = by_bucket.get("normal", [])
    random.shuffle(normal)
    selected.extend(normal[:MAX_NORMAL_WINDOWS])
    
    for key, lst in by_bucket.items():
        if key == "normal":
            continue
        random.shuffle(lst)
        selected.extend(lst[:MAX_PER_ATTACK_WINDOWS])

    random.shuffle(selected)
    
    # ID atamasÄ± (JSON ve CSV iÃ§in)
    output_data = []
    for i, w in enumerate(selected, 1):
        item = {
            "id": i, 
            "label": w["label"],
            "attack_type": w["attack_type"],
            "source_pcap": w["source_pcap"],
            "window_index": w["window_index"],
            "summary": w["summary"]
        }
        output_data.append(item)

    # 1. STANDART JSON Ã‡IKTISI (GeÃ§erli Format)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False, indent=4)

    # 2. CSV Ã‡IKTISI
    with open(OUT_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id","label","attack_type","source_pcap","window_index","summary"])
        for w in output_data:
            writer.writerow([w["id"], w["label"], w["attack_type"] or "",
                             w["source_pcap"], w["window_index"], w["summary"]])

    # ==========================================
    # 3. YÃœKSEK KALÄ°TELÄ° 50 Ã–RNEK (.txt Ã‡Ä±ktÄ±sÄ±)
    # ==========================================
    
    # AdÄ±m A: YanlÄ±ÅŸ pozitif olmayan temiz "Normal" trafiÄŸi seÃ§ (25 Adet)
    best_normals = [w for w in output_data if w["label"] == "normal" and "Behavioral indicators: none" in w["summary"]]
    random.shuffle(best_normals)
    selected_normals = best_normals[:25]

    # AdÄ±m B: GÃ¼Ã§lÃ¼ Sinyal barÄ±ndÄ±ran SaldÄ±rÄ±larÄ± seÃ§ (25 Adet, Dengeli)
    best_malicious = defaultdict(list)
    for w in output_data:
        if w["label"] != "malicious":
            continue
        
        summ = w["summary"]
        is_strong_signal = False
        
        if w["attack_type"] == "port_scan_recon" and "port_scan_signature" in summ:
            is_strong_signal = True
        elif w["attack_type"] == "arp_spoof" and ("arp_conflict" in summ or "high_arp_reply_rate" in summ):
            is_strong_signal = True
        elif w["attack_type"] == "dhcp_poison" and ("DHCP types" in summ or "high_dhcp_discover_rate" in summ):
            is_strong_signal = True
        elif w["attack_type"] == "dns_spoof" and ("DNS queries" in summ and ("arp_conflict" in summ or "high_arp_reply_rate" in summ)):
            is_strong_signal = True
            
        if is_strong_signal:
            best_malicious[w["attack_type"]].append(w)

    # KotalarÄ± 4 saldÄ±rÄ± tipine bÃ¶l: 6, 6, 6, 7 = 25 adet toplam
    quotas = {
        "port_scan_recon": 6,
        "arp_spoof": 6,
        "dhcp_poison": 6,
        "dns_spoof": 7
    }
    
    selected_malicious = []
    for atype, quota in quotas.items():
        candidates = best_malicious.get(atype, [])
        random.shuffle(candidates)
        selected_malicious.extend(candidates[:quota])

    final_50 = selected_normals + selected_malicious
    random.shuffle(final_50) # KarÄ±ÅŸtÄ±rÄ±yoruz ki hepsi sÄ±rayla gelmesin

    with open(OUT_TXT, "w", encoding="utf-8") as f:
        f.write("="*60 + "\n")
        f.write("   YÃœKSEK KALÄ°TELÄ° 50 VERÄ° SETÄ° (SIFIR YANLIÅ POZÄ°TÄ°F)\n")
        f.write("="*60 + "\n\n")
        for i, w in enumerate(final_50, 1):
            f.write(f"[{i}/50] ID: {w['id']} | ETÄ°KET: {w['label'].upper()} | TÄ°P: {w['attack_type'] or 'YOK'}\n")
            f.write("-" * 60 + "\n")
            f.write(f"{w['summary']}\n")
            f.write("=" * 60 + "\n\n")

    print()
    print("=" * 60)
    print(f"TOPLAM PENCERE (Ana Veriseti): {len(selected)}")
    lc = Counter(w["label"] for w in selected)
    print(f"  normal:    {lc['normal']}")
    print(f"  malicious: {lc['malicious']}")
    print(f"\nÃ‡IKTILAR:")
    print(f"  JSON (DÃ¼zeltildi): {OUT_JSON}")
    print(f"  CSV:               {OUT_CSV}")
    print(f"  TXT (50 En Ä°yi):   {OUT_TXT}")
    print("=" * 60)

if __name__ == "__main__":
    main()
