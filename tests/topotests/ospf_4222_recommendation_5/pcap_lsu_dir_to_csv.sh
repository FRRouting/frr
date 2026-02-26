#!/usr/bin/env bash
# pcap_ospf_dir_to_csv.sh
# Usage: ./pcap_ospf_dir_to_csv.sh [DIR]
# Outputs: <basename>_ospf.csv per .pcap/.pcapng/.pcap*.gz (chronologically sorted)
# Final columns:
# label,time,frame,dscp,src,dst,ospf_hdr_cksum,adv_router,cksum,seqnum,lsa_len,age,lsa_type_name,lsa_id

set -euo pipefail

DIR="${1:-.}"
for tool in tshark gawk sort; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool not found in PATH" >&2; exit 1; }
done

# Detect a Router-ID field for Hello/DBD/LS-Req adv_router
RID_FIELD="$(tshark -G fields 2>/dev/null \
  | awk -F'\t' '/^(ospf\.router_id|ospf\.routerid|ospf\.srcrouter)\t/ {print $1; exit}')"
[[ -n "$RID_FIELD" ]] && echo "Using Router-ID field: $RID_FIELD" >&2 \
                      || echo "No Router-ID field; adv_router blank on Hello/DBD/LS-Req" >&2

shopt -s nullglob
mapfile -t PCAPS < <(find "$DIR" -maxdepth 1 -type f \
  \( -iname '*.pcap' -o -iname '*.pcapng' -o -iname '*.pcap.gz' -o -iname '*.pcapng.gz' \) \
  -printf '%p\n' | sort)

((${#PCAPS[@]})) || { echo "No pcap files found in: $DIR" >&2; exit 0; }

for pcap in "${PCAPS[@]}"; do
  # Base filename (keeps dots like R1.eth0.pcap.gz)
  base="$(basename -- "$pcap")"

  # Label: strip trailing .gz, then .pcapng or .pcap (keep inner dots)
  label="$base"
  [[ "$label" == *.gz ]] && label="${label%.gz}"
  case "$label" in
    *.pcapng) label="${label%.pcapng}" ;;
    *.pcap)   label="${label%.pcap}" ;;
  esac
  # Examples:
  #   R1.eth0.pcap        -> R1.eth0
  #   R1.eth0.pcap.gz     -> R1.eth0
  #   R1.eth0.pcapng      -> R1.eth0
  #   R1.eth0.pcapng.gz   -> R1.eth0

  # CSV path built from the label
  out="$(dirname -- "$pcap")/${label}.csv"

  echo "Writing: $out"

  {
    # NOTE: lsa_len is AFTER seqnum per your preference
    echo "label,time,frame,dscp,src,dst,ospf_hdr_cksum,adv_router,cksum,seqnum,lsa_len,age,lsa_type_name,lsa_id"

    {
      ################################################################
      # 1) Hello / DB-Desc / LS-Req (packet-level; lsa_len = ip.len)
      ################################################################
      if [[ -n "$RID_FIELD" ]]; then
        tshark -r "$pcap" -n \
          -Y 'ospf && (ospf.msg==1 || ospf.msg==2 || ospf.msg==3)' \
          -T fields \
          -e frame.time_epoch \
          -e frame.number \
          -e ip.dsfield.dscp \
          -e ip.src \
          -e ip.dst \
          -e ospf.checksum \
          -e "$RID_FIELD" \
          -e ip.len \
          -e ospf.msg \
          -E header=n -E separator=, -E quote=n \
        | gawk -F',' -v OFS=',' -v label="$label" '
            function typename(t){ return (t=="1")?"Hello":(t=="2")?"DB-Desc":(t=="3")?"LS-Req":"OSPF"; }
            {
              # epoch,label,frame,dscp,src,dst,ospf_hdr_cksum,adv_router,cksum,seqnum,lsa_len,age,lsa_type_name,lsa_id
              print $1, label, $2, $3, $4, $5, $6, $7, "", "", $8, "", typename($9), "";
            }'
      else
        tshark -r "$pcap" -n \
          -Y 'ospf && (ospf.msg==1 || ospf.msg==2 || ospf.msg==3)' \
          -T fields \
          -e frame.time_epoch \
          -e frame.number \
          -e ip.dsfield.dscp \
          -e ip.src \
          -e ip.dst \
          -e ospf.checksum \
          -e ip.len \
          -e ospf.msg \
          -E header=n -E separator=, -E quote=n \
        | gawk -F',' -v OFS=',' -v label="$label" '
            function typename(t){ return (t=="1")?"Hello":(t=="2")?"DB-Desc":(t=="3")?"LS-Req":"OSPF"; }
            {
              # epoch,label,frame,dscp,src,dst,ospf_hdr_cksum,adv_router,cksum,seqnum,lsa_len,age,lsa_type_name,lsa_id
              print $1, label, $2, $3, $4, $5, $6, "", "", "", $7, "", typename($8), "";
            }'
      fi

      ################################################################
      # 2) LSU (msg==4): explode to one row per LSA; lsa_len = ospf.lsa.length
      ################################################################
      tshark -r "$pcap" -n -Y 'ospf && ospf.msg==4' -T fields \
        -e frame.time_epoch \
        -e frame.number \
        -e ip.dsfield.dscp \
        -e ip.src \
        -e ip.dst \
        -e ospf.checksum \
        -e ospf.advrouter \
        -e ospf.lsa.chksum \
        -e ospf.lsa.seqnum \
        -e ospf.lsa.length \
        -e ospf.lsa.age \
        -e ospf.lsa \
        -e ospf.lsa.id \
        -E header=n -E separator=, -E quote=n -E occurrence=a -E aggregator=';' \
      | gawk -F',' -v OFS=',' -v label="$label" '
          function map_type_name(t){
            return (t=="1")?"Router-LSA" :
                   (t=="2")?"Network-LSA" :
                   (t=="3")?"Summary-LSA(Network)" :
                   (t=="4")?"Summary-LSA(ASBR)" :
                   (t=="5")?"AS-External-LSA" :
                   (t=="6")?"Group-Membership-LSA" :
                   (t=="7")?"NSSA-LSA" :
                   (t=="9")?"Opaque-LSA(Link)" :
                   (t=="10")?"Opaque-LSA(Area)" :
                   (t=="11")?"Opaque-LSA(AS)" :
                   (t==""?"":"Unknown(" t ")");
          }
          {
            # 1 epoch,2 frame,3 dscp,4 src,5 dst,6 ospf_hdr_cksum,
            # 7 adv(list),8 lsa.chksum(list),9 lsa.seqnum(list),10 lsa.length(list),
            # 11 lsa.age(list),12 lsa.type(list),13 lsa.id(list)
            n_adv = split($7, adv, /;/);   n_ck = split($8, cks, /;/);
            n_sq  = split($9, seqs, /;/);  n_len = split($10, lens, /;/);
            n_age = split($11, ages, /;/); n_ty  = split($12, types, /;/);
            n_id  = split($13, ids, /;/);

            n = n_adv; if (n_ck>n) n=n_ck; if (n_sq>n) n=n_sq; if (n_len>n) n=n_len;
            if (n_age>n) n=n_age; if (n_ty>n) n=n_ty; if (n_id>n) n=n_id;

            if (n==0) {
              # epoch,label,frame,dscp,src,dst,ospf_hdr_cksum,adv_router,cksum,seqnum,lsa_len,age,lsa_type_name,lsa_id
              print $1, label, $2, $3, $4, $5, $6, "", "", "", "", "", "LSU", "";
              next;
            }

            for (i=1; i<=n; i++){
              # epoch,label,frame,dscp,src,dst,ospf_hdr_cksum,adv_router,cksum,seqnum,lsa_len,age,lsa_type_name,lsa_id
              print $1, label, $2, $3, $4, $5, $6,
                    (i in adv ? adv[i] : ""),
                    (i in cks ? cks[i] : ""),
                    (i in seqs ? seqs[i] : ""),
                    (i in lens ? lens[i] : ""),
                    (i in ages ? ages[i] : ""),
                    map_type_name(i in types ? types[i] : ""),
                    (i in ids ? ids[i] : "");
            }
          }'

    ################################################################
    # 3) LSAck (msg==5): one row per ACK; lsa_len = ip.len; age IN tuple; age column blank
    ################################################################
    tshark -r "$pcap" -n -Y 'ospf && ospf.msg==5' -T fields \
      -e frame.time_epoch \
      -e frame.number \
      -e ip.dsfield.dscp \
      -e ip.src \
      -e ip.dst \
      -e ospf.checksum \
      -e ip.len \
      -e ospf.advrouter \
      -e ospf.lsa.chksum \
      -e ospf.lsa.seqnum \
      -e ospf.lsa.age \
      -E header=n -E separator=, -E quote=n -E occurrence=a -E aggregator=';' \
    | gawk -F',' -v OFS=',' -v label="$label" '
        # normalize hex checksums to 0xNNNN form (16-bit)
        function norm_cksum(s,   v) {
          if (s ~ /^0x[0-9A-Fa-f]+$/) {
            v = strtonum(s);
            return sprintf("0x%04x", and(v, 0xFFFF));
          }
          return s;
        }
    
        function tuples4(adv, ck, sq, ag,    a1,a2,a3,a4,n1,n2,n3,n4,n,i,out){
          n1=split(adv,a1,/;/); n2=split(ck,a2,/;/); n3=split(sq,a3,/;/); n4=split(ag,a4,/;/);
          n=n1; if(n2>n)n=n2; if(n3>n)n=n3; if(n4>n)n=n4;
          out="";
          for(i=1;i<=n;i++){
            if (i>1) out = out ";";
            # adv|ck|seq|age, with ck normalized
            out = out (i in a1?a1[i]:"") "|" norm_cksum(i in a2?a2[i]:"") "|" (i in a3?a3[i]:"") "|" (i in a4?a4[i]:"");
          }
          return out;
        }
        {
          # 1 epoch,2 frame,3 dscp,4 src,5 dst,6 ospf_hdr_cksum,7 ip.len,
          # 8 adv(list),9 lsa.cksum(list),10 lsa.seqnum(list),11 lsa.age(list)
          lsa_len = $7; sub(/;.*/, "", lsa_len);   # guard: scalar only
          # epoch,label,frame,dscp,src,dst,ospf_hdr_cksum,adv_router(blank),
          # cksum="----",seqnum="",lsa_len(ip.len),age(blank),LSA-Ack,
          # lsa_id=adv|ck|seq|age;...
          print $1, label, $2, $3, $4, $5, $6, "", "----", "", lsa_len, "",
                "LSA-Ack", tuples4($8,$9,$10,$11);
        }'
    } \
    | LC_ALL=C sort -t, -k1,1n \
    | gawk -F',' -v OFS=',' '
        function pad9(s,   n){
          n=length(s);
          return (n>=9) ? substr(s,1,9) : s sprintf("%0*d", 9-n, 0);
        }
        # Normalize hex checksums to 16-bit 0xNNNN form
        function norm_cksum(s,   v){
          if (s ~ /^0x[0-9A-Fa-f]+$/) {
            v = strtonum(s);
            # keep only lower 16 bits, format as 4 hex digits
            return sprintf("0x%04x", and(v, 0xFFFF));
          }
          return s;
        }
        {
          # Input: epoch,label,frame,dscp,src,dst,ospf_hdr_cksum,adv_router,cksum,seqnum,lsa_len,age,lsa_type_name,lsa_id
          # Normalize checksums so Rocky "0x00002683" -> "0x2683"
          $7 = norm_cksum($7);  # ospf_hdr_cksum
          $9 = norm_cksum($9);  # cksum

          # $1=epoch -> HH:MM:SS.nnnnnnnnn (local; use TZ=UTC for UTC)
          split($1,a,".");
          sec = (a[1]=="" ? 0 : a[1]+0);
          frac = (length(a)>1 ? a[2] : "0");
          frac = pad9(frac);
          t = strftime("%H:%M:%S", sec);
          $1 = t "." frac;

          # Reorder to final header:
          # label,time,frame,dscp,src,dst,ospf_hdr_cksum,adv_router,cksum,seqnum,lsa_len,age,lsa_type_name,lsa_id
          print $2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14;
        }'
  } > "$out"
done

echo "Done. Created *.csv for each pcap."

