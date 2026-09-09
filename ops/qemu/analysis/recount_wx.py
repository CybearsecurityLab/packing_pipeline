"""Independent write-then-execute recount over a paper_trace.jsonl.

A cross-check on the classifier, NOT a second oracle.  Three predicates are
reported together so the effect of each is separable:

  A) first_write < first_exec, page granular.  This was the original version and
     it is WRONG on its own: it cannot see X->W->X (execute a page, modify it,
     execute the modified bytes), which is the canonical decrypt-in-place shape.
     On upx_label2 it reported 1 page where B reports 2, one of them with 32
     distinct write->exec epochs.
  B) any execution after any write, page granular.  Sees X->W->X, but a 4 KB page
     that holds both code and data yields a false positive whenever a write lands
     on the data bytes and execution lands on the code bytes.
  C) byte granular: an executed byte range overlaps bytes previously written.
     This is the one to believe.  On alushpackerA_rep1 A and B both report 1 page
     and C reports 0; on armadilloB_rep3 A reports 8, B reports 12 and C reports 0
     across 38.4M events -- every page-level candidate was page-granularity noise.

Pass candidate pages (as hex physical page addresses) to limit the byte-level
pass, which is the expensive one.

What this CANNOT see, and so cannot be used to claim a true negative:
kernel writes made on the process's behalf (backend_validation.json records
kernel_write_observed=false and kernel_store_callbacks_registered=false, so they
are absent from the trace), remote writes (remote_write_proved=false), and
shared-alias writes (shared_alias_proved=false).  The backend is certified
single_process.  Note also that filtered_kernel_write_events in paper_trace.c is
declared and printed but never incremented, so its zero measures nothing.

Usage: recount_wx.py <trace.jsonl> [candidate_page_hex ...]
"""
import json,sys,collections
# candidates are given as full physical page ADDRESSES (0xe3fa0000) but are
# compared against page NUMBERS (addr>>12); converting here.  Getting this
# wrong silently empties written_bytes and makes predicate C always report 0.
CAND=set(int(x,16)>>12 for x in sys.argv[2:]) if len(sys.argv)>2 else None
first_w={}; first_x={}; last_w={}; seq=0
skipped=collections.Counter()
A=set(); B={}; epochs=collections.Counter()
written_bytes=collections.defaultdict(set)   # page -> set of written offsets
Cpages={}; Cdetail=collections.Counter()
for line in open(sys.argv[1]):
    try: e=json.loads(line)
    except ValueError: continue
    t=e.get("event")
    if t not in ("write","exec"): continue
    seq+=1
    if not e.get("physical_spans"):
        # No physical provenance: invisible to every predicate below.  Counted so
        # a "0" is always reported alongside how much of the trace it covers.
        skipped[t]+=1
        continue
    spans=e.get("physical_spans") or []
    if t=="write":
        for s in spans:
            a=s["address"]; n=s.get("size",0); p=a>>12
            first_w.setdefault(p,seq); last_w[p]=seq
            if CAND is None or p in CAND:
                off=a & 0xfff
                for i in range(off, min(off+n,4096)): written_bytes[p].add(i)
    elif t=="exec":
        for s in spans:
            a=s["address"]; n=s.get("size",0); p=a>>12
            first_x.setdefault(p,seq)
            if p in first_w and first_w[p] < first_x[p]: A.add(p)
            if p in last_w:
                B.setdefault(p,(last_w[p],seq)); epochs[p]+=1; del last_w[p]
            if CAND is None or p in CAND:
                off=a & 0xfff
                hit=[i for i in range(off,min(off+n,4096)) if i in written_bytes[p]]
                if hit:
                    Cpages.setdefault(p,(off,n,len(hit)))
                    Cdetail[p]+=1
nw_tot=skipped["write"]; nx_tot=skipped["exec"]
print(f"trace: {sys.argv[1].split('/')[-2]}  seq={seq}")
if nw_tot or nx_tot:
    print(f"  !! EXCLUDED for lack of physical provenance: {nw_tot} writes, {nx_tot} execs")
    print(f"     a 0 below means 'none among the events that HAD physical spans'")
print(f"  A) old predicate  (first_write<first_exec) : {len(A)} pages")
print(f"  B) corrected      (exec after write)       : {len(B)} pages")
print(f"  C) BYTE-level     (executed a written byte): {len(Cpages)} pages")
for p,(off,n,h) in Cpages.items():
    print(f"      phys 0x{p<<12:x} exec@off 0x{off:x} size {n}, {h} of those bytes were previously written; {Cdetail[p]} such execs")
