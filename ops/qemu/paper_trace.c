/*
 * Paper-faithful execution/write tracer for Deep Packer Inspection.
 *
 * This is an upstream-QEMU TCG plugin, not a DRAKVUF approximation.  It
 * observes executed translation blocks and every successful guest store.  A
 * Windows service in the guest supplies the packed child's PID and trace
 * boundaries with CPUID markers.  Windows process/thread attribution uses
 * offsets from the exact ntoskrnl PDB profile installed with this guest.
 *
 * The first milestone intentionally emits only the core execution and write
 * channels.  Metadata produced by the runner must keep paper_label_eligible
 * false until remote/shared/file/invalidation channel audits all pass.
 */

#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define PACKER_MARKER_MAGIC UINT32_C(0x5041434b)
#define MARK_ROOT_PID UINT32_C(1)
#define MARK_TRACE_START UINT32_C(2)
#define MARK_TRACE_STOP UINT32_C(3)
#define MARK_STATUS_QUERY UINT32_C(4)
#define MARK_STATUS_MAGIC UINT64_C(0x5153544154555350)

#define USER_LIMIT_32 UINT64_C(0x80000000)
#define USER_LIMIT_64 UINT64_C(0x0000800000000000)
#define IO_TYPE_FILE UINT16_C(5)
#define FILE_OBJECT_MIN_SIZE UINT16_C(0xd8)
#define PROTOTYPE_PTE_SIZE UINT64_C(8)

/* Exact offsets for ntkrnlmp profile GUID+age
 * 89284d0ca6acc8274b9a44bd5af9290b5.  build_profile_header.py verifies and
 * regenerates this block from /var/lib/drakrun/profiles/kernel.json. */
#include "win10_profile.h"

typedef struct {
    struct qemu_plugin_register *rax;
    struct qemu_plugin_register *rbx;
    struct qemu_plugin_register *rcx;
    struct qemu_plugin_register *rdx;
    struct qemu_plugin_register *rsp;
    struct qemu_plugin_register *r8;
    struct qemu_plugin_register *r9;
    struct qemu_plugin_register *cr3;
    struct qemu_plugin_register *fs_base;
    struct qemu_plugin_register *gs_base;
    struct qemu_plugin_register *k_gs_base;
    bool has_rax;
    bool has_rbx;
    bool has_rcx;
    bool has_rdx;
    bool has_rsp;
    bool has_r8;
    bool has_r9;
    bool has_cr3;
    bool has_fs_base;
    bool has_gs_base;
    bool has_k_gs_base;
} RegisterSet;

typedef struct {
    uint64_t ethread;
    uint64_t source_pid;
    uint64_t tid;
    uint64_t source_eprocess;
    uint64_t attached_pid;
    uint64_t attached_eprocess;
    uint64_t attached_asid;
} ThreadContext;

typedef struct {
    uint64_t pid;
    uint64_t tid;
    uint64_t eprocess;
    uint64_t last_application_pc;
} ThreadIdentity;

typedef struct {
    uint32_t offset;
    uint32_t size;
    uint64_t address;
} PhysicalSpan;

#define MAX_PHYSICAL_SPANS 4

typedef struct {
    uint64_t address;
    uint32_t size;
    uint32_t insns;
    uint32_t span_count;
    bool physical_complete;
    PhysicalSpan spans[MAX_PHYSICAL_SPANS];
} BlockInfo;

typedef struct {
    uint64_t pc;
} InstructionInfo;

typedef struct {
    uint64_t magic;
    uint64_t status_ready;
    uint64_t sample_started;
    uint64_t active_processes;
    uint64_t execution_events;
    uint64_t pending_exceptions;
    uint64_t oldest_exception_age_ms;
} MarkerStatus;

typedef struct {
    bool used;
    uint64_t return_address;
    uint64_t pid;
    uint64_t tid;
    uint64_t target_pid;
    uint64_t target_eprocess;
    uint64_t address;
    uint64_t size;
    GArray *physical_spans;
    const char *event;
} PendingInvalidation;

#define MAX_PENDING_INVALIDATIONS 4096

typedef struct {
    bool used;
    bool write;
    /* Allocation order, so an exhausted table can evict its OLDEST entry instead
     * of failing.  Entries are matched on completion by (pid, tid, return_address)
     * and freed there; a thread that never returns through that path -- killed,
     * exited, or unwound past it -- leaks its entry permanently.  Before eviction
     * existed the table filled monotonically with run length and every subsequent
     * file I/O counted as a failure, which disqualified long runs. */
    uint64_t alloc_seq;
    uint64_t return_address;
    uint64_t pid;
    uint64_t tid;
    uint64_t target_pid;
    uint64_t file_id;
    uint64_t file_offset;
    uint64_t buffer;
    uint64_t requested;
    uint64_t io_status_block;
} PendingFileIo;

#define MAX_PENDING_FILE_IO 4096

typedef struct {
    bool used;
    uint64_t return_address;
    uint64_t pid;
    uint64_t tid;
    uint64_t source_pc;
    uint64_t target_pid;
    uint64_t target_eprocess;
    uint64_t target_directory_table;
    uint64_t address;
    uint64_t requested;
    uint64_t completed_pointer;
} PendingVirtualWrite;

#define MAX_PENDING_VIRTUAL_WRITES 4096

typedef struct {
    uint64_t eprocess;
    uint64_t page;
} MappedPageKey;

typedef struct {
    int result;
    uint64_t file_id;
    uint64_t file_offset;
    bool system;
} MappedPageValue;

static RegisterSet registers_by_vcpu[64];
static ThreadContext block_context_by_vcpu[64];
static bool block_context_valid_by_vcpu[64];
/* Cached "does this vCPU's current thread belong to the root or a monitored
 * descendant" verdict, valid exactly while block_context_valid_by_vcpu is set.
 * A cached context is identical across consecutive user blocks (identity only
 * changes through a kernel transition, which invalidates the context), so the
 * monitored/root verdict computed on the refreshing block is final for the
 * whole run of cache hits.  This lets an unmonitored, non-root user block be
 * rejected before the global trace lock and descendant bookkeeping. */
static bool block_source_monitored_by_vcpu[64];
static bool block_source_is_root_by_vcpu[64];
static bool block_write_eligible_by_vcpu[64];
/* F1 throughput: cache the KPCR->CurrentThread guest read inside current_ethread,
 * keyed on the live (gs_base, k_gs_base) register pair.  The user-mode pair is
 * (TEB, KPCR) and the kernel-mode pair is (KPCR, TEB) -- swapped -- so the first
 * user block after ANY kernel block (hence after any thread switch, which must
 * run kernel code) always misses and re-reads the live ETHREAD; consecutive
 * user blocks of the same thread hit.  This removes the dominant per-block guest
 * memory read paid across the write->execute block-entry storm without changing
 * which ETHREAD is resolved.  Kernel-block invalidation is kept as defense. */
static uint64_t ethread_cache_gs_by_vcpu[64];
static uint64_t ethread_cache_kgs_by_vcpu[64];
static uint64_t ethread_cache_value_by_vcpu[64];
static bool ethread_cache_valid_by_vcpu[64];
static struct qemu_plugin_scoreboard *memory_trace_scoreboard;
static qemu_plugin_u64 memory_trace_enabled;
static struct qemu_plugin_mem_buffer *memory_event_buffer;
static FILE *trace_file;
static GMutex trace_lock;
static GHashTable *monitored_pids;
/* Diagnostic-only: dedup set so each distinct candidate process emits one
 * descendant_debug record (pid, parent, job vs root_job) at its first
 * enrollment attempt.  No behavior effect. */
static GHashTable *debugged_pids;
static GHashTable *mapped_page_cache;
static GHashTable *pending_exceptions;
static GHashTable *thread_identities;
static uint64_t sequence_number;
static uint64_t root_pid;
static uint64_t root_eprocess;
static uint64_t root_create_time;
static uint64_t root_job;
static uint64_t descendant_create_cutoff;
static uint64_t root_asid;
static uint64_t root_image_base;
static uint64_t root_image_size;
static uint64_t root_entry;
static bool root_entry_seen;
static bool sample_started;
static bool armed;
static bool active;
static bool saw_stop;
static uint64_t stop_detail;
static uint64_t exec_events;
static uint64_t write_events;
static uint64_t filtered_kernel_write_events;
static uint64_t context_failures;
static uint64_t kernel_base;
static uint64_t invalidation_events;
static uint64_t invalidation_failures;
static uint64_t unresolved_process_handles;
static uint64_t physical_mapping_failures;
/* Diagnostic-only (no gate effect): monitored exec blocks recorded with their
 * exact virtual identity but WITHOUT physical spans (one-shot/uncached TBs whose
 * physical could not be resolved at translate time; see block_exec). */
static uint64_t blocks_without_physical;
/* Diagnostic-only (no gate effect): successful stores recorded with their exact
 * virtual identity but WITHOUT physical spans (physical unresolvable at store
 * time; see memory_write).  Single-process layering uses the virtual write. */
static uint64_t writes_without_physical;
static uint64_t marker_candidate_hits;
static uint64_t marker_callback_hits;
static uint64_t marker_register_failures;
static uint64_t marker_query_failures;
static uint64_t marker_query_initializing;
static uint64_t marker_query_ready;
static uint64_t prestart_root_exec_events;
static uint64_t prestart_system_exec_events;
static uint64_t prestart_unmapped_exec_events;
static PendingInvalidation pending_invalidations[MAX_PENDING_INVALIDATIONS];
static PendingFileIo pending_file_io[MAX_PENDING_FILE_IO];
static PendingVirtualWrite pending_virtual_writes[MAX_PENDING_VIRTUAL_WRITES];
static uint64_t file_io_events;
static uint64_t file_io_failures;
static uint64_t file_io_evictions;
static uint64_t file_io_alloc_seq;
static uint64_t file_io_register_failures;
static uint64_t file_io_handle_failures;
static uint64_t file_io_disk_failures;
static uint64_t file_io_argument_failures;
static uint64_t file_io_status_failures;
static uint64_t asynchronous_file_io;
static uint64_t mapped_file_exec_events;
static uint64_t mapped_file_failures;
static uint64_t system_role_failures;
static uint64_t exception_dispatch_events;
static uint64_t exception_recovery_events;
static uint64_t process_snapshot_failures;
static uint64_t virtual_memory_write_events;
static uint64_t virtual_memory_write_failures;
static uint64_t tb_flush_requests;
static uint64_t block_context_misses;
static uint64_t block_context_refreshes;
static uint64_t block_context_cache_hits;
/* Diagnostic-only descendant-enrollment counters (no behavior effect): explain
 * why a spawned child does or does not enroll as a monitored job descendant. */
static uint64_t descendant_enroll_attempts;
static uint64_t descendant_read_failures;
static uint64_t descendant_job_mismatch;
static uint64_t descendant_createtime_reject;
static uint64_t descendant_enrolled;
static uint64_t descendant_parent_enrolled;
static bool descendant_by_parent;
static uint64_t unmonitored_block_rejects;
/* F5 diagnostic-only (no behavior effect): count user-mode #PF (14) and #NM (7)
 * discontinuities that occur while a monitored thread is current, and how many
 * are repeat faults at the same from_pc with no intervening progress.
 *
 * This was originally described as "the signature of a fault-on-entry loop at a
 * just-written (OEP) page".  MEASURED FALSE (2026-08-12): with pf_loop=on emitting
 * the addresses, yoda_protector 1.03.3 produced 15 loop sites over 26 repeats and
 * NONE of them coincided with a written byte or even a written page.  The repeats
 * are ordinary demand paging.  Do not re-chase this as an explanation for the
 * no-W->X residue -- see .superpowers/WX_VISIBILITY_FINDINGS.md sections 9-10. */
static uint64_t monitored_user_pagefaults;
static uint64_t monitored_user_pagefault_repeats;
static uint64_t monitored_user_pagefault_last_pc_by_vcpu[64];
/* Opt-in (`pf_loop=on`).  The counters above prove a fault-on-entry loop HAPPENED
 * but not WHERE, which is the one thing needed to correlate it with the earlier
 * writes: a byte written and then faulted-on at the same address is a W->X whose
 * execute half never lands.  Emitting every #PF would flood the trace with routine
 * demand paging (why the switch below drops vector 14/7), so emit only the REPEAT
 * case -- a second fault at the same from_pc with no intervening progress, which
 * demand paging does not produce -- and only ONCE per (pid, pc), which bounds the
 * volume to the number of distinct looping sites.  Diagnostic only: emits an event,
 * never changes exec/write accounting or the layer computation. */
static bool pagefault_loop_events;
static GHashTable *pagefault_loop_reported;
static uint64_t pagefault_loop_sites;

static bool process_monitored(uint64_t pid, uint64_t eprocess);
static bool user_address(uint64_t address);
static void monitor_pid(uint64_t pid, uint64_t eprocess, uint64_t parent,
                        const char *reason);
static void emit_process(uint64_t pid, uint64_t parent, const char *reason);

#define NTDLL_KIUSER_EXCEPTION_DISPATCHER_FILE_OFFSET UINT64_C(0xa02e0)
#define NTDLL_RTL_RAISE_EXCEPTION_FILE_OFFSET UINT64_C(0x50470)
#define NTDLL_SHA256                                                          \
    "fdb2689bffabe7d2e300882ca1c3fc2fe24a998ffcbd5f48795c7d95712d1e98"

static const uint8_t ki_user_exception_dispatcher_signature[] = {
    0xfc, 0x48, 0x8b, 0x05, 0x48, 0x03, 0x0e, 0x00,
    0x48, 0x85, 0xc0, 0x74, 0x0f, 0x48, 0x8b, 0xcc,
};

static const uint8_t rtl_raise_exception_signature[] = {
    0x40, 0x55, 0x57, 0x41, 0x56, 0x48, 0x81, 0xec,
    0x60, 0x01, 0x00, 0x00, 0x48, 0x8d, 0x6c, 0x24,
};

static void marker_candidate_exec(unsigned int vcpu_index, void *userdata)
{
    (void)vcpu_index;
    (void)userdata;
    g_mutex_lock(&trace_lock);
    marker_candidate_hits++;
    g_mutex_unlock(&trace_lock);
}

static bool add_physical_byte(PhysicalSpan *spans, uint32_t *count,
                              uint32_t offset, uint64_t address)
{
    PhysicalSpan *last;

    if (address == UINT64_MAX) {
        return false;
    }
    if (*count) {
        last = &spans[*count - 1];
        if (last->offset + last->size == offset &&
            last->address + last->size == address) {
            last->size++;
            return true;
        }
    }
    if (*count >= MAX_PHYSICAL_SPANS) {
        return false;
    }
    spans[*count] = (PhysicalSpan){
        .offset = offset,
        .size = 1,
        .address = address,
    };
    (*count)++;
    return true;
}

static void emit_physical_spans(const PhysicalSpan *spans, uint32_t count)
{
    fputs(",\"physical_spans\":[", trace_file);
    for (uint32_t index = 0; index < count; index++) {
        fprintf(trace_file,
                "%s{\"offset\":%u,\"size\":%u,\"address\":%" PRIu64 "}",
                index ? "," : "", spans[index].offset, spans[index].size,
                spans[index].address);
    }
    fputc(']', trace_file);
}

static void emit_physical_span_array(const GArray *spans,
                                     const char *field_name)
{
    fprintf(trace_file, ",\"%s\":[", field_name);
    for (guint index = 0; index < spans->len; index++) {
        const PhysicalSpan *span = &g_array_index(spans, PhysicalSpan, index);
        fprintf(trace_file,
                "%s{\"offset\":%u,\"size\":%u,\"address\":%" PRIu64 "}",
                index ? "," : "", span->offset, span->size, span->address);
    }
    fputc(']', trace_file);
}

static bool add_physical_range(GArray *spans, uint64_t offset, uint64_t size,
                               uint64_t address)
{
    PhysicalSpan span;

    if (!size || offset > UINT32_MAX || size > UINT32_MAX ||
        offset + size > (uint64_t)UINT32_MAX + 1 ||
        address + size < address) {
        return false;
    }
    if (spans->len) {
        PhysicalSpan *last =
            &g_array_index(spans, PhysicalSpan, spans->len - 1);
        if ((uint64_t)last->offset + last->size == offset &&
            last->address + last->size == address &&
            (uint64_t)last->size + size <= UINT32_MAX) {
            last->size += (uint32_t)size;
            return true;
        }
    }
    span = (PhysicalSpan){
        .offset = (uint32_t)offset,
        .size = (uint32_t)size,
        .address = address,
    };
    g_array_append_val(spans, span);
    return true;
}

static bool canonical_kernel_pointer(uint64_t value)
{
    return value >= UINT64_C(0xffff800000000000);
}

static uint64_t read_register_value(struct qemu_plugin_register *handle,
                                    bool *ok)
{
    g_autoptr(GByteArray) bytes = g_byte_array_new();
    uint64_t value = 0;

    /* Register zero is represented by a NULL-valued opaque handle. */
    if (!qemu_plugin_read_register(handle, bytes) ||
        bytes->len == 0 || bytes->len > sizeof(value)) {
        *ok = false;
        return 0;
    }
    memcpy(&value, bytes->data, bytes->len);
    *ok = true;
    return value;
}

static bool read_memory(uint64_t address, void *destination, size_t size)
{
    g_autoptr(GByteArray) bytes = g_byte_array_new();

    if (!qemu_plugin_read_memory_vaddr(address, bytes, size) ||
        bytes->len != size) {
        return false;
    }
    memcpy(destination, bytes->data, size);
    return true;
}

static bool read_u8(uint64_t address, uint8_t *value)
{
    return read_memory(address, value, sizeof(*value));
}

static bool read_u16(uint64_t address, uint16_t *value)
{
    return read_memory(address, value, sizeof(*value));
}

static bool read_u32(uint64_t address, uint32_t *value)
{
    return read_memory(address, value, sizeof(*value));
}

static bool read_u64(uint64_t address, uint64_t *value)
{
    return read_memory(address, value, sizeof(*value));
}

static bool current_ethread(unsigned int vcpu_index, uint64_t *ethread)
{
    RegisterSet *regs;
    uint64_t candidates[2];
    uint64_t kpcr;
    bool ok;

    if (vcpu_index >= G_N_ELEMENTS(registers_by_vcpu)) {
        return false;
    }
    regs = &registers_by_vcpu[vcpu_index];
    candidates[0] = regs->has_gs_base
                        ? read_register_value(regs->gs_base, &ok)
                        : 0;
    if (!regs->has_gs_base) {
        ok = false;
    }
    if (!ok) {
        candidates[0] = 0;
    }
    candidates[1] = regs->has_k_gs_base
                        ? read_register_value(regs->k_gs_base, &ok)
                        : 0;
    if (!regs->has_k_gs_base) {
        ok = false;
    }
    if (!ok) {
        candidates[1] = 0;
    }

    /* F1: reuse the last resolved ETHREAD when the (gs_base, k_gs_base) pair is
     * unchanged on this vCPU (same thread on the same CPU => same ETHREAD),
     * skipping the KPCR->CurrentThread guest read.  Populated only on a
     * successful resolution below, so a bogus (0,0) pair never matches. */
    if (vcpu_index < G_N_ELEMENTS(ethread_cache_valid_by_vcpu) &&
        ethread_cache_valid_by_vcpu[vcpu_index] &&
        ethread_cache_gs_by_vcpu[vcpu_index] == candidates[0] &&
        ethread_cache_kgs_by_vcpu[vcpu_index] == candidates[1]) {
        *ethread = ethread_cache_value_by_vcpu[vcpu_index];
        return true;
    }

    for (size_t index = 0; index < G_N_ELEMENTS(candidates); index++) {
        kpcr = candidates[index];
        if (!canonical_kernel_pointer(kpcr) ||
            !read_u64(kpcr + KPCR_PRCB + KPRCB_CURRENT_THREAD, ethread)) {
            continue;
        }
        if (canonical_kernel_pointer(*ethread)) {
            if (vcpu_index < G_N_ELEMENTS(ethread_cache_valid_by_vcpu)) {
                ethread_cache_gs_by_vcpu[vcpu_index] = candidates[0];
                ethread_cache_kgs_by_vcpu[vcpu_index] = candidates[1];
                ethread_cache_value_by_vcpu[vcpu_index] = *ethread;
                ethread_cache_valid_by_vcpu[vcpu_index] = true;
            }
            return true;
        }
        *ethread = 0;
    }
    return false;
}

/* Resolve the process a thread is currently ATTACHED to.  Unlike the thread's
 * owning process, this changes at runtime via KeStackAttachProcess, so it must
 * be re-read on every context resolution even when the thread is unchanged. */
static bool resolve_attached_process(ThreadContext *context)
{
    if (!read_u64(context->ethread + KTHREAD_APC_STATE + KAPC_STATE_PROCESS,
                  &context->attached_eprocess) ||
        !canonical_kernel_pointer(context->attached_eprocess) ||
        !read_u64(context->attached_eprocess + EPROCESS_PID,
                  &context->attached_pid)) {
        return false;
    }
    if (!read_u64(context->attached_eprocess + KPROCESS_USER_DIRECTORY_TABLE,
                  &context->attached_asid) || !context->attached_asid) {
        if (!read_u64(context->attached_eprocess + KPROCESS_DIRECTORY_TABLE,
                      &context->attached_asid)) {
            return false;
        }
    }
    context->attached_asid &= ~UINT64_C(0xfff);
    return true;
}

static bool current_context(unsigned int vcpu_index, ThreadContext *context)
{
    uint64_t source_eprocess_pid;

    if (!current_ethread(vcpu_index, &context->ethread) ||
        !read_u64(context->ethread + ETHREAD_CID + CLIENT_ID_PID,
                  &context->source_pid) ||
        !read_u64(context->ethread + ETHREAD_CID + CLIENT_ID_TID,
                  &context->tid) ||
        !read_u64(context->ethread + KTHREAD_PROCESS,
                  &context->source_eprocess) ||
        !canonical_kernel_pointer(context->source_eprocess) ||
        !read_u64(context->source_eprocess + EPROCESS_PID,
                  &source_eprocess_pid) ||
        source_eprocess_pid != context->source_pid) {
        return false;
    }
    return resolve_attached_process(context);
}

/* Per-vCPU cache of a thread's IMMUTABLE identity (owning process/PID/TID keyed
 * by ETHREAD).  A refresh after a kernel block is usually the same thread
 * (syscall/interrupt return), so this skips the owning-process reads and only
 * re-reads the mutable attached process.  Re-verifying the PID guards against
 * ETHREAD-object reuse: a stale entry whose PID no longer matches falls through
 * to the full walk. */
typedef struct {
    uint64_t ethread;
    uint64_t source_pid;
    uint64_t tid;
    uint64_t source_eprocess;
    bool valid;
} ThreadImmutable;
static ThreadImmutable thread_immutable_by_vcpu[64];
static uint64_t context_immutable_reuse;
/* Bounds eager kernel-base discovery so a persistently-unresolvable scan cannot
 * run on every kernel block indefinitely. */
static uint64_t eager_kernel_discovery_attempts;
static uint64_t discover_calls;
static uint64_t discover_reads_ok;
static bool root_debug_emitted;

static bool cached_current_context(unsigned int vcpu_index,
                                   ThreadContext *context)
{
    uint64_t ethread;
    uint64_t verify_pid;

    if (!current_ethread(vcpu_index, &ethread)) {
        return false;
    }
    if (vcpu_index < G_N_ELEMENTS(thread_immutable_by_vcpu)) {
        ThreadImmutable *imm = &thread_immutable_by_vcpu[vcpu_index];
        if (imm->valid && imm->ethread == ethread &&
            read_u64(ethread + ETHREAD_CID + CLIENT_ID_PID, &verify_pid) &&
            verify_pid == imm->source_pid) {
            context->ethread = ethread;
            context->source_pid = imm->source_pid;
            context->tid = imm->tid;
            context->source_eprocess = imm->source_eprocess;
            if (!resolve_attached_process(context)) {
                return false;
            }
            context_immutable_reuse++;
            return true;
        }
    }
    if (!current_context(vcpu_index, context)) {
        return false;
    }
    if (vcpu_index < G_N_ELEMENTS(thread_immutable_by_vcpu)) {
        ThreadImmutable *imm = &thread_immutable_by_vcpu[vcpu_index];
        imm->ethread = context->ethread;
        imm->source_pid = context->source_pid;
        imm->tid = context->tid;
        imm->source_eprocess = context->source_eprocess;
        imm->valid = true;
    }
    return true;
}

static void cache_thread_identity(const ThreadContext *context)
{
    gpointer key = (gpointer)(uintptr_t)context->ethread;
    ThreadIdentity *identity = g_hash_table_lookup(thread_identities, key);

    if (!identity) {
        identity = g_new0(ThreadIdentity, 1);
        g_hash_table_insert(thread_identities, key, identity);
    }
    identity->pid = context->source_pid;
    identity->tid = context->tid;
    identity->eprocess = context->source_eprocess;
}

static void cache_application_pc(const ThreadContext *context, uint64_t pc)
{
    ThreadIdentity *identity = g_hash_table_lookup(
        thread_identities, (gpointer)(uintptr_t)context->ethread);

    if (identity) {
        identity->last_application_pc = pc;
    }
}

static uint64_t cached_application_pc(const ThreadContext *context)
{
    ThreadIdentity *identity = g_hash_table_lookup(
        thread_identities, (gpointer)(uintptr_t)context->ethread);

    return identity ? identity->last_application_pc : 0;
}

static bool current_asid(unsigned int vcpu_index, uint64_t *asid)
{
    RegisterSet *regs;
    bool ok;

    if (vcpu_index >= G_N_ELEMENTS(registers_by_vcpu)) {
        return false;
    }
    regs = &registers_by_vcpu[vcpu_index];
    if (!regs->has_cr3) {
        return false;
    }
    *asid = read_register_value(regs->cr3, &ok) & ~UINT64_C(0xfff);
    return ok && *asid;
}

static bool valid_eprocess(uint64_t eprocess, uint64_t *pid)
{
    uint64_t link;

    return canonical_kernel_pointer(eprocess) &&
           read_u64(eprocess + EPROCESS_PID, pid) && *pid <= G_MAXUINT &&
           read_u64(eprocess + EPROCESS_ACTIVE_LINKS, &link) &&
           canonical_kernel_pointer(link);
}

static bool resolve_handle_object(const ThreadContext *context,
                                  uint64_t handle, uint64_t *object)
{
    uint64_t table;
    uint64_t code;
    uint64_t base;
    uint64_t entry;
    uint64_t pointer;
    uint64_t leaf;
    uint64_t middle;
    uint64_t value = handle & UINT64_C(0xfffffffffffffffc);
    unsigned int level;

    if ((uint32_t)handle == UINT32_C(0xffffffff) ||
        (uint32_t)handle == UINT32_C(0xfffffffe)) {
        return false;
    }
    if (!read_u64(context->source_eprocess + EPROCESS_OBJECT_TABLE, &table) ||
        !canonical_kernel_pointer(table) ||
        !read_u64(table + HANDLE_TABLE_CODE, &code)) {
        return false;
    }
    level = (unsigned int)(code & 3);
    base = code & ~UINT64_C(3);
    if (level == 0) {
        entry = base + value * 4;
    } else if (level == 1) {
        if (!read_u64(base + ((value >> 10) * 8), &leaf) ||
            !canonical_kernel_pointer(leaf)) {
            return false;
        }
        entry = leaf + ((value & 0x3ff) * 4);
    } else if (level == 2) {
        if (!read_u64(base + ((value >> 19) * 8), &middle) ||
            !canonical_kernel_pointer(middle) ||
            !read_u64(middle + (((value >> 10) & 0x1ff) * 8), &leaf) ||
            !canonical_kernel_pointer(leaf)) {
            return false;
        }
        entry = leaf + ((value & 0x3ff) * 4);
    } else {
        return false;
    }
    if (!read_u64(entry, &pointer) || !pointer) {
        return false;
    }
    /* Windows 10 stores bits 4..47 of the object header in bits 20..63. */
    pointer = (pointer >> 16) | UINT64_C(0xffff000000000000);
    *object = pointer + OBJECT_HEADER_BODY;
    return canonical_kernel_pointer(*object);
}

static bool resolve_process_handle(const ThreadContext *context,
                                   uint64_t handle, uint64_t *eprocess,
                                   uint64_t *pid)
{
    if ((uint32_t)handle == UINT32_C(0xffffffff)) {
        *eprocess = context->attached_eprocess;
        *pid = context->attached_pid;
        return true;
    }
    return resolve_handle_object(context, handle, eprocess) &&
           valid_eprocess(*eprocess, pid);
}

static bool vad_find(uint64_t eprocess, uint64_t address, uint64_t *vad,
                     uint64_t *base, uint64_t *size)
{
    uint64_t node;
    uint64_t start_vpn;
    uint64_t end_vpn;
    uint32_t low;
    uint8_t high;
    uint64_t vpn = address >> 12;

    if (!read_u64(eprocess + EPROCESS_VAD_ROOT + AVL_TREE_ROOT, &node)) {
        return false;
    }
    for (unsigned int iteration = 0; iteration < 65536; iteration++) {
        if (!node) {
            return false;
        }
        if (!canonical_kernel_pointer(node) ||
            !read_u32(node + VAD_START, &low) ||
            !read_u8(node + VAD_START_HIGH, &high)) {
            return false;
        }
        start_vpn = low | ((uint64_t)high << 32);
        if (!read_u32(node + VAD_END, &low) ||
            !read_u8(node + VAD_END_HIGH, &high)) {
            return false;
        }
        end_vpn = low | ((uint64_t)high << 32);
        if (vpn < start_vpn) {
            if (!read_u64(node + VAD_LEFT, &node)) {
                return false;
            }
        } else if (vpn > end_vpn) {
            if (!read_u64(node + VAD_RIGHT, &node)) {
                return false;
            }
        } else {
            if (vad) {
                *vad = node;
            }
            *base = start_vpn << 12;
            *size = (end_vpn - start_vpn + 1) << 12;
            return true;
        }
    }
    return false;
}

static bool vad_range(uint64_t eprocess, uint64_t address, uint64_t *base,
                      uint64_t *size)
{
    return vad_find(eprocess, address, NULL, base, size);
}

static bool file_object_id(uint64_t file_object, uint64_t *file_id)
{
    uint16_t type;
    uint16_t size;

    file_object &= ~UINT64_C(0xf);
    return canonical_kernel_pointer(file_object) &&
           read_u16(file_object + FILE_OBJECT_TYPE, &type) &&
           type == IO_TYPE_FILE &&
           read_u16(file_object + FILE_OBJECT_SIZE, &size) &&
           size >= FILE_OBJECT_MIN_SIZE &&
           read_u64(file_object + FILE_OBJECT_FS_CONTEXT, file_id) &&
           canonical_kernel_pointer(*file_id);
}

typedef enum {
    DISK_FILE_NONE,
    DISK_FILE_FOUND,
    DISK_FILE_ERROR,
} DiskFileResult;

static DiskFileResult disk_file_object_id(uint64_t file_object,
                                          uint64_t *file_id)
{
    uint16_t type;
    uint16_t size;
    uint64_t section_pointer;

    file_object &= ~UINT64_C(0xf);
    if (!canonical_kernel_pointer(file_object) ||
        !read_u16(file_object + FILE_OBJECT_TYPE, &type) ||
        type != IO_TYPE_FILE ||
        !read_u16(file_object + FILE_OBJECT_SIZE, &size) ||
        size < FILE_OBJECT_MIN_SIZE ||
        !read_u64(file_object + FILE_OBJECT_SECTION_POINTER,
                  &section_pointer)) {
        return DISK_FILE_ERROR;
    }
    if (!section_pointer) {
        return DISK_FILE_NONE;
    }
    if (!canonical_kernel_pointer(section_pointer) ||
        !read_u64(file_object + FILE_OBJECT_FS_CONTEXT, file_id) ||
        !canonical_kernel_pointer(*file_id)) {
        return DISK_FILE_ERROR;
    }
    return DISK_FILE_FOUND;
}

static bool file_object_path(uint64_t file_object, GString *path)
{
    uint64_t chain[32];
    size_t count = 0;

    file_object &= ~UINT64_C(0xf);
    while (file_object && count < G_N_ELEMENTS(chain)) {
        uint64_t related;
        chain[count++] = file_object;
        if (!read_u64(file_object + FILE_OBJECT_RELATED, &related)) {
            return false;
        }
        related &= ~UINT64_C(0xf);
        if (related == file_object) {
            return false;
        }
        file_object = related;
    }
    if (file_object) {
        return false;
    }
    while (count) {
        uint16_t length;
        uint64_t buffer;
        g_autofree uint16_t *characters = NULL;
        uint64_t object = chain[--count];

        if (!read_u16(object + FILE_OBJECT_NAME + UNICODE_STRING_LENGTH,
                      &length) ||
            length > 4096 || (length & 1) ||
            !read_u64(object + FILE_OBJECT_NAME + UNICODE_STRING_BUFFER,
                      &buffer)) {
            return false;
        }
        if (!length) {
            continue;
        }
        if (!buffer) {
            return false;
        }
        characters = g_malloc(length);
        if (!read_memory(buffer, characters, length)) {
            return false;
        }
        if (path->len && path->str[path->len - 1] != '\\' &&
            characters[0] != '\\' && characters[0] != '/') {
            g_string_append_c(path, '\\');
        }
        for (size_t index = 0; index < length / 2; index++) {
            uint16_t character = characters[index];
            if (character == '/') {
                character = '\\';
            }
            if (character < 0x80) {
                g_string_append_c(path,
                                  g_ascii_tolower((gchar)character));
            } else {
                g_string_append_c(path, '?');
            }
        }
    }
    return path->len > 0;
}

static bool file_object_system_role(uint64_t file_object, bool *system)
{
    g_autoptr(GString) path = g_string_new(NULL);
    static const char *const system_directories[] = {
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\windows\\winsxs\\",
        "\\windows\\systemapps\\",
    };

    if (!file_object_path(file_object, path)) {
        return false;
    }
    *system = false;
    for (size_t index = 0; index < G_N_ELEMENTS(system_directories); index++) {
        if (strstr(path->str, system_directories[index])) {
            *system = true;
            break;
        }
    }
    return true;
}

typedef enum {
    MAPPED_FILE_NONE,
    MAPPED_FILE_FOUND,
    MAPPED_FILE_ERROR,
} MappedFileResult;

static MappedFileResult mapped_file_location(uint64_t eprocess,
                                             uint64_t address,
                                             uint64_t *file_id,
                                             uint64_t *file_offset,
                                             uint64_t *file_object_out)
{
    uint64_t vad;
    uint64_t vad_base;
    uint64_t vad_size;
    uint64_t file_object;
    uint64_t subsection;
    uint64_t control_area;
    uint64_t prototype;
    uint64_t subsection_base;
    uint64_t next;
    uint32_t ptes;
    uint32_t sector;
    uint32_t vad_flags;

    if (!vad_find(eprocess, address, &vad, &vad_base, &vad_size)) {
        return MAPPED_FILE_ERROR;
    }
    if (!read_u32(vad + VAD_FLAGS, &vad_flags)) {
        return MAPPED_FILE_ERROR;
    }
    if (vad_flags & UINT32_C(1 << 20)) {
        return MAPPED_FILE_NONE;
    }
    if (!read_u64(vad + MMVAD_FILE_OBJECT, &file_object)) {
        return MAPPED_FILE_ERROR;
    }
    if (!file_object) {
        if (!read_u64(vad + MMVAD_SUBSECTION, &subsection)) {
            return MAPPED_FILE_ERROR;
        }
        if (!subsection) {
            return MAPPED_FILE_NONE;
        }
        if (!read_u64(subsection + SUBSECTION_CONTROL_AREA, &control_area) ||
            !canonical_kernel_pointer(control_area) ||
            !read_u64(control_area + CONTROL_AREA_FILE_POINTER,
                      &file_object)) {
            return MAPPED_FILE_ERROR;
        }
    }
    if (!file_object) {
        return MAPPED_FILE_NONE;
    }
    file_object &= ~UINT64_C(0xf);
    if (!file_object_id(file_object, file_id) ||
        !read_u64(vad + MMVAD_FIRST_PROTOTYPE_PTE, &prototype) ||
        !canonical_kernel_pointer(prototype) ||
        !read_u64(vad + MMVAD_SUBSECTION, &subsection) ||
        !canonical_kernel_pointer(subsection)) {
        return MAPPED_FILE_ERROR;
    }
    prototype += ((address - vad_base) >> 12) * PROTOTYPE_PTE_SIZE;
    for (unsigned int iteration = 0; iteration < 65536; iteration++) {
        if (!read_u64(subsection + SUBSECTION_BASE, &subsection_base) ||
            !canonical_kernel_pointer(subsection_base) ||
            !read_u32(subsection + SUBSECTION_PTES, &ptes) || !ptes ||
            !read_u32(subsection + SUBSECTION_STARTING_SECTOR, &sector)) {
            return MAPPED_FILE_ERROR;
        }
        if (prototype >= subsection_base &&
            prototype < subsection_base + (uint64_t)ptes * PROTOTYPE_PTE_SIZE) {
            *file_offset = (uint64_t)sector * UINT64_C(512) +
                           ((prototype - subsection_base) /
                            PROTOTYPE_PTE_SIZE) * UINT64_C(4096) +
                           (address & UINT64_C(0xfff));
            *file_object_out = file_object;
            return MAPPED_FILE_FOUND;
        }
        if (!read_u64(subsection + SUBSECTION_NEXT, &next)) {
            return MAPPED_FILE_ERROR;
        }
        if (!next) {
            return MAPPED_FILE_ERROR;
        }
        if (!canonical_kernel_pointer(next)) {
            return MAPPED_FILE_ERROR;
        }
        subsection = next;
    }
    return MAPPED_FILE_ERROR;
}

static guint mapped_page_hash(gconstpointer pointer)
{
    const MappedPageKey *key = pointer;
    uint64_t mixed = key->eprocess ^ (key->page * UINT64_C(0x9e3779b97f4a7c15));
    return (guint)(mixed ^ (mixed >> 32));
}

static gboolean mapped_page_equal(gconstpointer left, gconstpointer right)
{
    const MappedPageKey *a = left;
    const MappedPageKey *b = right;
    return a->eprocess == b->eprocess && a->page == b->page;
}

static MappedFileResult cached_mapped_file_location(uint64_t eprocess,
                                                    uint64_t address,
                                                    uint64_t *file_id,
                                                    uint64_t *file_offset,
                                                    bool *system)
{
    MappedPageKey lookup = {
        .eprocess = eprocess,
        .page = address >> 12,
    };
    MappedPageValue *cached = g_hash_table_lookup(mapped_page_cache, &lookup);
    MappedFileResult result;
    uint64_t page_offset = 0;
    uint64_t file_object = 0;

    if (cached) {
        if (cached->result == MAPPED_FILE_FOUND) {
            *file_id = cached->file_id;
            *file_offset = cached->file_offset + (address & UINT64_C(0xfff));
            *system = cached->system;
        }
        return (MappedFileResult)cached->result;
    }
    result = mapped_file_location(eprocess, address & ~UINT64_C(0xfff),
                                  file_id, &page_offset, &file_object);
    MappedPageKey *stored_key = g_new(MappedPageKey, 1);
    MappedPageValue *stored_value = g_new0(MappedPageValue, 1);
    *stored_key = lookup;
    stored_value->result = result;
    if (result == MAPPED_FILE_FOUND) {
        if (!file_object_system_role(file_object, system)) {
            system_role_failures++;
            result = MAPPED_FILE_ERROR;
            stored_value->result = result;
            g_hash_table_insert(mapped_page_cache, stored_key, stored_value);
            return result;
        }
        stored_value->file_id = *file_id;
        stored_value->file_offset = page_offset;
        stored_value->system = *system;
        *file_offset = page_offset + (address & UINT64_C(0xfff));
    }
    g_hash_table_insert(mapped_page_cache, stored_key, stored_value);
    return result;
}

static void invalidate_mapped_page_cache(uint64_t eprocess, uint64_t address,
                                         uint64_t size)
{
    GHashTableIter iterator;
    gpointer key_pointer;
    uint64_t first = address >> 12;
    uint64_t last = size ? (address + size - 1) >> 12 : first;

    g_hash_table_iter_init(&iterator, mapped_page_cache);
    while (g_hash_table_iter_next(&iterator, &key_pointer, NULL)) {
        const MappedPageKey *key = key_pointer;
        if (key->eprocess == eprocess && key->page >= first &&
            key->page <= last) {
            g_hash_table_iter_remove(&iterator);
        }
    }
}

static bool discover_kernel_base(uint64_t pc)
{
    uint64_t candidate = pc & ~UINT64_C(0x1fffff);
    uint16_t dos_magic;
    uint32_t pe_offset;
    uint32_t signature;
    uint32_t image_size;
    uint64_t minimum_size =
        MAX(MAX(NT_FREE_VIRTUAL_MEMORY_RVA, NT_UNMAP_VIEW_RVA),
            MAX(MAX(NT_UNMAP_VIEW_EX_RVA, NT_WRITE_FILE_RVA),
                MAX(NT_READ_FILE_RVA, NT_WRITE_VIRTUAL_MEMORY_RVA))) +
        UINT64_C(0x1000);

    /* Scan backward for the ntoskrnl PE header.  Kernel PCs (drivers, HAL,
     * scheduler, syscall stubs) sit ABOVE ntoskrnl's base, so scanning down
     * reaches it — but the distance varies, and a range that happened to be
     * enough on one boot (256 MiB) left kernel_base=0 on a faster guest that
     * sampled a more distant kernel PC first.  Use 1 GiB (512 * 2 MiB): more
     * robust than 256 MiB, but bounded so a persistently-unresolved scan cannot
     * crawl the guest with thousands of reads per kernel block.  The loop stops
     * at the first ntoskrnl-sized PE header. */
    discover_calls++;
    for (unsigned int index = 0; index < 512 && canonical_kernel_pointer(candidate);
         index++, candidate -= UINT64_C(0x200000)) {
        if (!read_u16(candidate, &dos_magic)) {
            continue;
        }
        discover_reads_ok++;
        if (dos_magic != UINT16_C(0x5a4d) ||
            !read_u32(candidate + 0x3c, &pe_offset) || pe_offset > 0x1000 ||
            !read_u32(candidate + pe_offset, &signature) ||
            signature != UINT32_C(0x00004550) ||
            !read_u32(candidate + pe_offset + 0x18 + 0x38, &image_size) ||
            image_size < minimum_size) {
            continue;
        }
        kernel_base = candidate;
        return true;
    }
    return false;
}

/* Deterministic, KPTI-independent kernel-base discovery from a known EPROCESS.
 * Backward-scanning from a kernel PC fails on a KPTI guest because syscall entry
 * PCs land in the KVA-shadow trampoline, not contiguous with ntoskrnl.  Instead
 * walk the ActiveProcessLinks list (which the plugin can read from any resolved
 * EPROCESS without kernel_base): PsActiveProcessHead is a global INSIDE ntoskrnl
 * threaded into that circular list, so the list entry E for which
 * (E - PS_ACTIVE_PROCESS_HEAD_RVA) is a page-aligned ntoskrnl PE header IS the
 * head, and kernel_base = E - PS_ACTIVE_PROCESS_HEAD_RVA exactly.  No scanning,
 * no lucky code sample. */
static bool discover_kernel_base_from_eprocess(uint64_t eprocess)
{
    uint64_t link;
    uint64_t minimum_size =
        MAX(MAX(NT_FREE_VIRTUAL_MEMORY_RVA, NT_UNMAP_VIEW_RVA),
            MAX(MAX(NT_UNMAP_VIEW_EX_RVA, NT_WRITE_FILE_RVA),
                MAX(NT_READ_FILE_RVA, NT_WRITE_VIRTUAL_MEMORY_RVA))) +
        UINT64_C(0x1000);

    if (!canonical_kernel_pointer(eprocess) ||
        !read_u64(eprocess + EPROCESS_ACTIVE_LINKS, &link)) {
        return false;
    }
    for (unsigned int index = 0;
         index < 65536 && canonical_kernel_pointer(link); index++) {
        uint64_t base = link - PS_ACTIVE_PROCESS_HEAD_RVA;
        uint16_t dos_magic;
        uint32_t pe_offset;
        uint32_t signature;
        uint32_t image_size;

        if (base < link && (base & UINT64_C(0xfff)) == 0 &&
            canonical_kernel_pointer(base) &&
            read_u16(base, &dos_magic) && dos_magic == UINT16_C(0x5a4d) &&
            read_u32(base + 0x3c, &pe_offset) && pe_offset <= 0x1000 &&
            read_u32(base + pe_offset, &signature) &&
            signature == UINT32_C(0x00004550) &&
            read_u32(base + pe_offset + 0x18 + 0x38, &image_size) &&
            image_size >= minimum_size) {
            kernel_base = base;
            return true;
        }
        if (!read_u64(link, &link)) {
            return false;
        }
    }
    return false;
}

static PendingInvalidation *allocate_invalidation(void)
{
    for (size_t index = 0; index < G_N_ELEMENTS(pending_invalidations); index++) {
        if (!pending_invalidations[index].used) {
            pending_invalidations[index].used = true;
            return &pending_invalidations[index];
        }
    }
    return NULL;
}

typedef enum {
    PAGE_TRANSLATION_ERROR = -1,
    PAGE_NOT_PRESENT = 0,
    PAGE_TRANSLATION_OK = 1,
} PageTranslationResult;

static bool read_physical_u64(uint64_t address, uint64_t *value)
{
    g_autoptr(GByteArray) bytes = g_byte_array_new();

    if (qemu_plugin_read_memory_hwaddr(address, bytes, sizeof(*value)) !=
            QEMU_PLUGIN_HWADDR_OPERATION_OK ||
        bytes->len != sizeof(*value)) {
        return false;
    }
    memcpy(value, bytes->data, sizeof(*value));
    return true;
}

static PageTranslationResult translate_x64_page(uint64_t directory_table,
                                                 uint64_t address,
                                                 uint64_t *physical)
{
    static const unsigned int shifts[] = {39, 30, 21, 12};
    uint64_t table = directory_table & UINT64_C(0x000ffffffffff000);
    uint64_t entry;

    for (size_t level = 0; level < G_N_ELEMENTS(shifts); level++) {
        uint64_t index = (address >> shifts[level]) & UINT64_C(0x1ff);
        if (!read_physical_u64(table + index * 8, &entry)) {
            return PAGE_TRANSLATION_ERROR;
        }
        if (!(entry & 1)) {
            return PAGE_NOT_PRESENT;
        }
        if (level == 1 && (entry & UINT64_C(0x80))) {
            *physical = (entry & UINT64_C(0x000fffffc0000000)) |
                        (address & UINT64_C(0x3fffffff));
            return PAGE_TRANSLATION_OK;
        }
        if (level == 2 && (entry & UINT64_C(0x80))) {
            *physical = (entry & UINT64_C(0x000fffffffe00000)) |
                        (address & UINT64_C(0x1fffff));
            return PAGE_TRANSLATION_OK;
        }
        table = entry & UINT64_C(0x000ffffffffff000);
    }
    *physical = table | (address & UINT64_C(0xfff));
    return PAGE_TRANSLATION_OK;
}

static bool capture_range_physical_spans(uint64_t address, uint64_t size,
                                         uint64_t directory_table,
                                         bool allow_holes, GArray **spans)
{
    uint64_t end;

    if (!size || size > UINT32_MAX || address + size < address) {
        return false;
    }
    end = address + size;
    *spans = g_array_new(false, false, sizeof(PhysicalSpan));
    for (uint64_t cursor = address; cursor < end;) {
        uint64_t next_page = (cursor | UINT64_C(0xfff)) + 1;
        uint64_t chunk_end = MIN(end, next_page);
        uint64_t physical;
        uint64_t ram_address;
        PageTranslationResult result =
            translate_x64_page(directory_table, cursor, &physical);
        if (result == PAGE_TRANSLATION_ERROR) {
            return false;
        }
        if (result == PAGE_NOT_PRESENT && !allow_holes) {
            return false;
        }
        if (result == PAGE_TRANSLATION_OK) {
            ram_address = qemu_plugin_phys_addr_ram_addr(physical);
            if (ram_address == UINT64_MAX ||
                !add_physical_range(*spans, cursor - address,
                                    chunk_end - cursor, ram_address)) {
                return false;
            }
        }
        cursor = chunk_end;
    }
    return true;
}

static bool capture_invalidation_physical_spans(PendingInvalidation *pending,
                                                uint64_t directory_table)
{
    return capture_range_physical_spans(
        pending->address, pending->size, directory_table, true,
        &pending->physical_spans);
}

static void invalidation_entry(unsigned int vcpu_index, uint64_t pc,
                               const ThreadContext *context)
{
    RegisterSet *regs = &registers_by_vcpu[vcpu_index];
    PendingInvalidation *pending;
    uint64_t process_handle;
    uint64_t target_eprocess;
    uint64_t target_pid;
    uint64_t address;
    uint64_t size;
    uint64_t pointer;
    uint64_t rsp;
    uint64_t directory_table;
    bool ok;
    const char *event;

    if (pc != kernel_base + NT_FREE_VIRTUAL_MEMORY_RVA &&
        pc != kernel_base + NT_UNMAP_VIEW_RVA &&
        pc != kernel_base + NT_UNMAP_VIEW_EX_RVA) {
        return;
    }
    if (!regs->has_rcx || !regs->has_rdx || !regs->has_rsp ||
        (pc == kernel_base + NT_FREE_VIRTUAL_MEMORY_RVA && !regs->has_r8)) {
        invalidation_failures++;
        return;
    }
    process_handle = read_register_value(regs->rcx, &ok);
    if (!ok || !resolve_process_handle(context, process_handle,
                                       &target_eprocess, &target_pid)) {
        unresolved_process_handles++;
        return;
    }
    pointer = read_register_value(regs->rdx, &ok);
    if (!ok) {
        invalidation_failures++;
        return;
    }
    if (pc == kernel_base + NT_FREE_VIRTUAL_MEMORY_RVA) {
        if (!read_u64(pointer, &address)) {
            invalidation_failures++;
            return;
        }
        pointer = read_register_value(regs->r8, &ok);
        if (!ok || !read_u64(pointer, &size)) {
            invalidation_failures++;
            return;
        }
        event = "free";
    } else {
        address = pointer;
        size = 0;
        event = "unmap";
    }
    if (!size && !vad_range(target_eprocess, address, &address, &size)) {
        invalidation_failures++;
        return;
    }
    if ((!read_u64(target_eprocess + KPROCESS_USER_DIRECTORY_TABLE,
                   &directory_table) || !directory_table) &&
        !read_u64(target_eprocess + KPROCESS_DIRECTORY_TABLE,
                  &directory_table)) {
        invalidation_failures++;
        return;
    }
    rsp = read_register_value(regs->rsp, &ok);
    if (!ok || !read_u64(rsp, &pointer)) {
        invalidation_failures++;
        return;
    }
    pending = allocate_invalidation();
    if (!pending) {
        invalidation_failures++;
        return;
    }
    *pending = (PendingInvalidation){
        .used = true,
        .return_address = pointer,
        .pid = context->source_pid,
        .tid = context->tid,
        .target_pid = target_pid,
        .target_eprocess = target_eprocess,
        .address = address,
        .size = size,
        .event = event,
    };
    if (!capture_invalidation_physical_spans(pending, directory_table)) {
        invalidation_failures++;
        if (pending->physical_spans) {
            g_array_free(pending->physical_spans, true);
        }
        pending->used = false;
        return;
    }
}

static void invalidation_return(unsigned int vcpu_index, uint64_t pc,
                                const ThreadContext *context)
{
    RegisterSet *regs = &registers_by_vcpu[vcpu_index];
    bool ok;
    uint32_t status;

    for (size_t index = 0; index < G_N_ELEMENTS(pending_invalidations); index++) {
        PendingInvalidation *pending = &pending_invalidations[index];
        if (!pending->used || pending->pid != context->source_pid ||
            pending->tid != context->tid ||
            pending->return_address != pc) {
            continue;
        }
        status = regs->has_rax
                     ? (uint32_t)read_register_value(regs->rax, &ok)
                     : 0;
        if (!regs->has_rax) {
            ok = false;
        }
        if (!ok) {
            invalidation_failures++;
        } else if (status < UINT32_C(0x80000000)) {
            fprintf(trace_file,
                    "{\"event\":\"%s\",\"seq\":%" PRIu64
                    ",\"pid\":%" PRIu64 ",\"tid\":%" PRIu64
                    ",\"target_pid\":%" PRIu64 ",\"address\":%" PRIu64
                    ",\"size\":%" PRIu64,
                    pending->event, ++sequence_number, pending->pid,
                    pending->tid, pending->target_pid, pending->address,
                    pending->size);
            emit_physical_span_array(pending->physical_spans,
                                     "invalidated_physical_spans");
            fputs("}\n", trace_file);
            invalidation_events++;
            invalidate_mapped_page_cache(pending->target_eprocess,
                                         pending->address, pending->size);
        }
        g_array_free(pending->physical_spans, true);
        pending->physical_spans = NULL;
        pending->used = false;
        return;
    }
}

static PendingFileIo *allocate_file_io(void)
{
    size_t oldest = 0;
    uint64_t oldest_seq = UINT64_MAX;

    for (size_t index = 0; index < G_N_ELEMENTS(pending_file_io); index++) {
        if (!pending_file_io[index].used) {
            pending_file_io[index].used = true;
            pending_file_io[index].alloc_seq = ++file_io_alloc_seq;
            return &pending_file_io[index];
        }
        if (pending_file_io[index].alloc_seq < oldest_seq) {
            oldest_seq = pending_file_io[index].alloc_seq;
            oldest = index;
        }
    }
    /* Table full: every entry belongs to a call we never saw return.  Reclaim the
     * oldest rather than dropping this observation.  Losing the stalest pending
     * completion is strictly better than losing every subsequent file I/O, and it
     * is counted separately so it can never be mistaken for a channel failure. */
    file_io_evictions++;
    pending_file_io[oldest].used = true;
    pending_file_io[oldest].alloc_seq = ++file_io_alloc_seq;
    return &pending_file_io[oldest];
}

static bool capture_file_offset(uint64_t file_object, uint64_t pointer,
                                uint64_t *offset)
{
    uint64_t value;

    if (pointer) {
        if (!read_u64(pointer, &value)) {
            return false;
        }
        if (value == UINT64_MAX) {
            /* FILE_WRITE_TO_END_OF_FILE requires querying end-of-file state. */
            return false;
        }
        if (value != UINT64_MAX - 1) {
            if (value > INT64_MAX) {
                return false;
            }
            *offset = value;
            return true;
        }
    }
    return read_u64(file_object + FILE_OBJECT_CURRENT_OFFSET, offset) &&
           *offset <= INT64_MAX;
}

static void file_io_entry(unsigned int vcpu_index, uint64_t pc,
                          const ThreadContext *context)
{
    RegisterSet *regs = &registers_by_vcpu[vcpu_index];
    PendingFileIo *pending;
    uint64_t handle;
    uint64_t file_object;
    uint64_t file_id;
    uint64_t rsp;
    uint64_t return_address;
    uint64_t io_status_block;
    uint64_t buffer;
    uint64_t length;
    uint64_t byte_offset;
    uint64_t offset;
    bool ok;
    DiskFileResult disk_result;

    if (pc != kernel_base + NT_WRITE_FILE_RVA &&
        pc != kernel_base + NT_READ_FILE_RVA) {
        return;
    }
    if (!regs->has_rcx || !regs->has_rsp) {
        file_io_register_failures++;
        file_io_failures++;
        return;
    }
    handle = read_register_value(regs->rcx, &ok);
    if (!ok || !resolve_handle_object(context, handle, &file_object)) {
        file_io_handle_failures++;
        file_io_failures++;
        return;
    }
    disk_result = disk_file_object_id(file_object, &file_id);
    if (disk_result == DISK_FILE_NONE) {
        return;
    }
    if (disk_result == DISK_FILE_ERROR) {
        file_io_disk_failures++;
        file_io_failures++;
        return;
    }
    rsp = read_register_value(regs->rsp, &ok);
    if (!ok || !read_u64(rsp, &return_address) ||
        !read_u64(rsp + UINT64_C(0x28), &io_status_block) ||
        !read_u64(rsp + UINT64_C(0x30), &buffer) ||
        !read_u64(rsp + UINT64_C(0x38), &length) ||
        !read_u64(rsp + UINT64_C(0x40), &byte_offset) ||
        !canonical_kernel_pointer(return_address) || !io_status_block ||
        !buffer || !length || length > UINT32_MAX ||
        !capture_file_offset(file_object, byte_offset, &offset)) {
        file_io_argument_failures++;
        file_io_failures++;
        return;
    }
    pending = allocate_file_io();
    if (!pending) {
        /* Unreachable: allocate_file_io() now evicts rather than returning NULL.
         * Kept so a future change cannot silently reintroduce a null deref. */
        file_io_failures++;
        return;
    }
    *pending = (PendingFileIo){
        .used = true,
        .write = pc == kernel_base + NT_WRITE_FILE_RVA,
        .return_address = return_address,
        .pid = context->source_pid,
        .tid = context->tid,
        .target_pid = context->attached_pid,
        .file_id = file_id,
        .file_offset = offset,
        .buffer = buffer,
        .requested = length,
        .io_status_block = io_status_block,
    };
}

static void file_io_return(unsigned int vcpu_index, uint64_t pc,
                           const ThreadContext *context)
{
    RegisterSet *regs = &registers_by_vcpu[vcpu_index];
    uint32_t status;
    uint64_t completed;
    bool ok;

    for (size_t index = 0; index < G_N_ELEMENTS(pending_file_io); index++) {
        PendingFileIo *pending = &pending_file_io[index];
        if (!pending->used || pending->pid != context->source_pid ||
            pending->tid != context->tid ||
            pending->return_address != pc) {
            continue;
        }
        status = regs->has_rax
                     ? (uint32_t)read_register_value(regs->rax, &ok)
                     : 0;
        if (!regs->has_rax) {
            ok = false;
        }
        if (!ok) {
            file_io_register_failures++;
            file_io_failures++;
        } else if (status == UINT32_C(0x103)) {
            /* STATUS_PENDING: exact completion requires a later IRP hook. */
            asynchronous_file_io++;
        } else if (status < UINT32_C(0x80000000)) {
            if (!read_u64(pending->io_status_block + IO_STATUS_INFORMATION,
                          &completed) ||
                completed > pending->requested) {
                file_io_status_failures++;
                file_io_failures++;
            } else if (completed) {
                fprintf(trace_file,
                        "{\"event\":\"file_%s\",\"seq\":%" PRIu64
                        ",\"pid\":%" PRIu64 ",\"tid\":%" PRIu64
                        ",\"target_pid\":%" PRIu64
                        ",\"file_id\":%" PRIu64
                        ",\"file_offset\":%" PRIu64
                        ",\"size\":%" PRIu64,
                        pending->write ? "write" : "read",
                        ++sequence_number, pending->pid, pending->tid,
                        pending->target_pid, pending->file_id,
                        pending->file_offset, completed);
                if (!pending->write) {
                    fprintf(trace_file, ",\"address\":%" PRIu64,
                            pending->buffer);
                }
                fputs("}\n", trace_file);
                file_io_events++;
            }
        }
        pending->used = false;
        return;
    }
}

static PendingVirtualWrite *allocate_virtual_write(void)
{
    for (size_t index = 0; index < G_N_ELEMENTS(pending_virtual_writes);
         index++) {
        if (!pending_virtual_writes[index].used) {
            pending_virtual_writes[index].used = true;
            return &pending_virtual_writes[index];
        }
    }
    return NULL;
}

static void virtual_write_entry(unsigned int vcpu_index, uint64_t pc,
                                const ThreadContext *context)
{
    RegisterSet *regs = &registers_by_vcpu[vcpu_index];
    PendingVirtualWrite *pending;
    uint64_t process_handle;
    uint64_t target_eprocess;
    uint64_t target_pid;
    uint64_t directory_table;
    uint64_t address;
    uint64_t requested;
    uint64_t rsp;
    uint64_t return_address;
    uint64_t completed_pointer;
    uint64_t source_pc;
    bool ok;

    if (pc != kernel_base + NT_WRITE_VIRTUAL_MEMORY_RVA) {
        return;
    }
    if (!regs->has_rcx || !regs->has_rdx || !regs->has_r8 ||
        !regs->has_r9 || !regs->has_rsp) {
        virtual_memory_write_failures++;
        return;
    }
    process_handle = read_register_value(regs->rcx, &ok);
    if (!ok || !resolve_process_handle(context, process_handle,
                                       &target_eprocess, &target_pid)) {
        unresolved_process_handles++;
        return;
    }
    address = read_register_value(regs->rdx, &ok);
    if (!ok || !user_address(address)) {
        virtual_memory_write_failures++;
        return;
    }
    (void)read_register_value(regs->r8, &ok);
    if (!ok) {
        virtual_memory_write_failures++;
        return;
    }
    requested = read_register_value(regs->r9, &ok);
    rsp = read_register_value(regs->rsp, &ok);
    if (!ok || !requested || requested > UINT32_MAX ||
        address + requested < address || !read_u64(rsp, &return_address) ||
        !read_u64(rsp + UINT64_C(0x28), &completed_pointer) ||
        !canonical_kernel_pointer(return_address)) {
        virtual_memory_write_failures++;
        return;
    }
    if ((!read_u64(target_eprocess + KPROCESS_USER_DIRECTORY_TABLE,
                   &directory_table) || !directory_table) &&
        !read_u64(target_eprocess + KPROCESS_DIRECTORY_TABLE,
                  &directory_table)) {
        virtual_memory_write_failures++;
        return;
    }
    source_pc = cached_application_pc(context);
    if (!source_pc) {
        virtual_memory_write_failures++;
        return;
    }
    pending = allocate_virtual_write();
    if (!pending) {
        virtual_memory_write_failures++;
        return;
    }
    *pending = (PendingVirtualWrite){
        .used = true,
        .return_address = return_address,
        .pid = context->source_pid,
        .tid = context->tid,
        .source_pc = source_pc,
        .target_pid = target_pid,
        .target_eprocess = target_eprocess,
        .target_directory_table = directory_table,
        .address = address,
        .requested = requested,
        .completed_pointer = completed_pointer,
    };
}

static void virtual_write_return(unsigned int vcpu_index, uint64_t pc,
                                 const ThreadContext *context)
{
    RegisterSet *regs = &registers_by_vcpu[vcpu_index];
    uint32_t status;
    bool ok;

    for (size_t index = 0; index < G_N_ELEMENTS(pending_virtual_writes);
         index++) {
        PendingVirtualWrite *pending = &pending_virtual_writes[index];
        uint64_t completed;
        GArray *spans = NULL;

        if (!pending->used || pending->pid != context->source_pid ||
            pending->tid != context->tid || pending->return_address != pc) {
            continue;
        }
        status = regs->has_rax
                     ? (uint32_t)read_register_value(regs->rax, &ok)
                     : 0;
        if (!regs->has_rax) {
            ok = false;
        }
        if (!ok) {
            virtual_memory_write_failures++;
        } else if (status < UINT32_C(0x80000000)) {
            if (pending->completed_pointer) {
                if (!read_u64(pending->completed_pointer, &completed) ||
                    completed > pending->requested) {
                    virtual_memory_write_failures++;
                    pending->used = false;
                    return;
                }
            } else {
                completed = pending->requested;
            }
            if (completed &&
                !capture_range_physical_spans(
                    pending->address, completed,
                    pending->target_directory_table, false, &spans)) {
                virtual_memory_write_failures++;
            } else if (completed) {
                if (pending->target_pid != pending->pid) {
                    bool already_monitored = process_monitored(
                        pending->target_pid, pending->target_eprocess);
                    monitor_pid(pending->target_pid,
                                pending->target_eprocess, pending->pid,
                                "remote_write_target");
                    if (already_monitored) {
                        emit_process(pending->target_pid, pending->pid,
                                     "remote_write_target");
                    }
                }
                fprintf(trace_file,
                        "{\"event\":\"write\",\"seq\":%" PRIu64
                        ",\"vcpu\":%u,\"pid\":%" PRIu64
                        ",\"tid\":%" PRIu64
                        ",\"target_pid\":%" PRIu64
                        ",\"address\":%" PRIu64
                        ",\"size\":%" PRIu64 ",\"pc\":%" PRIu64,
                        ++sequence_number, vcpu_index, pending->pid,
                        pending->tid, pending->target_pid,
                        pending->address, completed, pending->source_pc);
                emit_physical_span_array(spans, "physical_spans");
                fputs("}\n", trace_file);
                write_events++;
                virtual_memory_write_events++;
            }
        }
        if (spans) {
            g_array_free(spans, true);
        }
        pending->used = false;
        return;
    }
}

static void kernel_event(unsigned int vcpu_index, uint64_t pc,
                         const ThreadContext *context)
{
    if (!kernel_base && !discover_kernel_base(pc)) {
        return;
    }
    if (!sample_started) {
        return;
    }
    invalidation_entry(vcpu_index, pc, context);
    invalidation_return(vcpu_index, pc, context);
    file_io_entry(vcpu_index, pc, context);
    file_io_return(vcpu_index, pc, context);
    virtual_write_entry(vcpu_index, pc, context);
    virtual_write_return(vcpu_index, pc, context);
}

static bool kernel_pc_relevant(uint64_t pc)
{
    static const uint64_t entry_rvas[] = {
        NT_FREE_VIRTUAL_MEMORY_RVA,
        NT_UNMAP_VIEW_RVA,
        NT_UNMAP_VIEW_EX_RVA,
        NT_WRITE_FILE_RVA,
        NT_READ_FILE_RVA,
        NT_WRITE_VIRTUAL_MEMORY_RVA,
    };

    if (!kernel_base) {
        return true;
    }
    for (size_t index = 0; index < G_N_ELEMENTS(entry_rvas); index++) {
        if (pc == kernel_base + entry_rvas[index]) {
            return true;
        }
    }
    for (size_t index = 0; index < G_N_ELEMENTS(pending_invalidations);
         index++) {
        if (pending_invalidations[index].used &&
            pending_invalidations[index].return_address == pc) {
            return true;
        }
    }
    for (size_t index = 0; index < G_N_ELEMENTS(pending_file_io); index++) {
        if (pending_file_io[index].used &&
            pending_file_io[index].return_address == pc) {
            return true;
        }
    }
    for (size_t index = 0; index < G_N_ELEMENTS(pending_virtual_writes);
         index++) {
        if (pending_virtual_writes[index].used &&
            pending_virtual_writes[index].return_address == pc) {
            return true;
        }
    }
    return false;
}

static bool pid_monitored(uint64_t pid)
{
    return g_hash_table_contains(monitored_pids, GUINT_TO_POINTER((guint)pid));
}

static bool process_monitored(uint64_t pid, uint64_t eprocess)
{
    gpointer key = GUINT_TO_POINTER((guint)pid);
    gpointer stored;

    if (!pid_monitored(pid)) {
        return false;
    }
    stored = g_hash_table_lookup(monitored_pids, key);
    return !stored || !eprocess || (uint64_t)(uintptr_t)stored == eprocess;
}

static void emit_process(uint64_t pid, uint64_t parent, const char *reason)
{
    fprintf(trace_file,
            "{\"event\":\"process\",\"seq\":%" PRIu64
            ",\"pid\":%" PRIu64 ",\"parent_pid\":%" PRIu64
            ",\"reason\":\"%s\"}\n",
            ++sequence_number, pid, parent, reason);
}

static void monitor_pid(uint64_t pid, uint64_t eprocess, uint64_t parent,
                        const char *reason)
{
    gpointer key;

    if (!pid || pid > G_MAXUINT) {
        return;
    }
    key = GUINT_TO_POINTER((guint)pid);
    if (pid_monitored(pid)) {
        gpointer stored = g_hash_table_lookup(monitored_pids, key);
        if (eprocess && (!stored || (uint64_t)(uintptr_t)stored != eprocess)) {
            g_hash_table_insert(monitored_pids, key,
                                (gpointer)(uintptr_t)eprocess);
            if (stored) {
                emit_process(pid, parent, reason);
            }
        }
        return;
    }
    g_hash_table_insert(monitored_pids, key, (gpointer)(uintptr_t)eprocess);
    emit_process(pid, parent, reason);
}

static uint64_t process_parent(uint64_t eprocess)
{
    uint64_t parent = 0;
    if (!read_u64(eprocess + EPROCESS_PARENT_PID, &parent)) {
        return 0;
    }
    return parent;
}

static void update_monitored_descendant(const ThreadContext *context)
{
    uint64_t create_time;
    uint64_t job;
    uint64_t parent;

    if (context->source_pid == root_pid) {
        monitor_pid(root_pid, context->source_eprocess, 0, "root_marker");
        if (!root_eprocess) {
            if (!read_u64(context->source_eprocess + EPROCESS_CREATE_TIME,
                          &create_time) ||
                !read_u64(context->source_eprocess + EPROCESS_JOB, &job) ||
                !create_time || !canonical_kernel_pointer(job)) {
                return;
            }
            root_eprocess = context->source_eprocess;
            root_create_time = create_time;
            root_job = job;
        }
        return;
    }

    if (process_monitored(context->source_pid, context->source_eprocess) ||
        !sample_started || !root_eprocess || !descendant_create_cutoff) {
        return;
    }
    /* Same predicate as before, split only so a diagnostic counter attributes
     * every non-enrollment to its exact cause.  Behavior is unchanged. */
    descendant_enroll_attempts++;
    if (!read_u64(context->source_eprocess + EPROCESS_CREATE_TIME,
                  &create_time) ||
        !read_u64(context->source_eprocess + EPROCESS_JOB, &job)) {
        descendant_read_failures++;
        return;
    }
    /* Diagnostic: one record per distinct candidate process, capturing exactly
     * why it does or does not qualify as a job descendant of the root.  This
     * reveals whether a real child of the root (parent == root_pid) ever runs
     * and whether its job matches root_job. */
    if (!g_hash_table_contains(debugged_pids,
                               GUINT_TO_POINTER((guint)context->source_pid))) {
        g_hash_table_add(debugged_pids,
                         GUINT_TO_POINTER((guint)context->source_pid));
        fprintf(trace_file,
                "{\"event\":\"descendant_debug\",\"seq\":%" PRIu64
                ",\"pid\":%" PRIu64 ",\"parent_pid\":%" PRIu64
                ",\"job\":%" PRIu64 ",\"root_job\":%" PRIu64
                ",\"create_time\":%" PRIu64 ",\"cutoff\":%" PRIu64
                ",\"job_matches\":%s,\"after_cutoff\":%s}\n",
                ++sequence_number, context->source_pid,
                process_parent(context->source_eprocess), job, root_job,
                create_time, descendant_create_cutoff,
                job == root_job ? "true" : "false",
                create_time > descendant_create_cutoff ? "true" : "false");
    }
    /* Default: a descendant must share the root's job object.  That is the
     * conservative rule -- it keeps unrelated system processes out of the trace.
     * Armadillo and telock defeat it: 100% of enrollment attempts (223458 and
     * 96917 respectively) were rejected here with zero enrolled, so their child
     * processes were never traced and the classifier saw layers==1 / no unpacking
     * even though millions of writes were occurring.  `descendant=parent` enrolls
     * on parent-PID descendancy from the root instead, which follows a debugger
     * pair that deliberately breaks the job relationship. */
    if (job != root_job) {
        if (!descendant_by_parent ||
            process_parent(context->source_eprocess) != root_pid) {
            descendant_job_mismatch++;
            return;
        }
        descendant_parent_enrolled++;
    }
    if (create_time <= descendant_create_cutoff) {
        descendant_createtime_reject++;
        return;
    }

    parent = process_parent(context->source_eprocess);
    monitor_pid(context->source_pid, context->source_eprocess, parent,
                "job_descendant");
    descendant_enrolled++;
}

static bool count_active_monitored_processes(uint64_t *count,
                                             GHashTable *active_pids)
{
    uint64_t head;
    uint64_t link;

    *count = 0;
    if (!kernel_base) {
        return false;
    }
    head = kernel_base + PS_ACTIVE_PROCESS_HEAD_RVA;
    if (!read_u64(head, &link)) {
        return false;
    }
    for (unsigned int iteration = 0; link != head; iteration++) {
        uint64_t eprocess;
        uint64_t pid;
        gpointer stored;

        if (iteration >= 65536 || !canonical_kernel_pointer(link) ||
            link < EPROCESS_ACTIVE_LINKS) {
            return false;
        }
        eprocess = link - EPROCESS_ACTIVE_LINKS;
        if (!read_u64(eprocess + EPROCESS_PID, &pid) || pid > G_MAXUINT) {
            return false;
        }
        if (pid_monitored(pid)) {
            stored = g_hash_table_lookup(monitored_pids,
                                         GUINT_TO_POINTER((guint)pid));
            if (!stored || (uint64_t)(uintptr_t)stored == eprocess) {
                (*count)++;
                g_hash_table_add(active_pids,
                                 GUINT_TO_POINTER((guint)pid));
                if (!stored) {
                    g_hash_table_insert(monitored_pids,
                                        GUINT_TO_POINTER((guint)pid),
                                        (gpointer)(uintptr_t)eprocess);
                }
            }
        }
        if (!read_u64(link, &link)) {
            return false;
        }
    }
    return true;
}

static bool snapshot_latest_process_create_time(uint64_t *latest)
{
    uint64_t head;
    uint64_t link;

    *latest = 0;
    if (!kernel_base) {
        return false;
    }
    head = kernel_base + PS_ACTIVE_PROCESS_HEAD_RVA;
    if (!read_u64(head, &link)) {
        return false;
    }
    for (unsigned int iteration = 0; link != head; iteration++) {
        uint64_t create_time;
        uint64_t eprocess;

        if (iteration >= 65536 || !canonical_kernel_pointer(link) ||
            link < EPROCESS_ACTIVE_LINKS) {
            return false;
        }
        eprocess = link - EPROCESS_ACTIVE_LINKS;
        if (!read_u64(eprocess + EPROCESS_CREATE_TIME, &create_time) ||
            !read_u64(link, &link)) {
            return false;
        }
        *latest = MAX(*latest, create_time);
    }
    return *latest != 0;
}

static gpointer exception_thread_key(uint64_t pid, uint64_t tid)
{
    return (gpointer)(uintptr_t)(((pid & UINT64_C(0xffffffff)) << 32) |
                                 (tid & UINT64_C(0xffffffff)));
}

static void mark_exception_dispatch(uint64_t pid, uint64_t tid,
                                    uint64_t address, const char *source,
                                    int exception_index)
{
    gpointer key = exception_thread_key(pid, tid);
    gint64 *started = g_hash_table_lookup(pending_exceptions, key);

    exception_dispatch_events++;
    if (!started) {
        started = g_new(gint64, 1);
        *started = g_get_monotonic_time();
        g_hash_table_insert(pending_exceptions, key, started);
    }
    fprintf(trace_file,
            "{\"event\":\"exception_dispatch\",\"seq\":%" PRIu64
            ",\"pid\":%" PRIu64 ",\"tid\":%" PRIu64
            ",\"address\":%" PRIu64 ",\"source\":\"%s\"",
            ++sequence_number, pid, tid, address, source);
    if (exception_index >= 0) {
        fprintf(trace_file, ",\"exception_index\":%d", exception_index);
    }
    fputs("}\n", trace_file);
}

static void mark_exception_recovery(uint64_t pid, uint64_t tid,
                                    uint64_t address)
{
    gpointer key = exception_thread_key(pid, tid);

    if (!g_hash_table_remove(pending_exceptions, key)) {
        return;
    }
    exception_recovery_events++;
    fprintf(trace_file,
            "{\"event\":\"exception_recovered\",\"seq\":%" PRIu64
            ",\"pid\":%" PRIu64 ",\"tid\":%" PRIu64
            ",\"address\":%" PRIu64 "}\n",
            ++sequence_number, pid, tid, address);
}

static void pending_exception_status(GHashTable *active_pids,
                                     MarkerStatus *status)
{
    GHashTableIter iterator;
    gpointer key;
    gpointer value;
    gint64 now = g_get_monotonic_time();

    g_hash_table_iter_init(&iterator, pending_exceptions);
    while (g_hash_table_iter_next(&iterator, &key, &value)) {
        uint64_t packed = (uint64_t)(uintptr_t)key;
        guint pid = (guint)(packed >> 32);
        gint64 started = *(gint64 *)value;
        uint64_t age_ms;

        if (!g_hash_table_contains(active_pids, GUINT_TO_POINTER(pid))) {
            g_hash_table_iter_remove(&iterator);
            continue;
        }
        age_ms = now > started ? (uint64_t)(now - started) / 1000 : 0;
        status->pending_exceptions++;
        status->oldest_exception_age_ms =
            MAX(status->oldest_exception_age_ms, age_ms);
    }
}

static bool answer_marker_status_query(uint64_t destination)
{
    MarkerStatus status = {
        .magic = MARK_STATUS_MAGIC,
        .sample_started = sample_started,
        .execution_events = exec_events,
    };
    g_autoptr(GByteArray) bytes = g_byte_array_new();
    g_autoptr(GHashTable) active_pids =
        g_hash_table_new(g_direct_hash, g_direct_equal);

    if (!destination) {
        return false;
    }
    if (!kernel_base) {
        marker_query_initializing++;
    } else {
        if (!count_active_monitored_processes(&status.active_processes,
                                              active_pids)) {
            return false;
        }
        status.status_ready = 1;
        marker_query_ready++;
        pending_exception_status(active_pids, &status);
    }
    g_byte_array_append(bytes, (const guint8 *)&status, sizeof(status));
    return qemu_plugin_write_memory_vaddr(destination, bytes);
}

static bool user_address(uint64_t address)
{
    return address < USER_LIMIT_64;
}

static const char *exception_dispatch_source(uint64_t address,
                                             uint64_t file_offset,
                                             bool system_role)
{
    uint8_t bytes[16];

    if (!system_role || !read_memory(address, bytes, sizeof(bytes))) {
        return NULL;
    }
    if (file_offset == NTDLL_KIUSER_EXCEPTION_DISPATCHER_FILE_OFFSET &&
        memcmp(bytes, ki_user_exception_dispatcher_signature,
               sizeof(bytes)) == 0) {
        return "KiUserExceptionDispatcher";
    }
    if (file_offset == NTDLL_RTL_RAISE_EXCEPTION_FILE_OFFSET &&
        memcmp(bytes, rtl_raise_exception_signature, sizeof(bytes)) == 0) {
        return "RtlRaiseException";
    }
    return NULL;
}

static void vcpu_discontinuity(unsigned int vcpu_index,
                               enum qemu_plugin_discon_type type,
                               uint64_t from_pc, uint64_t to_pc,
                               void *userdata)
{
    ThreadContext context;
    int exception_index;

    (void)to_pc;
    (void)userdata;
    if (type != QEMU_PLUGIN_DISCON_EXCEPTION || !active || !sample_started ||
        !user_address(from_pc) ||
        vcpu_index >= G_N_ELEMENTS(block_context_valid_by_vcpu) ||
        !block_context_valid_by_vcpu[vcpu_index]) {
        return;
    }
    exception_index = qemu_plugin_vcpu_exception_index();
    /* F5 diagnostic (counts only, emits nothing): a monitored thread taking
     * #PF/#NM here, and especially repeat faults at the same from_pc, is the
     * fault-on-entry-loop signature at a just-written page.  This must run
     * before the switch below, which drops those vectors. */
    if ((exception_index == 14 || exception_index == 7) &&
        vcpu_index < G_N_ELEMENTS(block_source_monitored_by_vcpu) &&
        (block_source_is_root_by_vcpu[vcpu_index] ||
         block_source_monitored_by_vcpu[vcpu_index])) {
        monitored_user_pagefaults++;
        if (vcpu_index < G_N_ELEMENTS(monitored_user_pagefault_last_pc_by_vcpu)) {
            if (monitored_user_pagefault_last_pc_by_vcpu[vcpu_index] == from_pc) {
                monitored_user_pagefault_repeats++;
                if (pagefault_loop_events) {
                    ThreadContext loop_context =
                        block_context_by_vcpu[vcpu_index];
                    g_mutex_lock(&trace_lock);
                    /* One record per distinct looping site, so a tight loop
                     * cannot swamp the trace. */
                    gpointer key = (gpointer)(uintptr_t)
                        (from_pc ^ (loop_context.source_pid * UINT64_C(0x9e3779b9)));
                    if (!g_hash_table_contains(pagefault_loop_reported, key)) {
                        g_hash_table_add(pagefault_loop_reported, key);
                        pagefault_loop_sites++;
                        fprintf(trace_file,
                                "{\"event\":\"pagefault_loop\",\"seq\":%" PRIu64
                                ",\"vcpu\":%u,\"pid\":%" PRIu64
                                ",\"tid\":%" PRIu64 ",\"address\":%" PRIu64
                                ",\"vector\":%d}\n",
                                ++sequence_number, vcpu_index,
                                loop_context.source_pid, loop_context.tid,
                                from_pc, exception_index);
                    }
                    g_mutex_unlock(&trace_lock);
                }
            }
            monitored_user_pagefault_last_pc_by_vcpu[vcpu_index] = from_pc;
        }
    }
    /* x86 user-visible faults that represent application exceptions.  In
     * particular, exclude #PF (14) and #NM (7): Windows uses them routinely
     * for demand paging and lazy architectural state, and neither means that
     * the protected program raised an application exception. */
    switch (exception_index) {
    case 0:  /* #DE divide error */
    case 1:  /* #DB debug */
    case 3:  /* #BP breakpoint */
    case 4:  /* #OF overflow */
    case 5:  /* #BR bounds */
    case 6:  /* #UD invalid opcode */
    case 10: /* #TS invalid TSS */
    case 11: /* #NP segment not present */
    case 12: /* #SS stack fault */
    case 13: /* #GP general protection */
    case 16: /* #MF x87 floating point */
    case 17: /* #AC alignment check */
    case 19: /* #XM SIMD floating point */
    case 21: /* #CP control protection */
        break;
    default:
        return;
    }
    context = block_context_by_vcpu[vcpu_index];

    g_mutex_lock(&trace_lock);
    if (process_monitored(context.source_pid, context.source_eprocess)) {
        mark_exception_dispatch(context.source_pid, context.tid, from_pc,
                                "processor_exception", exception_index);
    }
    g_mutex_unlock(&trace_lock);
}

static bool learn_root_entry(unsigned int vcpu_index, uint64_t pc)
{
    RegisterSet *regs = &registers_by_vcpu[vcpu_index];
    bool ok;
    uint64_t teb;
    uint64_t peb;
    uint64_t image_base;
    uint32_t pe_offset;
    uint32_t signature;
    uint16_t optional_magic;
    uint32_t entry_rva;
    uint32_t image_size;

    if (pc < USER_LIMIT_32) {
        uint32_t peb32;
        uint32_t image32;
        if (!regs->has_fs_base) {
            return false;
        }
        teb = read_register_value(regs->fs_base, &ok);
        if (!ok || !teb || !read_u32(teb + 0x30, &peb32) ||
            !read_u32((uint64_t)peb32 + 0x08, &image32)) {
            return false;
        }
        peb = peb32;
        image_base = image32;
    } else {
        if (!regs->has_gs_base) {
            return false;
        }
        teb = read_register_value(regs->gs_base, &ok);
        if (!ok || !teb || !read_u64(teb + 0x60, &peb) ||
            !read_u64(peb + 0x10, &image_base)) {
            return false;
        }
    }
    if (!read_u32(image_base + 0x3c, &pe_offset) ||
        !read_u32(image_base + pe_offset, &signature) ||
        signature != UINT32_C(0x00004550) ||
        !read_u16(image_base + pe_offset + 0x18, &optional_magic) ||
        (optional_magic != UINT16_C(0x10b) &&
         optional_magic != UINT16_C(0x20b)) ||
        !read_u32(image_base + pe_offset + 0x28, &entry_rva) ||
        !read_u32(image_base + pe_offset + 0x50, &image_size) || !image_size) {
        return false;
    }
    root_image_base = image_base;
    root_image_size = image_size;
    root_entry = image_base + entry_rva;
    fprintf(trace_file,
            "{\"event\":\"root_image\",\"seq\":%" PRIu64
            ",\"pid\":%" PRIu64 ",\"image_base\":%" PRIu64
            ",\"entrypoint\":%" PRIu64 "}\n",
            ++sequence_number, root_pid, image_base, root_entry);
    return true;
}

static void marker_exec(unsigned int vcpu_index, void *userdata)
{
    RegisterSet *regs;
    uint64_t magic;
    uint64_t pid;
    uint64_t action;
    uint64_t detail;
    bool ok;

    (void)userdata;
    g_mutex_lock(&trace_lock);
    marker_callback_hits++;
    g_mutex_unlock(&trace_lock);
    if (vcpu_index >= G_N_ELEMENTS(registers_by_vcpu)) {
        return;
    }
    regs = &registers_by_vcpu[vcpu_index];
    if (!regs->has_rax || !regs->has_rbx || !regs->has_rcx ||
        !regs->has_rdx) {
        g_mutex_lock(&trace_lock);
        marker_register_failures++;
        g_mutex_unlock(&trace_lock);
        return;
    }
    magic = read_register_value(regs->rax, &ok);
    if (!ok || (uint32_t)magic != PACKER_MARKER_MAGIC) {
        if (!ok) {
            g_mutex_lock(&trace_lock);
            marker_register_failures++;
            g_mutex_unlock(&trace_lock);
        }
        return;
    }
    pid = read_register_value(regs->rbx, &ok);
    if (!ok) {
        return;
    }
    action = read_register_value(regs->rcx, &ok);
    if (!ok) {
        return;
    }
    detail = read_register_value(regs->rdx, &ok);
    if (!ok) {
        detail = 0;
    }

    g_mutex_lock(&trace_lock);
    if ((uint32_t)action == MARK_ROOT_PID) {
        root_pid = (uint32_t)pid;
        armed = true;
        monitor_pid(root_pid, 0, 0, "root_marker");
    } else if ((uint32_t)action == MARK_TRACE_START) {
        armed = true;
        /* This marker is emitted immediately before ResumeThread.  Activate
         * here so kernel discovery can run during process initialization and
         * so TLS callbacks that precede AddressOfEntryPoint are retained.
         * The exact PE entry is still learned and reported separately. */
        active = true;
    } else if ((uint32_t)action == MARK_STATUS_QUERY) {
        if (!answer_marker_status_query(detail)) {
            marker_query_failures++;
        }
    } else if ((uint32_t)action == MARK_TRACE_STOP) {
        active = false;
        saw_stop = true;
        stop_detail = (uint32_t)detail;
    }
    fprintf(trace_file,
            "{\"event\":\"marker\",\"seq\":%" PRIu64
            ",\"pid\":%u,\"action\":%u,\"detail\":%u}\n",
            ++sequence_number, (uint32_t)pid, (uint32_t)action,
            (uint32_t)detail);
    fflush(trace_file);
    g_mutex_unlock(&trace_lock);
}

static void block_exec(unsigned int vcpu_index, void *userdata)
{
    const BlockInfo *block = userdata;
    ThreadContext context;
    MappedFileResult mapped_result;
    MappedFileResult mapped_end_result;
    uint64_t file_id = 0;
    uint64_t file_offset = 0;
    uint64_t end_file_id = 0;
    uint64_t end_file_offset = 0;
    bool system_role = false;
    bool end_system_role = false;
    const char *exception_source = NULL;
    uint64_t asid;

    if (vcpu_index < G_N_ELEMENTS(block_write_eligible_by_vcpu)) {
        block_write_eligible_by_vcpu[vcpu_index] = false;
        qemu_plugin_u64_set(memory_trace_enabled, vcpu_index, 0);
    }

    /* A Windows thread cannot change while a vCPU executes consecutive
     * user-mode translated blocks: every syscall, interrupt, exception, and
     * scheduler transition enters the kernel first.  Retain the exact
     * ETHREAD-derived context across consecutive user blocks and invalidate it
     * on every kernel block. */
    if (!user_address(block->address) &&
        vcpu_index < G_N_ELEMENTS(block_context_valid_by_vcpu)) {
        block_context_valid_by_vcpu[vcpu_index] = false;
        block_source_is_root_by_vcpu[vcpu_index] = false;
        block_source_monitored_by_vcpu[vcpu_index] = false;
        /* F1 defense: drop the cached ETHREAD read on kernel blocks too. */
        ethread_cache_valid_by_vcpu[vcpu_index] = false;
    }
    if (!armed) {
        return;
    }
    /* Kernel-base discovery scans backward from a kernel PC for the ntoskrnl PE
     * header, so it only succeeds from a PC INSIDE ntoskrnl (a syscall handler),
     * not an arbitrary driver/scheduler PC.  It therefore runs below, on the
     * kernel blocks executed once the root is running (its syscalls land in
     * ntoskrnl).  An earlier "eager from activation" variant burned its budget
     * on far-from-ntoskrnl boot PCs and left kernel_base=0 — reverted. */
    if (active && !sample_started && root_asid) {
        if (!user_address(block->address)) {
            g_mutex_lock(&trace_lock);
            if (!kernel_base) {
                discover_kernel_base(block->address);
            }
            g_mutex_unlock(&trace_lock);
            return;
        }
        if (!current_asid(vcpu_index, &asid) || asid != root_asid ||
            block->address < root_image_base ||
            block->address - root_image_base >= root_image_size) {
            return;
        }
    }
    if (sample_started && !user_address(block->address) &&
        !kernel_pc_relevant(block->address)) {
        return;
    }
    bool context_cache_hit = false;
    uint64_t current_thread = 0;
    bool have_current_thread = current_ethread(vcpu_index, &current_thread);
    /* A cache hit is trusted ONLY when the vCPU's current ETHREAD still equals
     * the cached thread.  Without this re-check a stale cached context/verdict
     * from a different thread could be reused (and, via the fast path below,
     * suppress the root's own first blocks).  This mirrors the ETHREAD/PID
     * re-verification cached_current_context already does. */
    if (user_address(block->address) &&
        vcpu_index < G_N_ELEMENTS(block_context_valid_by_vcpu) &&
        block_context_valid_by_vcpu[vcpu_index] && have_current_thread &&
        block_context_by_vcpu[vcpu_index].ethread == current_thread) {
        context = block_context_by_vcpu[vcpu_index];
        block_context_cache_hits++;
        context_cache_hit = true;
    } else {
        if (!cached_current_context(vcpu_index, &context)) {
            context_failures++;
            return;
        }
        /* Validate the gs_base/KPCR-derived identity against the live CR3.  For
         * a USER block the running process's user directory table
         * (current_asid) must equal the resolved attached_asid.  A mismatch
         * means the thread context was sampled during a transient SWAPGS/KPCR
         * window — a fast-guest hazard that otherwise misattributes the block to
         * the wrong process and can hide the root's own first blocks entirely.
         * Reject the bogus resolution so it is neither cached nor acted on; the
         * next block retries with a good read.  (Kernel blocks legitimately run
         * on the kernel CR3 while attached_asid is the user table, so this check
         * applies to user blocks only.) */
        if (user_address(block->address)) {
            uint64_t live_asid;
            if (!current_asid(vcpu_index, &live_asid) ||
                live_asid != context.attached_asid) {
                context_failures++;
                return;
            }
        }
        block_context_refreshes++;
        /* Only USER blocks may (re)validate the per-vCPU user-thread cache; a
         * kernel block must never, or it would undo the kernel-block
         * invalidation above and let a stale non-root verdict persist. */
        if (user_address(block->address) &&
            vcpu_index < G_N_ELEMENTS(block_context_by_vcpu)) {
            block_context_by_vcpu[vcpu_index] = context;
            block_context_valid_by_vcpu[vcpu_index] = true;
        }
    }

    /* Seed kernel_base deterministically from the resolved EPROCESS (any
     * process's ActiveProcessLinks reaches PsActiveProcessHead inside ntoskrnl).
     * This does not depend on sampling an ntoskrnl code block, so it works on the
     * fast KPTI guest where the backward scan cannot. */
    if (!kernel_base && canonical_kernel_pointer(context.source_eprocess)) {
        g_mutex_lock(&trace_lock);
        if (!kernel_base) {
            discover_kernel_base_from_eprocess(context.source_eprocess);
        }
        g_mutex_unlock(&trace_lock);
    }

    /* Throughput fast path: on a cache hit the source thread, and therefore the
     * root/monitored verdict recorded by the refreshing block, are unchanged.
     * An unmonitored, non-root user block produces no trace event, so reject it
     * before taking the global lock or re-running descendant bookkeeping.  This
     * removes the dominant per-block cost incurred by every unrelated Windows
     * process once sample recording has started, without dropping any event
     * from the root or any enrolled descendant. */
    if (context_cache_hit &&
        vcpu_index < G_N_ELEMENTS(block_source_monitored_by_vcpu) &&
        !block_source_monitored_by_vcpu[vcpu_index] &&
        !block_source_is_root_by_vcpu[vcpu_index]) {
        unmonitored_block_rejects++;
        return;
    }

    cache_thread_identity(&context);

    g_mutex_lock(&trace_lock);
    update_monitored_descendant(&context);
    if (vcpu_index < G_N_ELEMENTS(block_source_monitored_by_vcpu)) {
        block_source_is_root_by_vcpu[vcpu_index] =
            (context.source_pid == root_pid);
        block_source_monitored_by_vcpu[vcpu_index] =
            process_monitored(context.source_pid, context.source_eprocess);
    }
    if (!user_address(block->address)) {
        if (active &&
            (process_monitored(context.source_pid,
                               context.source_eprocess) ||
             process_monitored(context.attached_pid,
                               context.attached_eprocess))) {
            kernel_event(vcpu_index, block->address, &context);
        }
        g_mutex_unlock(&trace_lock);
        return;
    }
    if (context.source_pid == root_pid) {
        if (!root_debug_emitted && user_address(block->address)) {
            uint64_t live = 0;
            current_asid(vcpu_index, &live);
            root_debug_emitted = true;
            fprintf(trace_file,
                    "{\"event\":\"root_debug\",\"seq\":%" PRIu64
                    ",\"pid\":%" PRIu64 ",\"address\":%" PRIu64
                    ",\"current_asid\":%" PRIu64 ",\"root_asid\":%" PRIu64
                    ",\"attached_pid\":%" PRIu64 ",\"image_base\":%" PRIu64
                    ",\"image_size\":%" PRIu64 ",\"kernel_base\":%" PRIu64 "}\n",
                    ++sequence_number, context.source_pid, block->address, live,
                    root_asid, context.attached_pid, root_image_base,
                    root_image_size, kernel_base);
        }
        if (!root_entry) {
            learn_root_entry(vcpu_index, block->address);
        }
        /* Learn root_asid from the LIVE CR3 while the root runs its OWN user
         * code (source == attached, so CR3 is the root's own user directory
         * table).  current_asid returns exactly the value the pre-sample asid
         * gate compares against, so this can never latch onto the wrong table:
         * deriving it from EPROCESS.DirectoryTable could pick the kernel table
         * on a KPTI guest and reject every image block forever, and deriving it
         * from a transient attached_asid picks another process's CR3.  Guarded
         * by !root_asid, but only set from an own-process user block, so it is
         * effectively re-derived until a correct value appears. */
        if (!root_asid && user_address(block->address) &&
            context.source_pid == context.attached_pid) {
            uint64_t live;
            if (current_asid(vcpu_index, &live)) {
                root_asid = live;
            }
        }
        if (!sample_started && root_asid && root_image_base &&
            block->address >= root_image_base &&
            block->address - root_image_base < root_image_size) {
            if (!snapshot_latest_process_create_time(
                    &descendant_create_cutoff)) {
                process_snapshot_failures++;
                g_mutex_unlock(&trace_lock);
                return;
            }
            sample_started = true;
            fprintf(trace_file,
                    "{\"event\":\"sample_start\",\"seq\":%" PRIu64
                    ",\"pid\":%" PRIu64 ",\"tid\":%" PRIu64
                    ",\"address\":%" PRIu64
                    ",\"reason\":\"first_root_image_execution\"}\n",
                    ++sequence_number, root_pid, context.tid, block->address);
        }
        if (!root_entry_seen && root_entry && block->address == root_entry) {
            root_entry_seen = true;
            fprintf(trace_file,
                    "{\"event\":\"trace_start\",\"seq\":%" PRIu64
                    ",\"pid\":%" PRIu64 ",\"entrypoint\":%" PRIu64
                    "}\n",
                    ++sequence_number, root_pid, root_entry);
        }
    }
    if (!sample_started) {
        g_mutex_unlock(&trace_lock);
        return;
    }
    if (active && process_monitored(context.source_pid,
                                    context.source_eprocess)) {
        /* One-shot/uncached TBs carry no translate-time physical mapping
         * (physical_complete=false): the code-fetch fast path returned no RAM
         * slot, though the block DID execute (a truly absent page aborts via #PF
         * and never reaches this callback).  Do NOT resolve the physical at
         * execution time -- a CoW/physical transient makes
         * qemu_plugin_translate_vaddr return a physical from a DIFFERENT virtual
         * alias (observed: the never-written stub aliasing the unpacked-output
         * writes, corrupting the analyzer's layer topology).  Record the block
         * with its exact VIRTUAL identity, which is all the paper's per-memory-
         * area single-process layering (Type I-III) needs, and OMIT physical
         * spans (used only for the deferred cross-process shared-RAM aliasing).
         * Audited via blocks_without_physical; never silently dropped. */
        bool emit_physical = block->physical_complete;
        if (!emit_physical) {
            blocks_without_physical++;
        }
        mapped_result = cached_mapped_file_location(
            context.attached_eprocess, block->address, &file_id, &file_offset,
            &system_role);
        if (mapped_result == MAPPED_FILE_FOUND && block->size > 1) {
            mapped_end_result = cached_mapped_file_location(
                context.attached_eprocess,
                block->address + block->size - 1,
                &end_file_id, &end_file_offset, &end_system_role);
            if (mapped_end_result != MAPPED_FILE_FOUND ||
                end_file_id != file_id ||
                end_system_role != system_role ||
                end_file_offset != file_offset + block->size - 1) {
                mapped_result = MAPPED_FILE_ERROR;
            }
        }
        if (mapped_result == MAPPED_FILE_ERROR) {
            mapped_file_failures++;
        }
        if (mapped_result == MAPPED_FILE_FOUND) {
            mapped_file_exec_events++;
            exception_source = exception_dispatch_source(
                block->address, file_offset, system_role);
        }
        if (exception_source) {
            mark_exception_dispatch(context.source_pid, context.tid,
                                    block->address, exception_source, -1);
        } else if (mapped_result != MAPPED_FILE_ERROR && !system_role) {
            mark_exception_recovery(context.source_pid, context.tid,
                                    block->address);
            cache_application_pc(&context, block->address);
        }
        if (context.source_pid == context.attached_pid &&
            vcpu_index < G_N_ELEMENTS(block_write_eligible_by_vcpu)) {
            block_write_eligible_by_vcpu[vcpu_index] = true;
            qemu_plugin_u64_set(memory_trace_enabled, vcpu_index, 1);
        }
        fprintf(trace_file,
                "{\"event\":\"exec\",\"seq\":%" PRIu64
                ",\"vcpu\":%u,\"pid\":%" PRIu64
                ",\"tid\":%" PRIu64 ",\"address\":%" PRIu64
                ",\"size\":%u,\"basic_block_instructions\":%u",
                ++sequence_number, vcpu_index, context.source_pid, context.tid,
                block->address, block->size, block->insns);
        if (emit_physical) {
            emit_physical_spans(block->spans, block->span_count);
        }
        if (mapped_result == MAPPED_FILE_FOUND) {
            fprintf(trace_file,
                    ",\"file_id\":%" PRIu64
                    ",\"file_offset\":%" PRIu64,
                    file_id, file_offset);
            if (system_role) {
                fputs(",\"role\":\"system\"", trace_file);
            }
        }
        fputs("}\n", trace_file);
        exec_events++;
    }
    g_mutex_unlock(&trace_lock);
}

static void memory_write(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                         uint64_t address, void *userdata)
{
    const InstructionInfo *instruction = userdata;
    ThreadContext context;
    PhysicalSpan spans[MAX_PHYSICAL_SPANS] = {0};
    uint32_t span_count = 0;
    unsigned int shift;
    uint64_t size;

    if (!active || !sample_started || !qemu_plugin_mem_is_store(info) ||
        vcpu_index >= G_N_ELEMENTS(block_write_eligible_by_vcpu) ||
        !block_write_eligible_by_vcpu[vcpu_index]) {
        return;
    }
    shift = qemu_plugin_mem_size_shift(info);
    if (shift >= 63) {
        return;
    }
    size = UINT64_C(1) << shift;
    if (vcpu_index >= G_N_ELEMENTS(block_context_valid_by_vcpu) ||
        !block_context_valid_by_vcpu[vcpu_index]) {
        block_context_misses++;
        return;
    }
    context = block_context_by_vcpu[vcpu_index];

    g_mutex_lock(&trace_lock);
    if (context.source_pid != context.attached_pid ||
        !process_monitored(context.source_pid, context.source_eprocess)) {
        g_mutex_unlock(&trace_lock);
        return;
    }
    g_mutex_unlock(&trace_lock);

    /* Buffered callbacks are drained immediately after the current TB and
     * before another TB or vCPU can execute.  qemu_plugin_get_hwaddr() is only
     * valid inside QEMU's dynamic memory-callback lifetime, so it must not be
     * used here.  A retained user-mode store cannot change its page-table
     * mapping inside that TB; resolve the address through the still-current
     * vCPU address space and convert the resulting physical address to the
     * stable RAM-block identity used by execution and invalidation events. */
    bool write_physical_complete = true;
    for (uint64_t offset = 0; offset < size; offset++) {
        uint64_t physical_address;
        uint64_t ram_address = UINT64_MAX;

        if (qemu_plugin_translate_vaddr(address + offset,
                                        &physical_address)) {
            ram_address =
                qemu_plugin_phys_addr_ram_addr(physical_address);
        }
        if (!add_physical_byte(spans, &span_count, (uint32_t)offset,
                               ram_address)) {
            /* Physical could not be resolved for this stored byte (a CoW/one-shot
             * transient).  The store DID happen -- record the write with its exact
             * VIRTUAL identity (all the paper's per-memory-area layering needs) and
             * OMIT physical spans instead of dropping the write event.  Physical
             * spans matter only for the deferred cross-process shared-RAM aliasing.
             * Audited via writes_without_physical; never silently dropped. */
            write_physical_complete = false;
            break;
        }
    }
    if (!write_physical_complete) {
        writes_without_physical++;
    }

    g_mutex_lock(&trace_lock);
    fprintf(trace_file,
            "{\"event\":\"write\",\"seq\":%" PRIu64
            ",\"vcpu\":%u,\"pid\":%" PRIu64
            ",\"tid\":%" PRIu64 ",\"target_pid\":%" PRIu64
            ",\"address\":%" PRIu64 ",\"size\":%" PRIu64
            ",\"pc\":%" PRIu64,
            ++sequence_number, vcpu_index, context.source_pid, context.tid,
            context.attached_pid, address, size, instruction->pc);
    if (write_physical_complete) {
        emit_physical_spans(spans, span_count);
    }
    fputs("}\n", trace_file);
    write_events++;
    g_mutex_unlock(&trace_lock);
}

static void translate_block(struct qemu_plugin_tb *tb, void *userdata)
{
    size_t count = qemu_plugin_tb_n_insns(tb);
    BlockInfo *block = g_new0(BlockInfo, 1);
    uint64_t end = 0;

    (void)userdata;
    block->address = qemu_plugin_tb_vaddr(tb);
    block->insns = (uint32_t)count;
    block->physical_complete = true;
    for (size_t index = 0; index < count; index++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);
        uint64_t address = qemu_plugin_insn_vaddr(insn);
        size_t size = qemu_plugin_insn_size(insn);

        end = address + size;
        if (user_address(address)) {
            uint8_t bytes[16] = {0};
            InstructionInfo *instruction = g_new(InstructionInfo, 1);
            instruction->pc = address;
            for (size_t byte = 0;
                 block->physical_complete && byte < size; byte++) {
                uint64_t ram_address =
                    qemu_plugin_insn_ram_addr_at(insn, byte);
                uint32_t offset =
                    (uint32_t)(address + byte - block->address);
                if (!add_physical_byte(block->spans,
                                       &block->span_count, offset,
                                       ram_address)) {
                    block->physical_complete = false;
                }
            }
            qemu_plugin_register_vcpu_mem_buffered_cond_cb(
                insn, memory_write, QEMU_PLUGIN_CB_NO_REGS,
                QEMU_PLUGIN_MEM_W, QEMU_PLUGIN_COND_EQ,
                memory_trace_enabled, 1, memory_event_buffer, instruction);
            size_t copied = qemu_plugin_insn_data(insn, bytes, sizeof(bytes));
            size_t marker_offset = copied >= 9 && bytes[0] == 0x67 ? 1 : 0;
            if (copied >= marker_offset + 8 &&
                bytes[marker_offset] == 0x0f &&
                bytes[marker_offset + 1] == 0x1f &&
                bytes[marker_offset + 2] == 0x84 &&
                bytes[marker_offset + 3] == 0x00 &&
                bytes[marker_offset + 4] == 0x4b &&
                bytes[marker_offset + 5] == 0x43 &&
                bytes[marker_offset + 6] == 0x41 &&
                bytes[marker_offset + 7] == 0x50) {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, marker_candidate_exec, QEMU_PLUGIN_CB_NO_REGS,
                    NULL);
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, marker_exec, QEMU_PLUGIN_CB_R_REGS, NULL);
            }
        }
    }
    block->size = end > block->address ? (uint32_t)(end - block->address) : 0;
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, block_exec, QEMU_PLUGIN_CB_R_REGS, block);
}

static void initialize_vcpu(unsigned int vcpu_index, void *userdata)
{
    GArray *descriptors;
    RegisterSet *regs;

    (void)userdata;
    if (vcpu_index >= G_N_ELEMENTS(registers_by_vcpu)) {
        return;
    }
    regs = &registers_by_vcpu[vcpu_index];
    descriptors = qemu_plugin_get_registers();
    for (guint index = 0; index < descriptors->len; index++) {
        qemu_plugin_reg_descriptor descriptor =
            g_array_index(descriptors, qemu_plugin_reg_descriptor, index);
#define PICK_REGISTER(field)                                                   \
        if (g_strcmp0(descriptor.name, #field) == 0) {                         \
            regs->field = descriptor.handle;                                  \
            regs->has_##field = true;                                         \
        }
        PICK_REGISTER(rax)
        PICK_REGISTER(rbx)
        PICK_REGISTER(rcx)
        PICK_REGISTER(rdx)
        PICK_REGISTER(rsp)
        PICK_REGISTER(r8)
        PICK_REGISTER(r9)
        PICK_REGISTER(cr3)
        PICK_REGISTER(fs_base)
        PICK_REGISTER(gs_base)
        PICK_REGISTER(k_gs_base)
#undef PICK_REGISTER
    }
    g_array_free(descriptors, true);
    g_mutex_lock(&trace_lock);
    fprintf(trace_file,
            "{\"event\":\"register_handles\",\"vcpu\":%u,"
            "\"rax\":%s,\"rbx\":%s,\"rcx\":%s,\"rdx\":%s,"
            "\"rsp\":%s,\"cr3\":%s,\"fs_base\":%s,"
            "\"gs_base\":%s,\"k_gs_base\":%s}\n",
            vcpu_index, regs->has_rax ? "true" : "false",
            regs->has_rbx ? "true" : "false",
            regs->has_rcx ? "true" : "false",
            regs->has_rdx ? "true" : "false",
            regs->has_rsp ? "true" : "false",
            regs->has_cr3 ? "true" : "false",
            regs->has_fs_base ? "true" : "false",
            regs->has_gs_base ? "true" : "false",
            regs->has_k_gs_base ? "true" : "false");
    fflush(trace_file);
    g_mutex_unlock(&trace_lock);
}

static void plugin_exit(void *userdata)
{
    (void)userdata;
    g_mutex_lock(&trace_lock);
    if (trace_file) {
        fprintf(trace_file,
                "{\"event\":\"summary\",\"seq\":%" PRIu64
                ",\"root_pid\":%" PRIu64
                ",\"root_eprocess\":%" PRIu64
                ",\"root_create_time\":%" PRIu64
                ",\"root_job\":%" PRIu64
                ",\"descendant_create_cutoff\":%" PRIu64
                ",\"root_asid\":%" PRIu64
                ",\"root_image_base\":%" PRIu64
                ",\"root_image_size\":%" PRIu64
                ",\"root_entry\":%" PRIu64
                ",\"root_entry_seen\":%s"
                ",\"sample_started\":%s"
                ",\"exec_events\":%" PRIu64 ",\"write_events\":%" PRIu64
                ",\"filtered_kernel_write_events\":%" PRIu64
                ",\"kernel_store_callbacks_registered\":false"
                ",\"always_present_user_store_callbacks\":true"
                ",\"buffered_memory_callbacks_registered\":true"
                ",\"memory_buffer_overflows\":%" PRIu64
                ",\"context_failures\":%" PRIu64
                ",\"invalidation_events\":%" PRIu64
                ",\"invalidation_failures\":%" PRIu64
                ",\"unresolved_process_handles\":%" PRIu64
                ",\"physical_mapping_failures\":%" PRIu64
                ",\"blocks_without_physical\":%" PRIu64
                ",\"writes_without_physical\":%" PRIu64
                ",\"marker_candidate_hits\":%" PRIu64
                ",\"marker_callback_hits\":%" PRIu64
                ",\"marker_register_failures\":%" PRIu64
                ",\"marker_query_failures\":%" PRIu64
                ",\"marker_query_initializing\":%" PRIu64
                ",\"marker_query_ready\":%" PRIu64
                ",\"prestart_root_exec_events\":%" PRIu64
                ",\"prestart_system_exec_events\":%" PRIu64
                ",\"prestart_unmapped_exec_events\":%" PRIu64
                ",\"file_io_events\":%" PRIu64
                ",\"file_io_failures\":%" PRIu64
                ",\"file_io_evictions\":%" PRIu64
                ",\"file_io_register_failures\":%" PRIu64
                ",\"file_io_handle_failures\":%" PRIu64
                ",\"file_io_disk_failures\":%" PRIu64
                ",\"file_io_argument_failures\":%" PRIu64
                ",\"file_io_status_failures\":%" PRIu64
                ",\"asynchronous_file_io\":%" PRIu64
                ",\"mapped_file_exec_events\":%" PRIu64
                ",\"mapped_file_failures\":%" PRIu64
                ",\"system_role_failures\":%" PRIu64
                ",\"exception_dispatch_events\":%" PRIu64
                ",\"exception_recovery_events\":%" PRIu64
                ",\"process_snapshot_failures\":%" PRIu64
                ",\"virtual_memory_write_events\":%" PRIu64
                ",\"virtual_memory_write_failures\":%" PRIu64
                ",\"tb_flush_requests\":%" PRIu64
                ",\"block_context_misses\":%" PRIu64
                ",\"block_context_refreshes\":%" PRIu64
                ",\"block_context_cache_hits\":%" PRIu64
                ",\"descendant_enroll_attempts\":%" PRIu64
                ",\"descendant_read_failures\":%" PRIu64
                ",\"descendant_job_mismatch\":%" PRIu64
                ",\"descendant_createtime_reject\":%" PRIu64
                ",\"descendant_enrolled\":%" PRIu64
                ",\"descendant_parent_enrolled\":%" PRIu64
                ",\"unmonitored_block_rejects\":%" PRIu64
                ",\"context_immutable_reuse\":%" PRIu64
                ",\"monitored_user_pagefaults\":%" PRIu64
                ",\"monitored_user_pagefault_repeats\":%" PRIu64
                ",\"pagefault_loop_sites\":%" PRIu64
                ",\"eager_kernel_discovery_attempts\":%" PRIu64
                ",\"kernel_base\":%" PRIu64
                ",\"discover_calls\":%" PRIu64
                ",\"discover_reads_ok\":%" PRIu64
                ",\"pending_exceptions\":%u"
                ",\"ntdll_sha256\":\"%s\""
                ",\"kernel_profile_guid_age\":\"%s\""
                ",\"saw_stop\":%s,\"stop_detail\":%" PRIu64 "}\n",
                ++sequence_number, root_pid, root_eprocess,
                root_create_time, root_job, descendant_create_cutoff,
                root_asid, root_image_base, root_image_size, root_entry,
                root_entry_seen ? "true" : "false",
                sample_started ? "true" : "false", exec_events,
                write_events, filtered_kernel_write_events,
                qemu_plugin_mem_buffer_overflow_count(memory_event_buffer),
                context_failures,
                invalidation_events,
                invalidation_failures, unresolved_process_handles,
                physical_mapping_failures, blocks_without_physical,
                writes_without_physical, marker_candidate_hits,
                marker_callback_hits, marker_register_failures,
                marker_query_failures, marker_query_initializing,
                marker_query_ready, prestart_root_exec_events,
                prestart_system_exec_events, prestart_unmapped_exec_events,
                file_io_events, file_io_failures,
                file_io_evictions, file_io_register_failures,
                file_io_handle_failures, file_io_disk_failures,
                file_io_argument_failures, file_io_status_failures,
                asynchronous_file_io,
                mapped_file_exec_events, mapped_file_failures,
                system_role_failures, exception_dispatch_events,
                exception_recovery_events, process_snapshot_failures,
                virtual_memory_write_events,
                virtual_memory_write_failures,
                tb_flush_requests,
                block_context_misses,
                block_context_refreshes,
                block_context_cache_hits,
                descendant_enroll_attempts,
                descendant_read_failures,
                descendant_job_mismatch,
                descendant_createtime_reject,
                descendant_enrolled,
                descendant_parent_enrolled,
                unmonitored_block_rejects,
                context_immutable_reuse,
                monitored_user_pagefaults,
                monitored_user_pagefault_repeats, pagefault_loop_sites,
                eager_kernel_discovery_attempts,
                kernel_base,
                discover_calls,
                discover_reads_ok,
                g_hash_table_size(pending_exceptions), NTDLL_SHA256,
                KERNEL_PROFILE_GUID_AGE,
                saw_stop ? "true" : "false",
                stop_detail);
        fclose(trace_file);
        trace_file = NULL;
    }
    g_mutex_unlock(&trace_lock);
    g_hash_table_destroy(monitored_pids);
    g_hash_table_destroy(debugged_pids);
    g_hash_table_destroy(mapped_page_cache);
    g_hash_table_destroy(pending_exceptions);
    g_hash_table_destroy(thread_identities);
    g_hash_table_destroy(pagefault_loop_reported);
    qemu_plugin_scoreboard_free(memory_trace_scoreboard);
    qemu_plugin_mem_buffer_free(memory_event_buffer);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    const char *output = NULL;

    if (!info->system_emulation) {
        fprintf(stderr, "paper_trace requires QEMU system emulation\n");
        return -1;
    }
    for (int index = 0; index < argc; index++) {
        if (g_str_has_prefix(argv[index], "out=")) {
            output = argv[index] + strlen("out=");
        } else if (g_strcmp0(argv[index], "pf_loop=on") == 0) {
            pagefault_loop_events = true;
        } else if (g_strcmp0(argv[index], "descendant=parent") == 0) {
            descendant_by_parent = true;
        } else {
            fprintf(stderr, "paper_trace: unknown option %s\n", argv[index]);
            return -1;
        }
    }
    if (!output || !*output) {
        fprintf(stderr, "paper_trace: required plugin option out=PATH missing\n");
        return -1;
    }
    trace_file = fopen(output, "w");
    if (!trace_file) {
        fprintf(stderr, "paper_trace: cannot open %s: %s\n", output,
                strerror(errno));
        return -1;
    }
    setvbuf(trace_file, NULL, _IOFBF, 1024 * 1024);
    monitored_pids = g_hash_table_new(g_direct_hash, g_direct_equal);
    debugged_pids = g_hash_table_new(g_direct_hash, g_direct_equal);
    mapped_page_cache = g_hash_table_new_full(
        mapped_page_hash, mapped_page_equal, g_free, g_free);
    pending_exceptions = g_hash_table_new_full(
        g_direct_hash, g_direct_equal, NULL, g_free);
    thread_identities = g_hash_table_new_full(
        g_direct_hash, g_direct_equal, NULL, g_free);
    pagefault_loop_reported = g_hash_table_new(g_direct_hash, g_direct_equal);
    g_mutex_init(&trace_lock);
    memory_trace_scoreboard = qemu_plugin_scoreboard_new(sizeof(uint64_t));
    memory_trace_enabled =
        qemu_plugin_scoreboard_u64(memory_trace_scoreboard);
    memory_event_buffer = qemu_plugin_mem_buffer_new(65536);
    if (!memory_event_buffer) {
        fprintf(stderr, "paper_trace: cannot allocate memory-event buffer\n");
        return -1;
    }
    qemu_plugin_register_vcpu_init_cb(id, initialize_vcpu, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate_block, NULL);
    qemu_plugin_register_vcpu_discon_cb(
        id, QEMU_PLUGIN_DISCON_EXCEPTION, vcpu_discontinuity, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
