// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

/*
 * misc.h needs to be first because it knows how to include the other kernel
 * headers in the pre-decompression code in a way that does not break
 * compilation.
 */
#include "misc.h"

#include <asm/pgtable_types.h>
#include <asm/sev.h>
#include <asm/trapnr.h>
#include <asm/trap_pf.h>
#include <asm/msr-index.h>
#include <asm/fpu/xcr.h>
#include <asm/ptrace.h>
#include <asm/svm.h>
#include <asm/cpuid.h>
#include <linux/efi.h>
#include <linux/log2.h>

#include "error.h"

struct ghcb boot_ghcb_page __aligned(PAGE_SIZE);
struct ghcb *boot_ghcb;
static u64 msr_sev_status;

/*
 * Copy a version of this function here - insn-eval.c can't be used in
 * pre-decompression code.
 */
static bool insn_has_rep_prefix(struct insn *insn)
{
	insn_byte_t p;
	int i;

	insn_get_prefixes(insn);

	for_each_insn_prefix(insn, i, p) {
		if (p == 0xf2 || p == 0xf3)
			return true;
	}

	return false;
}

/*
 * Only a dummy for insn_get_seg_base() - Early boot-code is 64bit only and
 * doesn't use segments.
 */
static unsigned long insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx)
{
	return 0UL;
}

static inline u64 sev_es_rd_ghcb_msr(void)
{
	unsigned long low, high;

	asm volatile("rdmsr" : "=a" (low), "=d" (high) :
			"c" (MSR_AMD64_SEV_ES_GHCB));

	return ((high << 32) | low);
}

static inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = val & 0xffffffffUL;
	high = val >> 32;

	asm volatile("wrmsr" : : "c" (MSR_AMD64_SEV_ES_GHCB),
			"a"(low), "d" (high) : "memory");
}

static enum es_result vc_decode_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	int ret;

	memcpy(buffer, (unsigned char *)ctxt->regs->ip, MAX_INSN_SIZE);

	ret = insn_decode(&ctxt->insn, buffer, MAX_INSN_SIZE, INSN_MODE_64);
	if (ret < 0)
		return ES_DECODE_FAILED;

	return ES_OK;
}

static enum es_result vc_write_mem(struct es_em_ctxt *ctxt,
				   void *dst, char *buf, size_t size)
{
	memcpy(dst, buf, size);

	return ES_OK;
}

static enum es_result vc_read_mem(struct es_em_ctxt *ctxt,
				  void *src, char *buf, size_t size)
{
	memcpy(buf, src, size);

	return ES_OK;
}

#undef __init
#undef __pa
#define __init
#define __pa(x)	((unsigned long)(x))

#define __BOOT_COMPRESSED

/* Basic instruction decoding support needed */
#include "../../lib/inat.c"
#include "../../lib/insn.c"

/* Include code for early handlers */
#include "../../kernel/sev-shared.c"

bool sev_snp_enabled(void)
{
	unsigned long low, high;

	if (!msr_sev_status) {
		asm volatile("rdmsr\n"
			     : "=a" (low), "=d" (high)
			     : "c" (MSR_AMD64_SEV));
		msr_sev_status = (high << 32) | low;
	}

	return msr_sev_status & MSR_AMD64_SEV_SNP_ENABLED;
}

static bool is_vmpl0(void)
{
	u64 attrs, va;
	int err;

	/*
	 * There is no straightforward way to query the current VMPL level. The
	 * simplest method is to use the RMPADJUST instruction to change a page
	 * permission to a VMPL level-1, and if the guest kernel is launched at
	 * a level <= 1, then RMPADJUST instruction will return an error.
	 */
	attrs = 1;

	/*
	 * Any page aligned virtual address is sufficent to test the VMPL level.
	 * The boot_ghcb_page is page aligned memory, so lets use for the test.
	 */
	va = (u64)&boot_ghcb_page;

	/* Instruction mnemonic supported in binutils versions v2.36 and later */
	asm volatile (".byte 0xf3,0x0f,0x01,0xfe\n\t"
		      : "=a" (err)
		      : "a" (va), "c" (RMP_PG_SIZE_4K), "d" (attrs)
		      : "memory", "cc");
	if (err)
		return false;

	return true;
}

static void __page_state_change(unsigned long paddr, enum psc_op op)
{
	u64 val;

	if (!sev_snp_enabled())
		return;

	/*
	 * If private -> shared then invalidate the page before requesting the
	 * state change in the RMP table.
	 */
	if (op == SNP_PAGE_STATE_SHARED && pvalidate(paddr, RMP_PG_SIZE_4K, 0))
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PVALIDATE);

	/* Issue VMGEXIT to change the page state in RMP table. */
	sev_es_wr_ghcb_msr(GHCB_MSR_PSC_REQ_GFN(paddr >> PAGE_SHIFT, op));
	VMGEXIT();

	/* Read the response of the VMGEXIT. */
	val = sev_es_rd_ghcb_msr();
	if ((GHCB_RESP_CODE(val) != GHCB_MSR_PSC_RESP) || GHCB_MSR_PSC_RESP_VAL(val))
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PSC);

	/*
	 * Now that page is added in the RMP table, validate it so that it is
	 * consistent with the RMP entry.
	 */
	if (op == SNP_PAGE_STATE_PRIVATE && pvalidate(paddr, RMP_PG_SIZE_4K, 1))
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PVALIDATE);
}

void snp_set_page_private(unsigned long paddr)
{
	__page_state_change(paddr, SNP_PAGE_STATE_PRIVATE);
}

void snp_set_page_shared(unsigned long paddr)
{
	__page_state_change(paddr, SNP_PAGE_STATE_SHARED);
}

static bool do_early_sev_setup(void)
{
	if (!sev_es_negotiate_protocol())
		sev_es_terminate(SEV_TERM_SET_GEN, GHCB_SEV_ES_PROT_UNSUPPORTED);

	/*
	 * If SEV-SNP is enabled, then check if the hypervisor supports the SEV-SNP
	 * features and is launched at VMPL-0 level.
	 */
	if (sev_snp_enabled()) {
		if (!(sev_hv_features & GHCB_HV_FT_SNP))
			sev_es_terminate(SEV_TERM_SET_GEN, GHCB_SNP_UNSUPPORTED);

		if (!is_vmpl0())
			sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_NOT_VMPL0);
	}

	if (set_page_decrypted((unsigned long)&boot_ghcb_page))
		return false;

	/* Page is now mapped decrypted, clear it */
	memset(&boot_ghcb_page, 0, sizeof(boot_ghcb_page));

	boot_ghcb = &boot_ghcb_page;

	/* Initialize lookup tables for the instruction decoder */
	inat_init_tables();

	/* SEV-SNP guest requires the GHCB GPA must be registered */
	if (sev_snp_enabled())
		snp_register_ghcb_early(__pa(&boot_ghcb_page));

	return true;
}

void sev_es_shutdown_ghcb(void)
{
	if (!boot_ghcb)
		return;

	if (!sev_es_check_cpu_features())
		error("SEV-ES CPU Features missing.");

	/*
	 * GHCB Page must be flushed from the cache and mapped encrypted again.
	 * Otherwise the running kernel will see strange cache effects when
	 * trying to use that page.
	 */
	if (set_page_encrypted((unsigned long)&boot_ghcb_page))
		error("Can't map GHCB page encrypted");

	/*
	 * GHCB page is mapped encrypted again and flushed from the cache.
	 * Mark it non-present now to catch bugs when #VC exceptions trigger
	 * after this point.
	 */
	if (set_page_non_present((unsigned long)&boot_ghcb_page))
		error("Can't unmap GHCB page");
}

bool sev_es_check_ghcb_fault(unsigned long address)
{
	/* Check whether the fault was on the GHCB page */
	return ((address & PAGE_MASK) == (unsigned long)&boot_ghcb_page);
}

void do_boot_stage2_vc(struct pt_regs *regs, unsigned long exit_code)
{
	struct es_em_ctxt ctxt;
	enum es_result result;

	if (!boot_ghcb && !do_early_sev_setup())
		sev_es_terminate(SEV_TERM_SET_GEN, GHCB_SEV_ES_GEN_REQ);

	vc_ghcb_invalidate(boot_ghcb);
	result = vc_init_em_ctxt(&ctxt, regs, exit_code);
	if (result != ES_OK)
		goto finish;

	switch (exit_code) {
	case SVM_EXIT_RDTSC:
	case SVM_EXIT_RDTSCP:
		result = vc_handle_rdtsc(boot_ghcb, &ctxt, exit_code);
		break;
	case SVM_EXIT_IOIO:
		result = vc_handle_ioio(boot_ghcb, &ctxt);
		break;
	case SVM_EXIT_CPUID:
		result = vc_handle_cpuid(boot_ghcb, &ctxt);
		break;
	default:
		result = ES_UNSUPPORTED;
		break;
	}

finish:
	if (result == ES_OK)
		vc_finish_insn(&ctxt);
	else if (result != ES_RETRY)
		sev_es_terminate(SEV_TERM_SET_GEN, GHCB_SEV_ES_GEN_REQ);
}
