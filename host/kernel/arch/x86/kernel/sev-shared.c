// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 *
 * This file is not compiled stand-alone. It contains code shared
 * between the pre-decompression boot code and the running Linux kernel
 * and is included directly into both code-bases.
 */

#ifndef __BOOT_COMPRESSED
#define error(v)	pr_err(v)
#define has_cpuflag(f)	boot_cpu_has(f)
#endif

struct sev_snp_cpuid_fn {
	u32 eax_in;
	u32 ecx_in;
	u64 unused;
	u64 unused2;
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
	u64 reserved;
} __packed;

struct sev_snp_cpuid_info {
	u32 count;
	u32 reserved1;
	u64 reserved2;
	struct sev_snp_cpuid_fn fn[0];
} __packed;

/*
 * Since feature negotiation related variables are set early in the boot
 * process they must reside in the .data section so as not to be zeroed
 * out when the .bss section is later cleared.
 *
 * GHCB protocol version negotiated with the hypervisor.
 */
static u16 __ro_after_init ghcb_version;

/* Bitmap of SEV features supported by the hypervisor */
static u64 __ro_after_init sev_hv_features;

/*
 * These are also stored in .data section to avoid the need to re-parse
 * boot_params and re-determine CPUID memory range when .bss is cleared.
 */
static int sev_snp_cpuid_enabled __section(".data");
static unsigned long sev_snp_cpuid_pa __section(".data");
static unsigned long sev_snp_cpuid_sz __section(".data");
static const struct sev_snp_cpuid_info *cpuid_info __section(".data");

static bool __init sev_es_check_cpu_features(void)
{
	if (!has_cpuflag(X86_FEATURE_RDRAND)) {
		error("RDRAND instruction not supported - no trusted source of randomness available\n");
		return false;
	}

	return true;
}

static void __noreturn sev_es_terminate(unsigned int set, unsigned int reason)
{
	u64 val = GHCB_MSR_TERM_REQ;

	/* Tell the hypervisor what went wrong. */
	val |= GHCB_SEV_TERM_REASON(set, reason);

	/* Request Guest Termination from Hypvervisor */
	sev_es_wr_ghcb_msr(val);
	VMGEXIT();

	while (true)
		asm volatile("hlt\n" : : : "memory");
}

/*
 * The hypervisor features are available from GHCB version 2 onward.
 */
static bool get_hv_features(void)
{
	u64 val;

	sev_hv_features = 0;

	if (ghcb_version < 2)
		return false;

	sev_es_wr_ghcb_msr(GHCB_MSR_HV_FT_REQ);
	VMGEXIT();

	val = sev_es_rd_ghcb_msr();
	if (GHCB_RESP_CODE(val) != GHCB_MSR_HV_FT_RESP)
		return false;

	sev_hv_features = GHCB_MSR_HV_FT_RESP_VAL(val);

	return true;
}

static void snp_register_ghcb_early(unsigned long paddr)
{
	unsigned long pfn = paddr >> PAGE_SHIFT;
	u64 val;

	sev_es_wr_ghcb_msr(GHCB_MSR_REG_GPA_REQ_VAL(pfn));
	VMGEXIT();

	val = sev_es_rd_ghcb_msr();

	/* If the response GPA is not ours then abort the guest */
	if ((GHCB_RESP_CODE(val) != GHCB_MSR_REG_GPA_RESP) ||
	    (GHCB_MSR_REG_GPA_RESP_VAL(val) != pfn))
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_REGISTER);
}

static bool sev_es_negotiate_protocol(void)
{
	u64 val;

	/* Do the GHCB protocol version negotiation */
	sev_es_wr_ghcb_msr(GHCB_MSR_SEV_INFO_REQ);
	VMGEXIT();
	val = sev_es_rd_ghcb_msr();

	if (GHCB_MSR_INFO(val) != GHCB_MSR_SEV_INFO_RESP)
		return false;

	if (GHCB_MSR_PROTO_MAX(val) < GHCB_PROTOCOL_MIN ||
	    GHCB_MSR_PROTO_MIN(val) > GHCB_PROTOCOL_MAX)
		return false;

	ghcb_version = min_t(size_t, GHCB_MSR_PROTO_MAX(val), GHCB_PROTOCOL_MAX);

	if (!get_hv_features())
		return false;

	return true;
}

static __always_inline void vc_ghcb_invalidate(struct ghcb *ghcb)
{
	ghcb->save.sw_exit_code = 0;
	memset(ghcb->save.valid_bitmap, 0, sizeof(ghcb->save.valid_bitmap));
}

static bool vc_decoding_needed(unsigned long exit_code)
{
	/* Exceptions don't require to decode the instruction */
	return !(exit_code >= SVM_EXIT_EXCP_BASE &&
		 exit_code <= SVM_EXIT_LAST_EXCP);
}

static enum es_result vc_init_em_ctxt(struct es_em_ctxt *ctxt,
				      struct pt_regs *regs,
				      unsigned long exit_code)
{
	enum es_result ret = ES_OK;

	memset(ctxt, 0, sizeof(*ctxt));
	ctxt->regs = regs;

	if (vc_decoding_needed(exit_code))
		ret = vc_decode_insn(ctxt);

	return ret;
}

static void vc_finish_insn(struct es_em_ctxt *ctxt)
{
	ctxt->regs->ip += ctxt->insn.length;
}

static enum es_result sev_es_ghcb_hv_call(struct ghcb *ghcb,
					  struct es_em_ctxt *ctxt,
					  u64 exit_code, u64 exit_info_1,
					  u64 exit_info_2)
{
	enum es_result ret;

	/* Fill in protocol and format specifiers */
	ghcb->protocol_version = ghcb_version;
	ghcb->ghcb_usage       = GHCB_DEFAULT_USAGE;

	ghcb_set_sw_exit_code(ghcb, exit_code);
	ghcb_set_sw_exit_info_1(ghcb, exit_info_1);
	ghcb_set_sw_exit_info_2(ghcb, exit_info_2);

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	if ((ghcb->save.sw_exit_info_1 & 0xffffffff) == 1) {
		u64 info = ghcb->save.sw_exit_info_2;
		unsigned long v;

		info = ghcb->save.sw_exit_info_2;
		v = info & SVM_EVTINJ_VEC_MASK;

		/* Check if exception information from hypervisor is sane. */
		if ((info & SVM_EVTINJ_VALID) &&
		    ((v == X86_TRAP_GP) || (v == X86_TRAP_UD)) &&
		    ((info & SVM_EVTINJ_TYPE_MASK) == SVM_EVTINJ_TYPE_EXEPT)) {
			ctxt->fi.vector = v;
			if (info & SVM_EVTINJ_VALID_ERR)
				ctxt->fi.error_code = info >> 32;
			ret = ES_EXCEPTION;
		} else {
			ret = ES_VMM_ERROR;
		}
	} else {
		ret = ES_OK;
	}

	return ret;
}

static int sev_cpuid_hv(u32 func, u32 subfunc, u32 *eax, u32 *ebx,
			u32 *ecx, u32 *edx)
{
	u64 val;

	if (eax) {
		sev_es_wr_ghcb_msr(GHCB_CPUID_REQ(func, GHCB_CPUID_REQ_EAX));
		VMGEXIT();
		val = sev_es_rd_ghcb_msr();

		if (GHCB_RESP_CODE(val) != GHCB_MSR_CPUID_RESP)
			return -EIO;

		*eax = (val >> 32);
	}

	if (ebx) {
		sev_es_wr_ghcb_msr(GHCB_CPUID_REQ(func, GHCB_CPUID_REQ_EBX));
		VMGEXIT();
		val = sev_es_rd_ghcb_msr();

		if (GHCB_RESP_CODE(val) != GHCB_MSR_CPUID_RESP)
			return -EIO;

		*ebx = (val >> 32);
	}

	if (ecx) {
		sev_es_wr_ghcb_msr(GHCB_CPUID_REQ(func, GHCB_CPUID_REQ_ECX));
		VMGEXIT();
		val = sev_es_rd_ghcb_msr();

		if (GHCB_RESP_CODE(val) != GHCB_MSR_CPUID_RESP)
			return -EIO;

		*ecx = (val >> 32);
	}

	if (edx) {
		sev_es_wr_ghcb_msr(GHCB_CPUID_REQ(func, GHCB_CPUID_REQ_EDX));
		VMGEXIT();
		val = sev_es_rd_ghcb_msr();

		if (GHCB_RESP_CODE(val) != GHCB_MSR_CPUID_RESP)
			return -EIO;

		*edx = (val >> 32);
	}

	return 0;
}

static inline bool sev_snp_cpuid_active(void)
{
	return sev_snp_cpuid_enabled;
}

static int sev_snp_cpuid_xsave_size(u64 xfeatures_en, u32 base_size,
				    u32 *xsave_size, bool compacted)
{
	u64 xfeatures_found = 0;
	int i;

	*xsave_size = base_size;

	for (i = 0; i < cpuid_info->count; i++) {
		const struct sev_snp_cpuid_fn *fn = &cpuid_info->fn[i];

		if (!(fn->eax_in == 0xd && fn->ecx_in > 1 && fn->ecx_in < 64))
			continue;
		if (!(xfeatures_en & (1UL << fn->ecx_in)))
			continue;
		if (xfeatures_found & (1UL << fn->ecx_in))
			continue;

		xfeatures_found |= (1UL << fn->ecx_in);
		if (compacted)
			*xsave_size += fn->eax;
		else
			*xsave_size = max(*xsave_size, fn->eax + fn->ebx);
	}

	/*
	 * Either the guest set unsupported XCR0/XSS bits, or the corresponding
	 * entries in the CPUID table were not present. This is not a valid
	 * state to be in.
	 */
	if (xfeatures_found != (xfeatures_en & ~3ULL))
		return -EINVAL;

	return 0;
}

static void sev_snp_cpuid_hv(u32 func, u32 subfunc, u32 *eax, u32 *ebx,
			     u32 *ecx, u32 *edx)
{
	/*
	 * Currently MSR protocol is sufficient to handle fallback cases, but
	 * should that change make sure we terminate rather than grabbing random
	 * values. Handling can be added in future to use GHCB-page protocol for
	 * cases that occur late enough in boot that GHCB page is available
	 */
	if (cpuid_function_is_indexed(func) && subfunc != 0)
		sev_es_terminate(1, GHCB_TERM_CPUID_HV);

	if (sev_cpuid_hv(func, 0, eax, ebx, ecx, edx))
		sev_es_terminate(1, GHCB_TERM_CPUID_HV);
}

static bool sev_snp_cpuid_find(u32 func, u32 subfunc, u32 *eax, u32 *ebx,
			       u32 *ecx, u32 *edx)
{
	int i;
	bool found = false;

	for (i = 0; i < cpuid_info->count; i++) {
		const struct sev_snp_cpuid_fn *fn = &cpuid_info->fn[i];

		if (fn->eax_in != func)
			continue;

		if (cpuid_function_is_indexed(func) && fn->ecx_in != subfunc)
			continue;

		*eax = fn->eax;
		*ebx = fn->ebx;
		*ecx = fn->ecx;
		*edx = fn->edx;
		found = true;

		break;
	}

	return found;
}

static bool sev_snp_cpuid_in_range(u32 func)
{
	int i;
	u32 std_range_min = 0;
	u32 std_range_max = 0;
	u32 hyp_range_min = 0x40000000;
	u32 hyp_range_max = 0;
	u32 ext_range_min = 0x80000000;
	u32 ext_range_max = 0;

	for (i = 0; i < cpuid_info->count; i++) {
		const struct sev_snp_cpuid_fn *fn = &cpuid_info->fn[i];

		if (fn->eax_in == std_range_min)
			std_range_max = fn->eax;
		else if (fn->eax_in == hyp_range_min)
			hyp_range_max = fn->eax;
		else if (fn->eax_in == ext_range_min)
			ext_range_max = fn->eax;
	}

	if ((func >= std_range_min && func <= std_range_max) ||
	    (func >= hyp_range_min && func <= hyp_range_max) ||
	    (func >= ext_range_min && func <= ext_range_max))
		return true;

	return false;
}

/*
 * Returns -EOPNOTSUPP if feature not enabled. Any other return value should be
 * treated as fatal by caller since we cannot fall back to hypervisor to fetch
 * the values for security reasons (outside of the specific cases handled here)
 */
static int sev_snp_cpuid(u32 func, u32 subfunc, u32 *eax, u32 *ebx, u32 *ecx,
			 u32 *edx)
{
	if (!sev_snp_cpuid_active())
		return -EOPNOTSUPP;

	if (!cpuid_info)
		return -EIO;

	if (!sev_snp_cpuid_find(func, subfunc, eax, ebx, ecx, edx)) {
		/*
		 * Some hypervisors will avoid keeping track of CPUID entries
		 * where all values are zero, since they can be handled the
		 * same as out-of-range values (all-zero). In our case, we want
		 * to be able to distinguish between out-of-range entries and
		 * in-range zero entries, since the CPUID table entries are
		 * only a template that may need to be augmented with
		 * additional values for things like CPU-specific information.
		 * So if it's not in the table, but is still in the valid
		 * range, proceed with the fix-ups below. Otherwise, just return
		 * zeros.
		 */
		*eax = *ebx = *ecx = *edx = 0;
		if (!sev_snp_cpuid_in_range(func))
			goto out;
	}

	if (func == 0x1) {
		u32 ebx2, edx2;

		sev_snp_cpuid_hv(func, subfunc, NULL, &ebx2, NULL, &edx2);
		/* initial APIC ID */
		*ebx = (*ebx & 0x00FFFFFF) | (ebx2 & 0xFF000000);
		/* APIC enabled bit */
		*edx = (*edx & ~BIT_ULL(9)) | (edx2 & BIT_ULL(9));

		/* OSXSAVE enabled bit */
		if (native_read_cr4() & X86_CR4_OSXSAVE)
			*ecx |= BIT_ULL(27);
	} else if (func == 0x7) {
		/* OSPKE enabled bit */
		*ecx &= ~BIT_ULL(4);
		if (native_read_cr4() & X86_CR4_PKE)
			*ecx |= BIT_ULL(4);
	} else if (func == 0xB) {
		/* extended APIC ID */
		sev_snp_cpuid_hv(func, 0, NULL, NULL, NULL, edx);
	} else if (func == 0xd && (subfunc == 0x0 || subfunc == 0x1)) {
		bool compacted = false;
		u64 xcr0 = 1, xss = 0;
		u32 xsave_size;

		if (native_read_cr4() & X86_CR4_OSXSAVE)
			xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
		if (subfunc == 1) {
			/* boot/compressed doesn't set XSS so 0 is fine there */
#ifndef __BOOT_COMPRESSED
			if (*eax & 0x8) /* XSAVES */
				if (boot_cpu_has(X86_FEATURE_XSAVES))
					rdmsrl(MSR_IA32_XSS, xss);
#endif
			/*
			 * The PPR and APM aren't clear on what size should be
			 * encoded in 0xD:0x1:EBX when compaction is not enabled
			 * by either XSAVEC or XSAVES since SNP-capable hardware
			 * has the entries fixed as 1. KVM sets it to 0 in this
			 * case, but to avoid this becoming an issue it's safer
			 * to simply treat this as unsupported or SNP guests.
			 */
			if (!(*eax & 0xA)) /* (XSAVEC|XSAVES) */
				return -EINVAL;

			compacted = true;
		}

		if (sev_snp_cpuid_xsave_size(xcr0 | xss, *ebx, &xsave_size,
					     compacted))
			return -EINVAL;

		*ebx = xsave_size;
	} else if (func == 0x8000001E) {
		u32 ebx2, ecx2;

		/* extended APIC ID */
		sev_snp_cpuid_hv(func, subfunc, eax, &ebx2, &ecx2, NULL);
		/* compute ID */
		*ebx = (*ebx & 0xFFFFFFF00) | (ebx2 & 0x000000FF);
		/* node ID */
		*ecx = (*ecx & 0xFFFFFFF00) | (ecx2 & 0x000000FF);
	}

out:
	return 0;
}

/*
 * Boot VC Handler - This is the first VC handler during boot, there is no GHCB
 * page yet, so it only supports the MSR based communication with the
 * hypervisor and only the CPUID exit-code.
 */
void __init do_vc_no_ghcb(struct pt_regs *regs, unsigned long exit_code)
{
	unsigned int fn = lower_bits(regs->ax, 32);
	unsigned int subfn = lower_bits(regs->cx, 32);
	u32 eax, ebx, ecx, edx;
	int ret;

	/* Only CPUID is supported via MSR protocol */
	if (exit_code != SVM_EXIT_CPUID)
		goto fail;

	ret = sev_snp_cpuid(fn, subfn, &eax, &ebx, &ecx, &edx);
	if (ret == 0)
		goto out;

	if (ret != -EOPNOTSUPP)
		goto fail;

	if (sev_cpuid_hv(fn, 0, &eax, &ebx, &ecx, &edx))
		goto fail;

out:
	regs->ax = eax;
	regs->bx = ebx;
	regs->cx = ecx;
	regs->dx = edx;

	/*
	 * This is a VC handler and the #VC is only raised when SEV-ES is
	 * active, which means SEV must be active too. Do sanity checks on the
	 * CPUID results to make sure the hypervisor does not trick the kernel
	 * into the no-sev path. This could map sensitive data unencrypted and
	 * make it accessible to the hypervisor.
	 *
	 * In particular, check for:
	 *	- Availability of CPUID leaf 0x8000001f
	 *	- SEV CPUID bit.
	 *
	 * The hypervisor might still report the wrong C-bit position, but this
	 * can't be checked here.
	 */

	if (fn == 0x80000000 && (regs->ax < 0x8000001f))
		/* SEV leaf check */
		goto fail;
	else if ((fn == 0x8000001f && !(regs->ax & BIT(1))))
		/* SEV bit */
		goto fail;

	/* Skip over the CPUID two-byte opcode */
	regs->ip += 2;

	return;

fail:
	/* Terminate the guest */
	sev_es_terminate(SEV_TERM_SET_GEN, GHCB_SEV_ES_GEN_REQ);
}

static enum es_result vc_insn_string_read(struct es_em_ctxt *ctxt,
					  void *src, char *buf,
					  unsigned int data_size,
					  unsigned int count,
					  bool backwards)
{
	int i, b = backwards ? -1 : 1;
	enum es_result ret = ES_OK;

	for (i = 0; i < count; i++) {
		void *s = src + (i * data_size * b);
		char *d = buf + (i * data_size);

		ret = vc_read_mem(ctxt, s, d, data_size);
		if (ret != ES_OK)
			break;
	}

	return ret;
}

static enum es_result vc_insn_string_write(struct es_em_ctxt *ctxt,
					   void *dst, char *buf,
					   unsigned int data_size,
					   unsigned int count,
					   bool backwards)
{
	int i, s = backwards ? -1 : 1;
	enum es_result ret = ES_OK;

	for (i = 0; i < count; i++) {
		void *d = dst + (i * data_size * s);
		char *b = buf + (i * data_size);

		ret = vc_write_mem(ctxt, d, b, data_size);
		if (ret != ES_OK)
			break;
	}

	return ret;
}

#define IOIO_TYPE_STR  BIT(2)
#define IOIO_TYPE_IN   1
#define IOIO_TYPE_INS  (IOIO_TYPE_IN | IOIO_TYPE_STR)
#define IOIO_TYPE_OUT  0
#define IOIO_TYPE_OUTS (IOIO_TYPE_OUT | IOIO_TYPE_STR)

#define IOIO_REP       BIT(3)

#define IOIO_ADDR_64   BIT(9)
#define IOIO_ADDR_32   BIT(8)
#define IOIO_ADDR_16   BIT(7)

#define IOIO_DATA_32   BIT(6)
#define IOIO_DATA_16   BIT(5)
#define IOIO_DATA_8    BIT(4)

#define IOIO_SEG_ES    (0 << 10)
#define IOIO_SEG_DS    (3 << 10)

static enum es_result vc_ioio_exitinfo(struct es_em_ctxt *ctxt, u64 *exitinfo)
{
	struct insn *insn = &ctxt->insn;
	*exitinfo = 0;

	switch (insn->opcode.bytes[0]) {
	/* INS opcodes */
	case 0x6c:
	case 0x6d:
		*exitinfo |= IOIO_TYPE_INS;
		*exitinfo |= IOIO_SEG_ES;
		*exitinfo |= (ctxt->regs->dx & 0xffff) << 16;
		break;

	/* OUTS opcodes */
	case 0x6e:
	case 0x6f:
		*exitinfo |= IOIO_TYPE_OUTS;
		*exitinfo |= IOIO_SEG_DS;
		*exitinfo |= (ctxt->regs->dx & 0xffff) << 16;
		break;

	/* IN immediate opcodes */
	case 0xe4:
	case 0xe5:
		*exitinfo |= IOIO_TYPE_IN;
		*exitinfo |= (u8)insn->immediate.value << 16;
		break;

	/* OUT immediate opcodes */
	case 0xe6:
	case 0xe7:
		*exitinfo |= IOIO_TYPE_OUT;
		*exitinfo |= (u8)insn->immediate.value << 16;
		break;

	/* IN register opcodes */
	case 0xec:
	case 0xed:
		*exitinfo |= IOIO_TYPE_IN;
		*exitinfo |= (ctxt->regs->dx & 0xffff) << 16;
		break;

	/* OUT register opcodes */
	case 0xee:
	case 0xef:
		*exitinfo |= IOIO_TYPE_OUT;
		*exitinfo |= (ctxt->regs->dx & 0xffff) << 16;
		break;

	default:
		return ES_DECODE_FAILED;
	}

	switch (insn->opcode.bytes[0]) {
	case 0x6c:
	case 0x6e:
	case 0xe4:
	case 0xe6:
	case 0xec:
	case 0xee:
		/* Single byte opcodes */
		*exitinfo |= IOIO_DATA_8;
		break;
	default:
		/* Length determined by instruction parsing */
		*exitinfo |= (insn->opnd_bytes == 2) ? IOIO_DATA_16
						     : IOIO_DATA_32;
	}
	switch (insn->addr_bytes) {
	case 2:
		*exitinfo |= IOIO_ADDR_16;
		break;
	case 4:
		*exitinfo |= IOIO_ADDR_32;
		break;
	case 8:
		*exitinfo |= IOIO_ADDR_64;
		break;
	}

	if (insn_has_rep_prefix(insn))
		*exitinfo |= IOIO_REP;

	return ES_OK;
}

static enum es_result vc_handle_ioio(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	struct pt_regs *regs = ctxt->regs;
	u64 exit_info_1, exit_info_2;
	enum es_result ret;

	ret = vc_ioio_exitinfo(ctxt, &exit_info_1);
	if (ret != ES_OK)
		return ret;

	if (exit_info_1 & IOIO_TYPE_STR) {

		/* (REP) INS/OUTS */

		bool df = ((regs->flags & X86_EFLAGS_DF) == X86_EFLAGS_DF);
		unsigned int io_bytes, exit_bytes;
		unsigned int ghcb_count, op_count;
		unsigned long es_base;
		u64 sw_scratch;

		/*
		 * For the string variants with rep prefix the amount of in/out
		 * operations per #VC exception is limited so that the kernel
		 * has a chance to take interrupts and re-schedule while the
		 * instruction is emulated.
		 */
		io_bytes   = (exit_info_1 >> 4) & 0x7;
		ghcb_count = sizeof(ghcb->shared_buffer) / io_bytes;

		op_count    = (exit_info_1 & IOIO_REP) ? regs->cx : 1;
		exit_info_2 = min(op_count, ghcb_count);
		exit_bytes  = exit_info_2 * io_bytes;

		es_base = insn_get_seg_base(ctxt->regs, INAT_SEG_REG_ES);

		/* Read bytes of OUTS into the shared buffer */
		if (!(exit_info_1 & IOIO_TYPE_IN)) {
			ret = vc_insn_string_read(ctxt,
					       (void *)(es_base + regs->si),
					       ghcb->shared_buffer, io_bytes,
					       exit_info_2, df);
			if (ret)
				return ret;
		}

		/*
		 * Issue an VMGEXIT to the HV to consume the bytes from the
		 * shared buffer or to have it write them into the shared buffer
		 * depending on the instruction: OUTS or INS.
		 */
		sw_scratch = __pa(ghcb) + offsetof(struct ghcb, shared_buffer);
		ghcb_set_sw_scratch(ghcb, sw_scratch);
		ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_IOIO,
					  exit_info_1, exit_info_2);
		if (ret != ES_OK)
			return ret;

		/* Read bytes from shared buffer into the guest's destination. */
		if (exit_info_1 & IOIO_TYPE_IN) {
			ret = vc_insn_string_write(ctxt,
						   (void *)(es_base + regs->di),
						   ghcb->shared_buffer, io_bytes,
						   exit_info_2, df);
			if (ret)
				return ret;

			if (df)
				regs->di -= exit_bytes;
			else
				regs->di += exit_bytes;
		} else {
			if (df)
				regs->si -= exit_bytes;
			else
				regs->si += exit_bytes;
		}

		if (exit_info_1 & IOIO_REP)
			regs->cx -= exit_info_2;

		ret = regs->cx ? ES_RETRY : ES_OK;

	} else {

		/* IN/OUT into/from rAX */

		int bits = (exit_info_1 & 0x70) >> 1;
		u64 rax = 0;

		if (!(exit_info_1 & IOIO_TYPE_IN))
			rax = lower_bits(regs->ax, bits);

		ghcb_set_rax(ghcb, rax);

		ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_IOIO, exit_info_1, 0);
		if (ret != ES_OK)
			return ret;

		if (exit_info_1 & IOIO_TYPE_IN) {
			if (!ghcb_rax_is_valid(ghcb))
				return ES_VMM_ERROR;
			regs->ax = lower_bits(ghcb->save.rax, bits);
		}
	}

	return ret;
}

static enum es_result vc_handle_cpuid(struct ghcb *ghcb,
				      struct es_em_ctxt *ctxt)
{
	struct pt_regs *regs = ctxt->regs;
	u32 cr4 = native_read_cr4();
	enum es_result ret;
	u32 eax, ebx, ecx, edx;
	int cpuid_ret;

	cpuid_ret = sev_snp_cpuid(regs->ax, regs->cx, &eax, &ebx, &ecx, &edx);
	if (cpuid_ret == 0) {
		regs->ax = eax;
		regs->bx = ebx;
		regs->cx = ecx;
		regs->dx = edx;
		return ES_OK;
	}
	if (cpuid_ret != -EOPNOTSUPP)
		return ES_VMM_ERROR;

	ghcb_set_rax(ghcb, regs->ax);
	ghcb_set_rcx(ghcb, regs->cx);

	if (cr4 & X86_CR4_OSXSAVE)
		/* Safe to read xcr0 */
		ghcb_set_xcr0(ghcb, xgetbv(XCR_XFEATURE_ENABLED_MASK));
	else
		/* xgetbv will cause #GP - use reset value for xcr0 */
		ghcb_set_xcr0(ghcb, 1);

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_CPUID, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!(ghcb_rax_is_valid(ghcb) &&
	      ghcb_rbx_is_valid(ghcb) &&
	      ghcb_rcx_is_valid(ghcb) &&
	      ghcb_rdx_is_valid(ghcb)))
		return ES_VMM_ERROR;

	regs->ax = ghcb->save.rax;
	regs->bx = ghcb->save.rbx;
	regs->cx = ghcb->save.rcx;
	regs->dx = ghcb->save.rdx;

	return ES_OK;
}

static enum es_result vc_handle_rdtsc(struct ghcb *ghcb,
				      struct es_em_ctxt *ctxt,
				      unsigned long exit_code)
{
	bool rdtscp = (exit_code == SVM_EXIT_RDTSCP);
	enum es_result ret;

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, exit_code, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!(ghcb_rax_is_valid(ghcb) && ghcb_rdx_is_valid(ghcb) &&
	     (!rdtscp || ghcb_rcx_is_valid(ghcb))))
		return ES_VMM_ERROR;

	ctxt->regs->ax = ghcb->save.rax;
	ctxt->regs->dx = ghcb->save.rdx;
	if (rdtscp)
		ctxt->regs->cx = ghcb->save.rcx;

	return ES_OK;
}

static struct setup_data *get_cc_setup_data(struct boot_params *bp)
{
	struct setup_data *hdr = (struct setup_data *)bp->hdr.setup_data;

	while (hdr) {
		if (hdr->type == SETUP_CC_BLOB)
			return hdr;
		hdr = (struct setup_data *)hdr->next;
	}

	return NULL;
}

/*
 * For boot/compressed kernel:
 *
 *   1) Search for CC blob in the following order/precedence:
 *      - via linux boot protocol / setup_data entry
 *      - via EFI configuration table
 *   2) If found, initialize boot_params->cc_blob_address to point to the
 *      blob so that uncompressed kernel can easily access it during very
 *      early boot without the need to re-parse EFI config table
 *   3) Return a pointer to the CC blob, NULL otherwise.
 *
 * For run-time/uncompressed kernel:
 *
 *   1) Search for CC blob in the following order/precedence:
 *      - via linux boot protocol / setup_data entry
 *      - via boot_params->cc_blob_address
 *   2) Return a pointer to the CC blob, NULL otherwise.
 */
static struct cc_blob_sev_info *sev_snp_probe_cc_blob(struct boot_params *bp)
{
	struct cc_blob_sev_info *cc_info = NULL;
	struct setup_data_cc {
		struct setup_data header;
		u32 cc_blob_address;
	} *sd;
#ifdef __BOOT_COMPRESSED
	unsigned long conf_table_pa;
	unsigned int conf_table_len;
	bool efi_64;
#endif

	/* Try to get CC blob via setup_data */
	sd = (struct setup_data_cc *)get_cc_setup_data(bp);
	if (sd) {
		cc_info = (struct cc_blob_sev_info *)(unsigned long)sd->cc_blob_address;
		goto out_verify;
	}

#ifdef __BOOT_COMPRESSED
	/* CC blob isn't in setup_data, see if it's in the EFI config table */
	if (!efi_get_conf_table(bp, &conf_table_pa, &conf_table_len, &efi_64))
		(void)efi_find_vendor_table(conf_table_pa, conf_table_len,
					    EFI_CC_BLOB_GUID, efi_64,
					    (unsigned long *)&cc_info);
#else
	/*
	 * CC blob isn't in setup_data, see if boot kernel passed it via
	 * boot_params.
	 */
	if (bp->cc_blob_address)
		cc_info = (struct cc_blob_sev_info *)(unsigned long)bp->cc_blob_address;
#endif

out_verify:
	/* CC blob should be either valid or not present. Fail otherwise. */
	if (cc_info && cc_info->magic != CC_BLOB_SEV_HDR_MAGIC)
		sev_es_terminate(1, GHCB_SNP_UNSUPPORTED);

#ifdef __BOOT_COMPRESSED
	/*
	 * Pass run-time kernel a pointer to CC info via boot_params for easier
	 * access during early boot.
	 */
	bp->cc_blob_address = (u32)(unsigned long)cc_info;
#endif

	return cc_info;
}

/*
 * Initial set up of CPUID table when running identity-mapped.
 *
 * NOTE: Since SEV_SNP feature partly relies on CPUID checks that can't
 * happen until we access CPUID page, we skip the check and hope the
 * bootloader is providing sane values. Current code relies on all CPUID
 * page lookups originating from #VC handler, which at least provides
 * indication that SEV-ES is enabled. Subsequent init levels will check for
 * SEV_SNP feature once available to also take SEV MSR value into account.
 */
void __init sev_snp_cpuid_init(struct boot_params *bp)
{
	struct cc_blob_sev_info *cc_info;

	if (!bp)
		sev_es_terminate(1, GHCB_TERM_CPUID);

	cc_info = sev_snp_probe_cc_blob(bp);

	if (!cc_info)
		return;

	sev_snp_cpuid_pa = cc_info->cpuid_phys;
	sev_snp_cpuid_sz = cc_info->cpuid_len;

	/*
	 * These should always be valid values for SNP, even if guest isn't
	 * actually configured to use the CPUID table.
	 */
	if (!sev_snp_cpuid_pa || sev_snp_cpuid_sz < PAGE_SIZE)
		sev_es_terminate(1, GHCB_TERM_CPUID);

	cpuid_info = (const struct sev_snp_cpuid_info *)sev_snp_cpuid_pa;

	/*
	 * We should be able to trust the 'count' value in the CPUID table
	 * area, but ensure it agrees with CC blob value to be safe.
	 */
	if (sev_snp_cpuid_sz < (sizeof(struct sev_snp_cpuid_info) +
				sizeof(struct sev_snp_cpuid_fn) *
				cpuid_info->count))
		sev_es_terminate(1, GHCB_TERM_CPUID);

	sev_snp_cpuid_enabled = 1;
}

#ifndef __BOOT_COMPRESSED

static bool __init early_make_pgtable_enc(unsigned long physaddr)
{
	pmdval_t pmd;

	/* early_pmd_flags hasn't been updated with SME bit yet; add it */
	pmd = (physaddr & PMD_MASK) + early_pmd_flags + sme_get_me_mask();

	return __early_make_pgtable((unsigned long)__va(physaddr), pmd);
}

/*
 * This is called when we switch to virtual kernel addresses, before #PF
 * handler is set up. boot_params have already been parsed at this point,
 * but CPUID page is no longer identity-mapped so we need to create a
 * virtual mapping.
 */
void __init sev_snp_cpuid_init_virtual(void)
{
	/*
	 * We rely on sev_snp_cpuid_init() to do initial parsing of bootparams
	 * and initial setup. If that didn't enable the feature then don't try
	 * to enable it here.
	 */
	if (!sev_snp_cpuid_active())
		return;

	/*
	 * Either boot_params/EFI advertised the feature even though SNP isn't
	 * enabled, or something else went wrong. Bail out.
	 */
	if (!sev_feature_enabled(SEV_SNP))
		sev_es_terminate(1, GHCB_TERM_CPUID);

	/* If feature is enabled, but we can't map CPUID info, we're hosed */
	if (!early_make_pgtable_enc(sev_snp_cpuid_pa))
		sev_es_terminate(1, GHCB_TERM_CPUID);

	cpuid_info = (const struct sev_snp_cpuid_info *)__va(sev_snp_cpuid_pa);
}

/* Called after early_ioremap_init() */
void __init sev_snp_cpuid_init_remap_early(void)
{
	if (!sev_snp_cpuid_active())
		return;

	/*
	 * This really shouldn't be possible at this point.
	 */
	if (!sev_feature_enabled(SEV_SNP))
		sev_es_terminate(1, GHCB_TERM_CPUID);

	cpuid_info = early_memremap(sev_snp_cpuid_pa, sev_snp_cpuid_sz);
}

/* Final switch to run-time mapping */
static int __init sev_snp_cpuid_init_remap(void)
{
	if (!sev_snp_cpuid_active())
		return 0;

	pr_info("Using SNP CPUID page, %d entries present.\n", cpuid_info->count);

	/*
	 * This really shouldn't be possible at this point either.
	 */
	if (!sev_feature_enabled(SEV_SNP))
		sev_es_terminate(1, GHCB_TERM_CPUID);

	/* Clean up earlier mapping. */
	if (cpuid_info)
		early_memunmap((void *)cpuid_info, sev_snp_cpuid_sz);

	/*
	 * We need ioremap_encrypted() to get an encrypted mapping, but this
	 * is normal RAM so can be accessed directly.
	 */
	cpuid_info = (__force void *)ioremap_encrypted(sev_snp_cpuid_pa,
						       sev_snp_cpuid_sz);
	if (!cpuid_info)
		return -EIO;

	return 0;
}

arch_initcall(sev_snp_cpuid_init_remap);

#endif /* __BOOT_COMPRESSED */
