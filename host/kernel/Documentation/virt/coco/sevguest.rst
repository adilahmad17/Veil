.. SPDX-License-Identifier: GPL-2.0

===================================================================
The Definitive SEV Guest API Documentation
===================================================================

1. General description
======================

The SEV API is a set of ioctls that are issued to by the guest or
hypervisor to get or set certain aspect of the SEV virtual machine.
The ioctls belong to the following classes:

 - Hypervisor ioctls: These query and set global attributes which affect the
   whole SEV firmware.  These ioctl is used by platform provision tools.

 - Guest ioctls: These query and set attribute of the SEV virtual machine.

2. API description
==================

This section describes ioctls that can be used to query or set SEV guests.
For each ioctl, the following information is provided along with a
description:

  Technology:
      which SEV techology provides this ioctl. sev, sev-es, sev-snp or all.

  Type:
      hypervisor or guest. The ioctl can be used inside the guest or the
      hypervisor.

  Parameters:
      what parameters are accepted by the ioctl.

  Returns:
      the return value.  General error numbers (ENOMEM, EINVAL)
      are not detailed, but errors with specific meanings are.

The guest ioctl should be called to /dev/sev-guest device. The ioctl accepts
struct snp_user_guest_request. The input and output structure is specified
through the req_data and resp_data field respectively. If the ioctl fails
to execute due to the firmware error, then fw_err code will be set.

::
        struct snp_user_guest_request {
                /* Request and response structure address */
                __u64 req_data;
                __u64 resp_data;

                /* firmware error code on failure (see psp-sev.h) */
                __u64 fw_err;
        };

The host ioctl should be called to /dev/sev device. The ioctl accepts command
id and command input structure.

::
        struct sev_issue_cmd {
                /* Command ID */
                __u32 cmd;

                /* Command request structure */
                __u64 data;

                /* firmware error code on failure (see psp-sev.h) */
                __u32 error;
        };


2.1 SNP_GET_REPORT
------------------

:Technology: sev-snp
:Type: guest ioctl
:Parameters (in): struct snp_report_req
:Returns (out): struct snp_report_resp on success, -negative on error

The SNP_GET_REPORT ioctl can be used to query the attestation report from the
SEV-SNP firmware. The ioctl uses the SNP_GUEST_REQUEST (MSG_REPORT_REQ) command
provided by the SEV-SNP firmware to query the attestation report.

On success, the snp_report_resp.data will contains the report. The report
format is described in the SEV-SNP specification. See the SEV-SNP specification
for further details.

2.2 SNP_GET_DERIVED_KEY
-----------------------
:Technology: sev-snp
:Type: guest ioctl
:Parameters (in): struct snp_derived_key_req
:Returns (out): struct snp_derived_key_req on success, -negative on error

The SNP_GET_DERIVED_KEY ioctl can be used to get a key derive from a root key.
The derived key can be used by the guest for any purpose, such as sealing keys
or communicating with external entities.

The ioctl uses the SNP_GUEST_REQUEST (MSG_KEY_REQ) command provided by the
SEV-SNP firmware to derive the key. See SEV-SNP specification for further details
on the various fileds passed in the key derivation request.

On success, the snp_derived_key_resp.data will contains the derived key
value.

2.2 SNP_GET_EXT_REPORT
----------------------
:Technology: sev-snp
:Type: guest ioctl
:Parameters (in/out): struct snp_ext_report_req
:Returns (out): struct snp_report_resp on success, -negative on error

The SNP_GET_EXT_REPORT ioctl is similar to the SNP_GET_REPORT. The difference is
related to the additional certificate data that is returned with the report.
The certificate data returned is being provided by the hypervisor through the
SNP_SET_EXT_CONFIG.

The ioctl uses the SNP_GUEST_REQUEST (MSG_REPORT_REQ) command provided by the SEV-SNP
firmware to get the attestation report.

On success, the snp_ext_report_resp.data will contains the attestation report
and snp_ext_report_req.certs_address will contains the certificate blob. If the
length of the blob is lesser than expected then snp_ext_report_req.certs_len will
be updated with the expected value.

See GHCB specification for further detail on how to parse the certificate blob.

2.3 SNP_PLATFORM_STATUS
-----------------------
:Technology: sev-snp
:Type: hypervisor ioctl cmd
:Parameters (in): struct sev_data_snp_platform_status
:Returns (out): 0 on success, -negative on error

The SNP_PLATFORM_STATUS command is used to query the SNP platform status. The
status includes API major, minor version and more. See the SEV-SNP
specification for further details.

2.4 SNP_SET_EXT_CONFIG
----------------------
:Technology: sev-snp
:Type: hypervisor ioctl cmd
:Parameters (in): struct sev_data_snp_ext_config
:Returns (out): 0 on success, -negative on error

The SNP_SET_EXT_CONFIG is used to set the system-wide configuration such as
reported TCB version in the attestation report. The command is similar to
SNP_CONFIG command defined in the SEV-SNP spec. The main difference is the
command also accepts an additional certificate blob defined in the GHCB
specification.

If the certs_address is zero, then previous certificate blob will deleted.
For more information on the certificate blob layout, see the GHCB spec
(extended guest request message).


2.4 SNP_GET_EXT_CONFIG
----------------------
:Technology: sev-snp
:Type: hypervisor ioctl cmd
:Parameters (in): struct sev_data_snp_ext_config
:Returns (out): 0 on success, -negative on error

The SNP_SET_EXT_CONFIG is used to query the system-wide configuration set
through the SNP_SET_EXT_CONFIG.
