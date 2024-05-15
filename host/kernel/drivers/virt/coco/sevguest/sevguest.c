// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Secure Encrypted Virtualization Nested Paging (SEV-SNP) guest request interface
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/set_memory.h>
#include <linux/fs.h>
#include <crypto/aead.h>
#include <linux/scatterlist.h>
#include <linux/psp-sev.h>
#include <uapi/linux/sev-guest.h>
#include <uapi/linux/psp-sev.h>

#include <asm/svm.h>
#include <asm/sev.h>

#include "sevguest.h"

#define DEVICE_NAME	"sev-guest"
#define AAD_LEN		48
#define MSG_HDR_VER	1

struct snp_guest_crypto {
	struct crypto_aead *tfm;
	u8 *iv, *authtag;
	int iv_len, a_len;
};

struct snp_guest_dev {
	struct device *dev;
	struct miscdevice misc;

	void *certs_data;
	struct snp_guest_crypto *crypto;
	struct snp_guest_msg *request, *response;
};

static u8 vmpck_id;
static DEFINE_MUTEX(snp_cmd_mutex);

static inline struct snp_guest_dev *to_snp_dev(struct file *file)
{
	struct miscdevice *dev = file->private_data;

	return container_of(dev, struct snp_guest_dev, misc);
}

static struct snp_guest_crypto *init_crypto(struct snp_guest_dev *snp_dev, u8 *key, size_t keylen)
{
	struct snp_guest_crypto *crypto;

	crypto = kzalloc(sizeof(*crypto), GFP_KERNEL_ACCOUNT);
	if (!crypto)
		return NULL;

	crypto->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(crypto->tfm))
		goto e_free;

	if (crypto_aead_setkey(crypto->tfm, key, keylen))
		goto e_free_crypto;

	crypto->iv_len = crypto_aead_ivsize(crypto->tfm);
	if (crypto->iv_len < 12) {
		dev_err(snp_dev->dev, "IV length is less than 12.\n");
		goto e_free_crypto;
	}

	crypto->iv = kmalloc(crypto->iv_len, GFP_KERNEL_ACCOUNT);
	if (!crypto->iv)
		goto e_free_crypto;

	if (crypto_aead_authsize(crypto->tfm) > MAX_AUTHTAG_LEN) {
		if (crypto_aead_setauthsize(crypto->tfm, MAX_AUTHTAG_LEN)) {
			dev_err(snp_dev->dev, "failed to set authsize to %d\n", MAX_AUTHTAG_LEN);
			goto e_free_crypto;
		}
	}

	crypto->a_len = crypto_aead_authsize(crypto->tfm);
	crypto->authtag = kmalloc(crypto->a_len, GFP_KERNEL_ACCOUNT);
	if (!crypto->authtag)
		goto e_free_crypto;

	return crypto;

e_free_crypto:
	crypto_free_aead(crypto->tfm);
e_free:
	kfree(crypto->iv);
	kfree(crypto->authtag);
	kfree(crypto);

	return NULL;
}

static void deinit_crypto(struct snp_guest_crypto *crypto)
{
	crypto_free_aead(crypto->tfm);
	kfree(crypto->iv);
	kfree(crypto->authtag);
	kfree(crypto);
}

static int enc_dec_message(struct snp_guest_crypto *crypto, struct snp_guest_msg *msg,
			   u8 *src_buf, u8 *dst_buf, size_t len, bool enc)
{
	struct snp_guest_msg_hdr *hdr = &msg->hdr;
	struct scatterlist src[3], dst[3];
	DECLARE_CRYPTO_WAIT(wait);
	struct aead_request *req;
	int ret;

	req = aead_request_alloc(crypto->tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	/*
	 * AEAD memory operations:
	 * +------ AAD -------+------- DATA -----+---- AUTHTAG----+
	 * |  msg header      |  plaintext       |  hdr->authtag  |
	 * | bytes 30h - 5Fh  |    or            |                |
	 * |                  |   cipher         |                |
	 * +------------------+------------------+----------------+
	 */
	sg_init_table(src, 3);
	sg_set_buf(&src[0], &hdr->algo, AAD_LEN);
	sg_set_buf(&src[1], src_buf, hdr->msg_sz);
	sg_set_buf(&src[2], hdr->authtag, crypto->a_len);

	sg_init_table(dst, 3);
	sg_set_buf(&dst[0], &hdr->algo, AAD_LEN);
	sg_set_buf(&dst[1], dst_buf, hdr->msg_sz);
	sg_set_buf(&dst[2], hdr->authtag, crypto->a_len);

	aead_request_set_ad(req, AAD_LEN);
	aead_request_set_tfm(req, crypto->tfm);
	aead_request_set_callback(req, 0, crypto_req_done, &wait);

	aead_request_set_crypt(req, src, dst, len, crypto->iv);
	ret = crypto_wait_req(enc ? crypto_aead_encrypt(req) : crypto_aead_decrypt(req), &wait);

	aead_request_free(req);
	return ret;
}

static int __enc_payload(struct snp_guest_dev *snp_dev, struct snp_guest_msg *msg,
			 void *plaintext, size_t len)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	struct snp_guest_msg_hdr *hdr = &msg->hdr;

	memset(crypto->iv, 0, crypto->iv_len);
	memcpy(crypto->iv, &hdr->msg_seqno, sizeof(hdr->msg_seqno));

	return enc_dec_message(crypto, msg, plaintext, msg->payload, len, true);
}

static int dec_payload(struct snp_guest_dev *snp_dev, struct snp_guest_msg *msg,
		       void *plaintext, size_t len)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	struct snp_guest_msg_hdr *hdr = &msg->hdr;

	/* Build IV with response buffer sequence number */
	memset(crypto->iv, 0, crypto->iv_len);
	memcpy(crypto->iv, &hdr->msg_seqno, sizeof(hdr->msg_seqno));

	return enc_dec_message(crypto, msg, msg->payload, plaintext, len, false);
}

static int verify_and_dec_payload(struct snp_guest_dev *snp_dev, void *payload, u32 sz)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	struct snp_guest_msg *resp = snp_dev->response;
	struct snp_guest_msg *req = snp_dev->request;
	struct snp_guest_msg_hdr *req_hdr = &req->hdr;
	struct snp_guest_msg_hdr *resp_hdr = &resp->hdr;

	dev_dbg(snp_dev->dev, "response [seqno %lld type %d version %d sz %d]\n",
		resp_hdr->msg_seqno, resp_hdr->msg_type, resp_hdr->msg_version, resp_hdr->msg_sz);

	/* Verify that the sequence counter is incremented by 1 */
	if (unlikely(resp_hdr->msg_seqno != (req_hdr->msg_seqno + 1)))
		return -EBADMSG;

	/* Verify response message type and version number. */
	if (resp_hdr->msg_type != (req_hdr->msg_type + 1) ||
	    resp_hdr->msg_version != req_hdr->msg_version)
		return -EBADMSG;

	/*
	 * If the message size is greater than our buffer length then return
	 * an error.
	 */
	if (unlikely((resp_hdr->msg_sz + crypto->a_len) > sz))
		return -EBADMSG;

	return dec_payload(snp_dev, resp, payload, resp_hdr->msg_sz + crypto->a_len);
}

static bool enc_payload(struct snp_guest_dev *snp_dev, int version, u8 type,
			void *payload, size_t sz)
{
	struct snp_guest_msg *req = snp_dev->request;
	struct snp_guest_msg_hdr *hdr = &req->hdr;

	memset(req, 0, sizeof(*req));

	hdr->algo = SNP_AEAD_AES_256_GCM;
	hdr->hdr_version = MSG_HDR_VER;
	hdr->hdr_sz = sizeof(*hdr);
	hdr->msg_type = type;
	hdr->msg_version = version;
	hdr->msg_seqno = snp_get_msg_seqno();
	hdr->msg_vmpck = vmpck_id;
	hdr->msg_sz = sz;

	/* Verify the sequence number is non-zero */
	if (!hdr->msg_seqno)
		return -ENOSR;

	dev_dbg(snp_dev->dev, "request [seqno %lld type %d version %d sz %d]\n",
		hdr->msg_seqno, hdr->msg_type, hdr->msg_version, hdr->msg_sz);

	return __enc_payload(snp_dev, req, payload, sz);
}

static int handle_guest_request(struct snp_guest_dev *snp_dev, int version, u8 type,
				void *req_buf, size_t req_sz, void *resp_buf,
				u32 resp_sz, __u64 *fw_err)
{
	struct snp_guest_request_data data;
	unsigned long err;
	int rc;

	memset(snp_dev->response, 0, sizeof(*snp_dev->response));

	/* Encrypt the userspace provided payload */
	rc = enc_payload(snp_dev, version, type, req_buf, req_sz);
	if (rc)
		return rc;

	/* Call firmware to process the request */
	data.req_gpa = __pa(snp_dev->request);
	data.resp_gpa = __pa(snp_dev->response);
	rc = snp_issue_guest_request(SVM_VMGEXIT_GUEST_REQUEST, &data, &err);

	if (fw_err)
		*fw_err = err;

	if (rc)
		return rc;

	return verify_and_dec_payload(snp_dev, resp_buf, resp_sz);
}

static int get_report(struct snp_guest_dev *snp_dev, struct snp_user_guest_request *arg)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	struct snp_report_resp *resp;
	struct snp_report_req req;
	int rc, resp_len;

	if (!arg->req_data || !arg->resp_data)
		return -EINVAL;

	/* Copy the request payload from the userspace */
	if (copy_from_user(&req, (void __user *)arg->req_data, sizeof(req)))
		return -EFAULT;

	/* Message version must be non-zero */
	if (!req.msg_version)
		return -EINVAL;

	/*
	 * The intermediate response buffer is used while decrypting the
	 * response payload. Make sure that it has enough space to cover the
	 * authtag.
	 */
	resp_len = sizeof(resp->data) + crypto->a_len;
	resp = kzalloc(resp_len, GFP_KERNEL_ACCOUNT);
	if (!resp)
		return -ENOMEM;

	/* Issue the command to get the attestation report */
	rc = handle_guest_request(snp_dev, req.msg_version, SNP_MSG_REPORT_REQ,
				  &req.user_data, sizeof(req.user_data), resp->data, resp_len,
				  &arg->fw_err);
	if (rc)
		goto e_free;

	/* Copy the response payload to userspace */
	if (copy_to_user((void __user *)arg->resp_data, resp, sizeof(*resp)))
		rc = -EFAULT;

e_free:
	kfree(resp);
	return rc;
}

static int get_derived_key(struct snp_guest_dev *snp_dev, struct snp_user_guest_request *arg)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	struct snp_derived_key_resp *resp;
	struct snp_derived_key_req req;
	int rc, resp_len;

	if (!arg->req_data || !arg->resp_data)
		return -EINVAL;

	/* Copy the request payload from the userspace */
	if (copy_from_user(&req, (void __user *)arg->req_data, sizeof(req)))
		return -EFAULT;

	/* Message version must be non-zero */
	if (!req.msg_version)
		return -EINVAL;

	/*
	 * The intermediate response buffer is used while decrypting the
	 * response payload. Make sure that it has enough space to cover the
	 * authtag.
	 */
	resp_len = sizeof(resp->data) + crypto->a_len;
	resp = kzalloc(resp_len, GFP_KERNEL_ACCOUNT);
	if (!resp)
		return -ENOMEM;

	/* Issue the command to get the attestation report */
	rc = handle_guest_request(snp_dev, req.msg_version, SNP_MSG_KEY_REQ,
				  &req.data, sizeof(req.data), resp->data, resp_len,
				  &arg->fw_err);
	if (rc)
		goto e_free;

	/* Copy the response payload to userspace */
	if (copy_to_user((void __user *)arg->resp_data, resp, sizeof(*resp)))
		rc = -EFAULT;

e_free:
	kfree(resp);
	return rc;
}

static int get_ext_report(struct snp_guest_dev *snp_dev, struct snp_user_guest_request *arg)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	struct snp_guest_request_data input = {};
	struct snp_ext_report_req req;
	int ret, npages = 0, resp_len;
	struct snp_report_resp *resp;
	struct snp_report_req *rreq;
	unsigned long fw_err = 0;

	if (!arg->req_data || !arg->resp_data)
		return -EINVAL;

	/* Copy the request payload from the userspace */
	if (copy_from_user(&req, (void __user *)arg->req_data, sizeof(req)))
		return -EFAULT;

	rreq = &req.data;

	/* Message version must be non-zero */
	if (!rreq->msg_version)
		return -EINVAL;

	if (req.certs_len) {
		if (req.certs_len > SEV_FW_BLOB_MAX_SIZE ||
		    !IS_ALIGNED(req.certs_len, PAGE_SIZE))
			return -EINVAL;
	}

	if (req.certs_address && req.certs_len) {
		if (!access_ok(req.certs_address, req.certs_len))
			return -EFAULT;

		/*
		 * Initialize the intermediate buffer with all zero's. This buffer
		 * is used in the guest request message to get the certs blob from
		 * the host. If host does not supply any certs in it, then we copy
		 * zeros to indicate that certificate data was not provided.
		 */
		memset(snp_dev->certs_data, 0, req.certs_len);

		input.data_gpa = __pa(snp_dev->certs_data);
		npages = req.certs_len >> PAGE_SHIFT;
	}

	/*
	 * The intermediate response buffer is used while decrypting the
	 * response payload. Make sure that it has enough space to cover the
	 * authtag.
	 */
	resp_len = sizeof(resp->data) + crypto->a_len;
	resp = kzalloc(resp_len, GFP_KERNEL_ACCOUNT);
	if (!resp)
		return -ENOMEM;

	if (copy_from_user(resp, (void __user *)arg->resp_data, sizeof(*resp))) {
		ret = -EFAULT;
		goto e_free;
	}

	/* Encrypt the userspace provided payload */
	ret = enc_payload(snp_dev, rreq->msg_version, SNP_MSG_REPORT_REQ,
			  &rreq->user_data, sizeof(rreq->user_data));
	if (ret)
		goto e_free;

	/* Call firmware to process the request */
	input.req_gpa = __pa(snp_dev->request);
	input.resp_gpa = __pa(snp_dev->response);
	input.data_npages = npages;
	memset(snp_dev->response, 0, sizeof(*snp_dev->response));
	ret = snp_issue_guest_request(SVM_VMGEXIT_EXT_GUEST_REQUEST, &input, &fw_err);

	/* Popogate any firmware error to the userspace */
	arg->fw_err = fw_err;

	/* If certs length is invalid then copy the returned length */
	if (arg->fw_err == SNP_GUEST_REQ_INVALID_LEN) {
		req.certs_len = input.data_npages << PAGE_SHIFT;

		if (copy_to_user((void __user *)arg->req_data, &req, sizeof(req)))
			ret = -EFAULT;

		goto e_free;
	}

	if (ret)
		goto e_free;

	/* Decrypt the response payload */
	ret = verify_and_dec_payload(snp_dev, resp->data, resp_len);
	if (ret)
		goto e_free;

	/* Copy the certificate data blob to userspace */
	if (req.certs_address &&
	    copy_to_user((void __user *)req.certs_address, snp_dev->certs_data,
			 req.certs_len)) {
		ret = -EFAULT;
		goto e_free;
	}

	/* Copy the response payload to userspace */
	if (copy_to_user((void __user *)arg->resp_data, resp, sizeof(*resp)))
		ret = -EFAULT;

e_free:
	kfree(resp);
	return ret;
}

static long snp_guest_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	struct snp_guest_dev *snp_dev = to_snp_dev(file);
	void __user *argp = (void __user *)arg;
	struct snp_user_guest_request input;
	int ret = -ENOTTY;

	if (copy_from_user(&input, argp, sizeof(input)))
		return -EFAULT;

	mutex_lock(&snp_cmd_mutex);

	switch (ioctl) {
	case SNP_GET_REPORT: {
		ret = get_report(snp_dev, &input);
		break;
	}
	case SNP_GET_DERIVED_KEY: {
		ret = get_derived_key(snp_dev, &input);
		break;
	}
	case SNP_GET_EXT_REPORT: {
		ret = get_ext_report(snp_dev, &input);
		break;
	}
	default:
		break;
	}

	mutex_unlock(&snp_cmd_mutex);

	if (copy_to_user(argp, &input, sizeof(input)))
		return -EFAULT;

	return ret;
}

static void free_shared_pages(void *buf, size_t sz)
{
	unsigned int npages = PAGE_ALIGN(sz) >> PAGE_SHIFT;

	/* If fail to restore the encryption mask then leak it. */
	if (set_memory_encrypted((unsigned long)buf, npages))
		return;

	__free_pages(virt_to_page(buf), get_order(sz));
}

static void *alloc_shared_pages(size_t sz)
{
	unsigned int npages = PAGE_ALIGN(sz) >> PAGE_SHIFT;
	struct page *page;
	int ret;

	page = alloc_pages(GFP_KERNEL_ACCOUNT, get_order(sz));
	if (IS_ERR(page))
		return NULL;

	ret = set_memory_decrypted((unsigned long)page_address(page), npages);
	if (ret) {
		__free_pages(page, get_order(sz));
		return NULL;
	}

	return page_address(page);
}

static const struct file_operations snp_guest_fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl = snp_guest_ioctl,
};

static int __init snp_guest_probe(struct platform_device *pdev)
{
	struct snp_guest_platform_data *data;
	struct device *dev = &pdev->dev;
	struct snp_guest_dev *snp_dev;
	struct miscdevice *misc;
	int ret;

	if (!dev->platform_data)
		return -ENODEV;

	data = (struct snp_guest_platform_data *)dev->platform_data;
	vmpck_id = data->vmpck_id;

	snp_dev = devm_kzalloc(&pdev->dev, sizeof(struct snp_guest_dev), GFP_KERNEL);
	if (!snp_dev)
		return -ENOMEM;

	platform_set_drvdata(pdev, snp_dev);
	snp_dev->dev = dev;

	snp_dev->crypto = init_crypto(snp_dev, data->vmpck, sizeof(data->vmpck));
	if (!snp_dev->crypto)
		return -EIO;

	/* Allocate the shared page used for the request and response message. */
	snp_dev->request = alloc_shared_pages(sizeof(struct snp_guest_msg));
	if (IS_ERR(snp_dev->request)) {
		ret = PTR_ERR(snp_dev->request);
		goto e_free_crypto;
	}

	snp_dev->response = alloc_shared_pages(sizeof(struct snp_guest_msg));
	if (IS_ERR(snp_dev->response)) {
		ret = PTR_ERR(snp_dev->response);
		goto e_free_req;
	}

	snp_dev->certs_data = alloc_shared_pages(SEV_FW_BLOB_MAX_SIZE);
	if (IS_ERR(snp_dev->certs_data)) {
		ret = PTR_ERR(snp_dev->certs_data);
		goto e_free_resp;
	}

	misc = &snp_dev->misc;
	misc->minor = MISC_DYNAMIC_MINOR;
	misc->name = DEVICE_NAME;
	misc->fops = &snp_guest_fops;

	return misc_register(misc);

e_free_resp:
	free_shared_pages(snp_dev->response, sizeof(struct snp_guest_msg));

e_free_req:
	free_shared_pages(snp_dev->request, sizeof(struct snp_guest_msg));

e_free_crypto:
	deinit_crypto(snp_dev->crypto);

	return ret;
}

static int __exit snp_guest_remove(struct platform_device *pdev)
{
	struct snp_guest_dev *snp_dev = platform_get_drvdata(pdev);

	free_shared_pages(snp_dev->request, sizeof(struct snp_guest_msg));
	free_shared_pages(snp_dev->response, sizeof(struct snp_guest_msg));
	free_shared_pages(snp_dev->certs_data, SEV_FW_BLOB_MAX_SIZE);
	deinit_crypto(snp_dev->crypto);
	misc_deregister(&snp_dev->misc);

	return 0;
}

static struct platform_driver snp_guest_driver = {
	.remove		= __exit_p(snp_guest_remove),
	.driver		= {
		.name = "snp-guest",
	},
};

module_platform_driver_probe(snp_guest_driver, snp_guest_probe);

MODULE_AUTHOR("Brijesh Singh <brijesh.singh@amd.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("AMD SNP Guest Driver");
