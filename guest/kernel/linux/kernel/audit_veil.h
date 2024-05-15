#ifndef __AUDIT_VEIL_H__
#define __AUDIT_VEIL_H__

extern struct svsm_caa *svsm_caa;
bool is_logging_service_enabled(void);
void invoke_logging_service_protection(unsigned long log_msg_va, unsigned long size);

#endif