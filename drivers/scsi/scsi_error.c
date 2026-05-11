// SPDX-License-Identifier: GPL-2.0-only
/*
 *  scsi_error.c Copyright (C) 1997 Eric Youngdale
 *
 *  SCSI error/timeout handling
 *      Initial versions: Eric Youngdale.  Based upon conversations with
 *                        Leonard Zubkoff and David Miller at Linux Expo,
 *                        ideas originating from all over the place.
 *
 *	Restructured scsi_unjam_host and associated functions.
 *	September 04, 2002 Mike Anderson (andmike@us.ibm.com)
 *
 *	Forward port of Russell King's (rmk@arm.linux.org.uk) changes and
 *	minor cleanups.
 *	September 30, 2002 Mike Anderson (andmike@us.ibm.com)
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/interrupt.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/jiffies.h>

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_common.h>
#include <scsi/scsi_transport.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/scsi_dh.h>
#include <scsi/scsi_devinfo.h>
#include <scsi/sg.h>

#include "scsi_priv.h"
#include "scsi_logging.h"
#include "scsi_transport_api.h"

#include <trace/events/scsi.h>

#include <linux/unaligned.h>

/*
 * These should *probably* be handled by the host itself.
 * Since it is allowed to sleep, it probably should.
 */
#define BUS_RESET_SETTLE_TIME   (10)
#define HOST_RESET_SETTLE_TIME  (10)

static int scsi_eh_try_stu(struct scsi_cmnd *scmd);
static enum scsi_disposition scsi_try_to_abort_cmd(const struct scsi_host_template *,
						   struct scsi_cmnd *);

void scsi_eh_wakeup(struct Scsi_Host *shost, unsigned int busy)
{
	lockdep_assert_held(shost->host_lock);

	if (busy == shost->host_failed) {
		trace_scsi_eh_wakeup(shost);
		wake_up_process(shost->ehandler);
		SCSI_LOG_ERROR_RECOVERY(5, shost_printk(KERN_INFO, shost,
			"Waking error handler thread\n"));
	}
}

/**
 * scsi_schedule_eh - schedule EH for SCSI host
 * @shost:	SCSI host to invoke error handling on.
 *
 * Schedule SCSI EH without scmd.
 */
void scsi_schedule_eh(struct Scsi_Host *shost)
{
	unsigned long flags;

	spin_lock_irqsave(shost->host_lock, flags);

	if (scsi_host_set_state(shost, SHOST_RECOVERY) == 0 ||
	    scsi_host_set_state(shost, SHOST_CANCEL_RECOVERY) == 0) {
		shost->host_eh_scheduled++;
		scsi_eh_wakeup(shost, scsi_host_busy(shost));
	}

	spin_unlock_irqrestore(shost->host_lock, flags);
}
EXPORT_SYMBOL_GPL(scsi_schedule_eh);

static int scsi_host_eh_past_deadline(struct Scsi_Host *shost)
{
	if (!shost->last_reset || shost->eh_deadline == -1)
		return 0;

	/*
	 * 32bit accesses are guaranteed to be atomic
	 * (on all supported architectures), so instead
	 * of using a spinlock we can as well double check
	 * if eh_deadline has been set to 'off' during the
	 * time_before call.
	 */
	if (time_before(jiffies, shost->last_reset + shost->eh_deadline) &&
	    shost->eh_deadline > -1)
		return 0;

	return 1;
}

static bool scsi_cmd_retry_allowed(struct scsi_cmnd *cmd)
{
	if (cmd->allowed == SCSI_CMD_RETRIES_NO_LIMIT)
		return true;

	return ++cmd->retries <= cmd->allowed;
}

static bool scsi_eh_should_retry_cmd(struct scsi_cmnd *cmd)
{
	struct scsi_device *sdev = cmd->device;
	struct Scsi_Host *host = sdev->host;

	if (host->hostt->eh_should_retry_cmd)
		return  host->hostt->eh_should_retry_cmd(cmd);

	return true;
}

/**
 * scmd_eh_abort_handler - Handle command aborts
 * @work:	command to be aborted.
 *
 * Note: this function must be called only for a command that has timed out.
 * Because the block layer marks a request as complete before it calls
 * scsi_timeout(), a .scsi_done() call from the LLD for a command that has
 * timed out do not have any effect. Hence it is safe to call
 * scsi_finish_command() from this function.
 */
void
scmd_eh_abort_handler(struct work_struct *work)
{
	struct scsi_cmnd *scmd =
		container_of(work, struct scsi_cmnd, abort_work.work);
	struct scsi_device *sdev = scmd->device;
	struct Scsi_Host *shost = sdev->host;
	enum scsi_disposition rtn;
	unsigned long flags;

	if (scsi_host_eh_past_deadline(shost)) {
		SCSI_LOG_ERROR_RECOVERY(3,
			scmd_printk(KERN_INFO, scmd,
				    "eh timeout, not aborting\n"));
		goto out;
	}

	SCSI_LOG_ERROR_RECOVERY(3,
			scmd_printk(KERN_INFO, scmd,
				    "aborting command\n"));
	rtn = scsi_try_to_abort_cmd(shost->hostt, scmd);
	if (rtn != SUCCESS) {
		SCSI_LOG_ERROR_RECOVERY(3,
			scmd_printk(KERN_INFO, scmd,
				    "cmd abort %s\n",
				    (rtn == FAST_IO_FAIL) ?
				    "not send" : "failed"));
		goto out;
	}
	set_host_byte(scmd, DID_TIME_OUT);
	if (scsi_host_eh_past_deadline(shost)) {
		SCSI_LOG_ERROR_RECOVERY(3,
			scmd_printk(KERN_INFO, scmd,
				    "eh timeout, not retrying "
				    "aborted command\n"));
		goto out;
	}

	spin_lock_irqsave(shost->host_lock, flags);
	list_del_init(&scmd->eh_entry);

	/*
	 * If the abort succeeds, and there is no further
	 * EH action, clear the ->last_reset time.
	 */
	if (list_empty(&shost->eh_abort_list) &&
	    list_empty(&shost->eh_cmd_q))
		if (shost->eh_deadline != -1)
			shost->last_reset = 0;

	spin_unlock_irqrestore(shost->host_lock, flags);

	if (!scsi_noretry_cmd(scmd) &&
	    scsi_cmd_retry_allowed(scmd) &&
	    scsi_eh_should_retry_cmd(scmd)) {
		SCSI_LOG_ERROR_RECOVERY(3,
			scmd_printk(KERN_WARNING, scmd,
				    "retry aborted command\n"));
		scsi_queue_insert(scmd, SCSI_MLQUEUE_EH_RETRY);
	} else {
		SCSI_LOG_ERROR_RECOVERY(3,
			scmd_printk(KERN_WARNING, scmd,
				    "finish aborted command\n"));
		scsi_finish_command(scmd);
	}
	return;

out:
	spin_lock_irqsave(shost->host_lock, flags);
	list_del_init(&scmd->eh_entry);
	spin_unlock_irqrestore(shost->host_lock, flags);

	if (shost->eh_mode == SCSI_EH_MODE_HOST)
		scsi_eh_scmd_add(scmd);
	else
		scsi_eh_scmd_add_to_sdev(scmd);
}

/**
 * scsi_abort_command - schedule a command abort
 * @scmd:	scmd to abort.
 *
 * We only need to abort commands after a command timeout
 */
static int
scsi_abort_command(struct scsi_cmnd *scmd)
{
	struct scsi_device *sdev = scmd->device;
	struct Scsi_Host *shost = sdev->host;
	unsigned long flags;

	if (!shost->hostt->eh_abort_handler) {
		/* No abort handler, fail command directly */
		return FAILED;
	}

	if (scmd->eh_eflags & SCSI_EH_ABORT_SCHEDULED) {
		/*
		 * Retry after abort failed, escalate to next level.
		 */
		SCSI_LOG_ERROR_RECOVERY(3,
			scmd_printk(KERN_INFO, scmd,
				    "previous abort failed\n"));
		BUG_ON(delayed_work_pending(&scmd->abort_work));
		return FAILED;
	}

	spin_lock_irqsave(shost->host_lock, flags);
	if (shost->eh_deadline != -1 && !shost->last_reset)
		shost->last_reset = jiffies;
	BUG_ON(!list_empty(&scmd->eh_entry));
	list_add_tail(&scmd->eh_entry, &shost->eh_abort_list);
	spin_unlock_irqrestore(shost->host_lock, flags);

	scmd->eh_eflags |= SCSI_EH_ABORT_SCHEDULED;
	SCSI_LOG_ERROR_RECOVERY(3,
		scmd_printk(KERN_INFO, scmd, "abort scheduled\n"));
	queue_delayed_work(shost->tmf_work_q, &scmd->abort_work, HZ / 100);
	return SUCCESS;
}

/**
 * scsi_eh_reset - call into ->eh_action to reset internal counters
 * @scmd:	scmd to run eh on.
 *
 * The scsi driver might be carrying internal state about the
 * devices, so we need to call into the driver to reset the
 * internal state once the error handler is started.
 */
static void scsi_eh_reset(struct scsi_cmnd *scmd)
{
	if (!blk_rq_is_passthrough(scsi_cmd_to_rq(scmd))) {
		struct scsi_driver *sdrv = scsi_cmd_to_driver(scmd);
		if (sdrv->eh_reset)
			sdrv->eh_reset(scmd);
	}
}

static void scsi_eh_inc_host_failed(struct rcu_head *head)
{
	struct scsi_cmnd *scmd = container_of(head, typeof(*scmd), rcu);
	struct Scsi_Host *shost = scmd->device->host;
	unsigned int busy = scsi_host_busy(shost);
	unsigned long flags;

	spin_lock_irqsave(shost->host_lock, flags);
	shost->host_failed++;
	scsi_eh_wakeup(shost, busy);
	spin_unlock_irqrestore(shost->host_lock, flags);
}

/**
 * scsi_eh_scmd_add - add scsi cmd to error handling.
 * @scmd:	scmd to run eh on.
 */
void scsi_eh_scmd_add(struct scsi_cmnd *scmd)
{
	struct Scsi_Host *shost = scmd->device->host;
	unsigned long flags;
	int ret;

	WARN_ON_ONCE(!shost->ehandler);
	WARN_ON_ONCE(!test_bit(SCMD_STATE_INFLIGHT, &scmd->state));

	if (shost->shost_state != SHOST_RECOVERY)
		pr_err("%s linux-EH/deadline-EH: set host to SHOST_RECOVERY!\n", __func__);

	spin_lock_irqsave(shost->host_lock, flags);
	if (scsi_host_set_state(shost, SHOST_RECOVERY)) {
		ret = scsi_host_set_state(shost, SHOST_CANCEL_RECOVERY);
		WARN_ON_ONCE(ret);
	}
	if (shost->eh_deadline != -1 && !shost->last_reset)
		shost->last_reset = jiffies;

	scsi_eh_reset(scmd);
	list_add_tail(&scmd->eh_entry, &shost->eh_cmd_q);
	spin_unlock_irqrestore(shost->host_lock, flags);
	/*
	 * Ensure that all tasks observe the host state change before the
	 * host_failed change.
	 */
	call_rcu_hurry(&scmd->rcu, scsi_eh_inc_host_failed);
}

































/* 关键 debug 函数 */
static inline const char *scsi_eh_state_name(enum scsi_eh_state state)
{
	switch (state) {
	case EH_NORMAL: return "EH_NORMAL";
	case EH_QUIESCE: return "EH_QUIESCE";
	case EH_SCHEDULED: return "EH_SCHEDULED";
	case EH_RUNNING: return "EH_RUNNING";
	default: return "EH_UNKNOWN";
	}
}

static inline const char *post_fault_action_name(enum post_fault_action pfaction)
{
	switch (pfaction) {
	case OFFLINE_POST_FAULT: return "OFFLINE_POST_FAULT";
	case UPGRADE_TO_TARGET_RESET_POST_FAULT: return "UPGRADE_TO_TARGET_RESET_POST_FAULT";
	case UPGRADE_TO_BUS_RESET_POST_FAULT: return "UPGRADE_TO_BUS_RESET_POST_FAULT";
	case UPGRADE_TO_HOST_RESET_POST_FAULT: return "UPGRADE_TO_HOST_RESET_POST_FAULT";
	default: return "EH_UNKNOWN";
	}
}

static inline const char *scsi_eh_reset_level_name(enum scsi_eh_reset_level level)
{
	switch (level) {
	case EH_SDEV: return "EH_SDEV";
	case EH_STARGET: return "EH_STARGET";
	case EH_SCHANNEL: return "EH_SCHANNEL";
	case EH_SHOST: return "EH_SHOST";
	default: return "EH_UNKNOWN";
	}
}

static inline const char *scsi_device_show_state(enum scsi_device_state state)
{
	switch (state) {
	case SDEV_CREATED: return "SDEV_CREATED";
	case SDEV_RUNNING: return "SDEV_RUNNING";
	case SDEV_CANCEL: return "SDEV_CANCEL";
	case SDEV_DEL: return "SDEV_DEL";
	case SDEV_QUIESCE: return "SDEV_QUIESCE";
	case SDEV_OFFLINE: return "SDEV_OFFLINE";
	case SDEV_TRANSPORT_OFFLINE: return "SDEV_TRANSPORT_OFFLINE";
	case SDEV_BLOCK: return "SDEV_BLOCK";
	case SDEV_CREATED_BLOCK: return "SDEV_CREATED_BLOCK";
	default: return "EH_UNKNOWN";
	}
}

static char sdev_locate[64] = {0};
static char starget_locate[64] = {0};
static char schannel_locate[64] = {0};
static char shost_locate[64] = {0};

static char* scsi_eh_locate_sdev(struct scsi_device *sdev)
{
    memset(sdev_locate, 0, sizeof(sdev_locate));

    snprintf(sdev_locate, sizeof(sdev_locate), "sdev(%d:%d:%d:%d)",
             sdev->host->unique_id,
             sdev->channel,
             sdev->sdev_target->id,
             sdev->id);

    return sdev_locate;
}

static char* scsi_eh_locate_starget(struct scsi_target *starget)
{
    memset(starget_locate, 0, sizeof(starget_locate));

    snprintf(starget_locate, sizeof(starget_locate), "starget(%d:%d:%d)",
             starget->host->unique_id,
             starget->channel,
             starget->id);

    return starget_locate;
}

static char* scsi_eh_locate_schannel(struct scsi_channel *schannel)
{
    memset(schannel_locate, 0, sizeof(schannel_locate));

    snprintf(schannel_locate, sizeof(schannel_locate), "schannel(%d:%d)",
             schannel->host->unique_id,
             schannel->channel);

    return schannel_locate;
}

static char* scsi_eh_locate_shost(struct Scsi_Host *shost)
{
    memset(shost_locate, 0, sizeof(shost_locate));

    snprintf(shost_locate, sizeof(shost_locate), "shost(%d)",
             shost->unique_id);

    return shost_locate;
}

static inline const char *scsi_eh_state_name(enum scsi_eh_state state);
static inline const char *post_fault_action_name(enum post_fault_action pfaction);
static inline const char *scsi_eh_reset_level_name(enum scsi_eh_reset_level level);
static inline const char *scsi_device_show_state(enum scsi_device_state state);

static void eh_host_statue_show(struct scsi_device *sdev)
{
	struct Scsi_Host *shost = sdev->host;
	// struct scsi_target *starget = sdev->sdev_target;
	// struct scsi_channel *schannel = sdev->schannel;
	struct scsi_device *_sdev;
	struct scsi_target *_starget;
	struct scsi_channel *_schannel;

	pr_err("\n");
	pr_err("\n");
	pr_err("\n");
	list_for_each_entry(_schannel, &shost->schannels, same_host_siblings) {
		list_for_each_entry(_starget, &_schannel->targets, same_channel_siblings) {
			list_for_each_entry(_sdev, &_starget->devices, same_target_siblings) {
				pr_err("%s: %s(%s) busy=%d,state=%s,eh_state=%s,pfaction=%s,eh_queued=%d,idle=%d\n",
					 __func__,
					 _sdev->vendor,
					 scsi_eh_locate_sdev(_sdev),
					 scsi_device_busy(_sdev),
					 scsi_device_show_state(_sdev->sdev_state),
					 scsi_eh_state_name(atomic_read(&_sdev->eh_sdev_state)),
					 post_fault_action_name(_sdev->pfaction),
					 _sdev->eh_queued,
					 _sdev->idle);
			}
			pr_err("%s: %s sdev_failed=%d,total_sdevs=%d,eh_state=%s,pfaction=%s,eh_queued=%d\n",
					 __func__,
					 scsi_eh_locate_starget(_starget),
					 _starget->sdev_failed,
					 _starget->total_sdevs,
					 scsi_eh_state_name(atomic_read(&_starget->eh_starget_state)),
					 post_fault_action_name(_starget->pfaction),
					 _starget->eh_queued);
		}
		pr_err("%s: %s starget_failed=%d,total_stargets=%d,eh_state=%s,pfaction=%s,eh_queued=%d\n",
				 __func__,
				 scsi_eh_locate_schannel(_schannel),
				 _schannel->starget_failed,
				 _schannel->total_stargets,
				 scsi_eh_state_name(atomic_read(&_schannel->eh_schannel_state)),
				 post_fault_action_name(_schannel->pfaction),
				 _schannel->eh_queued);
	}

	pr_err("%s: %s schannel_failed=%d,total_channels=%d,eh_state=%s,pfaction=%s\n",
			__func__,
			scsi_eh_locate_shost(shost),
			shost->schannel_failed,
			shost->total_channels,
			scsi_eh_state_name(atomic_read(&shost->eh_shost_state)),
			post_fault_action_name(shost->pfaction));
	pr_err("\n");
	pr_err("\n");
	pr_err("\n");

	return;
}

static inline bool eh_scsi_device_is_busy(struct scsi_device *sdev)
{
	if (scsi_device_busy(sdev) >= sdev->queue_depth)
		return true;
	if (atomic_read(&sdev->device_blocked) > 0)
		return true;
	return false;
}

#define FP_SUBMIT_WINDOW      (HZ / 5)   /* 200ms */
#define FP_COMPLETE_TIMEOUT   (2 * HZ)   /* 2s */

/* 
 * 该函数能够断定 sdev 有 I/O 且异常
 * 返回 true 说明 sdev 无法继续向前推进了
 */
static bool sdev_forward_progress_lost(struct scsi_device *sdev)
{
	int inflight;
	inflight = scsi_device_busy(sdev);
	if (inflight == 0)
		return false;

	if (!eh_scsi_device_is_busy(sdev) && time_after(jiffies, sdev->last_submit_jiffies + FP_SUBMIT_WINDOW))
		return false;

	if (time_after(jiffies, sdev->last_complete_jiffies + FP_COMPLETE_TIMEOUT))
		return true;   /* forward progress lost */

	return false;
}

/* 指定 sdev 是否健康，这个是最底层的检查方式，而且结果是确定性的，只是需要继续证明 */
static enum sentity_state sdev_is_healthy(struct scsi_device *sdev)
{
	/* 1. 优先检查状态。如果状态已经改变了，那 GG 了；但是该状态无法检查正在 GG 的 sdev，所以就有了下面的步骤 */
	if (atomic_read(&sdev->eh_sdev_state))
		return SENTITY_DEV_FAULT; /* GG */

	/* 2. 再检查是否有活跃的 I/O */
    	if (!scsi_device_busy(sdev))
        	return SENTITY_DEV_IDLE; /* idle */

	/* 3. 根据之前埋下的钩子判断是否有I/O正常返回 */
	if (sdev_forward_progress_lost(sdev))
		return SENTITY_DEV_FAULT; /* GG */

	/* 一切无碍后返回正常运行 */
	return SENTITY_DEV_RUNNING; /* running */
}

/* 
 * 指定 target 是否健康，遍历 sdev 调用 sdev 是否健康的方法
 * 这里第一次 involve 遍历操作
 * 其实只有这几种可能性（不考虑 sdev 的热拔插，即不考虑 starget->devices 的新增），我期待的返回状态
 * 只需要返回2个状态足矣（主要是2个状态）
 */
static enum sentity_state target_is_healthy(struct scsi_target *starget)
{
	struct scsi_device *sdev;

	/* 1. 先检查 EH 相关的状态；如果状态已经 GG 了，那就 GG；如果该 target 还在 GG 的路上，就依赖下面 */
	if (atomic_read(&starget->eh_starget_state))
		return SENTITY_FAULT;

	/* 2. 再通过遍历的方式确定漏网之鱼 */
	list_for_each_entry(sdev, &starget->devices, same_target_siblings) {
		if (sdev_is_healthy(sdev) == SENTITY_DEV_RUNNING)
			return SENTITY_ANY_RUNNING;
	}

	return SENTITY_UNCERTAIN;
}

/* 
 * 指定 channel 是否正常，遍历 channel 下有无正常的 target，实际操作要遍历 host 下的所有 sdev
 * 引入了 2 重遍历，考虑该方式与直接遍历 host，判断 target id 的方式哪个更好
 */
static enum sentity_state channel_is_healthy(struct scsi_channel *schannel)
{
	struct scsi_target *starget;

	if (atomic_read(&schannel->eh_schannel_state))
		return SENTITY_FAULT;

	list_for_each_entry(starget, &schannel->targets, same_channel_siblings)
		if (target_is_healthy(starget) == SENTITY_ANY_RUNNING)
			return SENTITY_ANY_RUNNING;

	return SENTITY_UNCERTAIN;
}

/*
 * 判断 host 是否有异常的 channel
 * 引入了 3 重遍历
 */
static enum sentity_state shost_is_healthy(struct Scsi_Host *shost)
{
	struct scsi_channel *schannel;

	if (atomic_read(&shost->eh_shost_state))
		return SENTITY_FAULT;

	if (scsi_host_in_recovery(shost))
		return SENTITY_FAULT;

	list_for_each_entry(schannel, &shost->schannels, same_host_siblings) {
		if (channel_is_healthy(schannel) == SENTITY_ANY_RUNNING)
			return SENTITY_ANY_RUNNING;
	}

	return SENTITY_UNCERTAIN;
}

static bool eh_scan_target_firstly(struct scsi_target *starget)
{
	struct scsi_device *sdev;
	struct scsi_channel *schannel = starget->schannel;
	bool need_wait = false;

	/* 
	* 遍历全部 sdev
	*  1. 将其从 host 上拿下来，因为目前错误处理粒度是 target
	*  2. 阻塞所有 sdev 的 I/O
	*/
	list_for_each_entry(sdev, &starget->devices, same_target_siblings) {
		if (sdev->eh_queued == true) {
			list_del_init(&sdev->sdev_eh_siblings);
			sdev->eh_queued = false;
		}

		if (atomic_read(&sdev->eh_sdev_state) == EH_SCHEDULED)
			continue;

		if (atomic_read(&sdev->eh_sdev_state) == EH_NORMAL) {
			atomic_set(&sdev->eh_sdev_state, EH_QUIESCE);
			sdev->is_worker_waiting = true;
		}

		mutex_lock(&sdev->state_mutex);
		scsi_device_set_state(sdev, SDEV_BLOCK);
		mutex_unlock(&sdev->state_mutex);

		if (scsi_device_busy(sdev) == sdev->scmd_failed) {
			atomic_set(&sdev->eh_sdev_state, EH_SCHEDULED);
			starget->sdev_failed++;
			if (sdev->scmd_failed == 0)
				sdev->idle = true;
			pr_err("%s: %s failed, starget->sdev_failed=%d, sdev->scmd_failed=%d\n",
				__func__, scsi_eh_locate_sdev(sdev), starget->sdev_failed, sdev->scmd_failed);
		} else {
			need_wait = true;
		}
	}

	/* 保证调用该函数之前，target 一定已经出于 EH_QUIESCE 状态 */
	if (starget->total_sdevs == starget->sdev_failed && (atomic_read(&starget->eh_starget_state) == EH_QUIESCE)) {
		/* 当 target 下面所有的 sdev 都 GG 的时候，target也应该迭代到 EH_SCHEDULED */
		atomic_set(&starget->eh_starget_state, EH_SCHEDULED);
		// channel 的 target failed++
		schannel->starget_failed++; /* 但是这里无法保证 channel 处于 EH_QUIESCE，所以无动作 */
		pr_err("%s: %s failed, schannel->starget_failed=%d\n",
			 __func__, scsi_eh_locate_starget(starget), schannel->starget_failed);
	}

	pr_err("%s %s need wait(%d)\n", __func__, scsi_eh_locate_starget(starget), need_wait);

	return need_wait;
}

static bool eh_scan_target_no_firstly(struct scsi_target *starget)
{
	struct scsi_device *sdev;
	struct scsi_channel *schannel = starget->schannel;
	bool need_wait = false;

	list_for_each_entry(sdev, &starget->devices, same_target_siblings) {
		if (atomic_read(&sdev->eh_sdev_state) == EH_SCHEDULED)
			continue;

		if (scsi_device_busy(sdev) == sdev->scmd_failed) {
			atomic_set(&sdev->eh_sdev_state, EH_SCHEDULED);
			starget->sdev_failed++;
			if (sdev->scmd_failed == 0)
				sdev->idle = true;
			pr_err("%s: %s failed, starget->sdev_failed=%d, sdev->scmd_failed=%d\n",
				 __func__, scsi_eh_locate_sdev(sdev), starget->sdev_failed, sdev->scmd_failed);
		} else {
			need_wait = true;
		}
	}

	/* 保证调用该函数之前，target 一定已经出于 EH_QUIESCE 状态 */
	if (starget->total_sdevs == starget->sdev_failed && (atomic_read(&starget->eh_starget_state) == EH_QUIESCE)) {
		/* 当 target 下面所有的 sdev 都 GG 的时候，target也应该迭代到 EH_SCHEDULED */
		atomic_set(&starget->eh_starget_state, EH_SCHEDULED);
		// channel 的 target failed++
		schannel->starget_failed++; /* 但是这里无法保证 channel 处于 EH_QUIESCE，所以无动作 */
		pr_err("%s: %s failed, schannel->starget_failed=%d\n",
			 __func__, scsi_eh_locate_starget(starget), schannel->starget_failed);
	}

	pr_err("%s %s need wait(%d)\n", __func__, scsi_eh_locate_starget(starget), need_wait);

	return need_wait;
}

/*
 * 时间复杂度是 O(N)，调用位置均为 check point
 * 1. 能跑到这里来，就说明无论如何，得要冻结 target，但是冻结的过程本身是需要时间的（等待正常 I/O 的返回，这是同步的方式，是否能换成异步的形式呢呢？）
 *  1. 如果需要等待，则直接退出工作队列；满足条件再触发 checkpoint 的执行
 * 2. 调用该函数的原因是
 *  1. target 没有 running 的 I/O，无法判断健康状况，可以直接 reset，所以就来尝试 target reset
 *  2. host 没有 sdev 对应的 reset 方法，一有点风吹草动，就需要升级到 target reset
 * 3. 考虑一下返回值，无非就是 done 和need wait
 *  1. DONE，可以继续向下执行
 *  2. NEED_WAIT_IO_DONE，直接 return，结束这个work，等待满足条件后重新入队
 * 4. 这里可能会多次进入，所以 target 本身是需要状态来维护的，target 本身需要状态机
 * 5. 主要逻辑：
 *  1. 如果还有新的 I/O 在ing，则首先阻止新 I/O 的下发
 *  2. 如果需要等待 I/O 完成或超时，则直接返回 NEED_WAIT_IO_DONE
 *   1. 如果是等待超时的话，迟早都会调用到
 *   2. 如果是正常 I/O 完成的话，该如何触发呢？
 *    1. 假设 target 有 3 个 sdev A，B，C，D (IDLE)；A 挂了之后，且 A 功德圆满 GG 后，我来尝试升级到 target reset
 *    2. 正常来讲，B，C 的 I/O 结束后是不会触发到 checkpoint 的，这里应该如何触发？
 *    3. 第一次进入后会判断 if (busy == failed)
 * 6. 谁会调用 update_eh_field_to_target
 *  1. 只有 checkpoint 会发起调用
 *  2. 目的是将 target 冻结。状态什么的都改掉
 *  3. 进入的时候可能会面临多种可能性
 *   1. 除了异常的 sdev，压根没有其它 sdev
 *    1. 先把 target 状态变了，再把 target 挂入到 host 的异常 list
 *    2. 遍历 sdev，只有这一个
 *    3. 最后能够返回 DONE，直接就把 eh 拉起来了
 *   2. 除了异常的 sdev，其它 sdev 都在IDEL
 *    1. 先把 target 状态变了，再把 target 挂入到 host 的异常 list
 *    2. 遍历 sdev，遍历到这个异常的直接continue掉了；遍历到 IDLE 的，直接修改这个 IDLE 设备的状态且 starget->sdev_failed++;
 *    3. 最后能够返回 DONE，直接就把 eh 拉起来了
 *   3. 除了异常的 sdev，其它 sdev 也在 GG 的路上
 *    1. 这种最后返回 NEED_WAIT_IO_DONE，等待 sdev 真的 GG 了
 *   4. 除了异常的 sdev，其它 sdev 都在正常 I/O
 *    1. 先把他的 I/O 停了
 *    2. 返回 NEED_WAIT_IO_DONE，这个 worker 的使命就结束了
 *     1. 好，问题来了。这个 I/O 完成后，怎么再把这个 checkpoint 拉起来，就现状来看，是没有机制把他拉起来的。目前看起来是自己把自己再次入队是最方便的，定时 check
 *   5. 除了异常的 sdev，其它 sdev 涵盖 2/3/4 的可能性
 *    1. 以最难得为准，在该例中，就需要定时重新入队来检查
 * 7. 统一一下，只要是返回了 need wait，就都自己重新入队自己   
 */
static enum eh_update_result update_eh_field_to_target(struct scsi_target *starget)
{
	struct Scsi_Host *shost = starget->host;
	struct scsi_channel *schannel = starget->schannel;
	bool need_wait = false;

	if (atomic_read(&starget->eh_starget_state) == EH_SCHEDULED || atomic_read(&starget->eh_starget_state) == EH_RUNNING) /* 可以直接升级到 target，如果已经running了，reset 线程自然会拦截 */
		return DONE;

	if (atomic_read(&starget->eh_starget_state) == EH_NORMAL) { /* 第一次进入 */
		atomic_set(&starget->eh_starget_state, EH_QUIESCE); /* 修改 target 状态 */
		list_add_tail(&starget->starget_eh_siblings, &shost->eh_starget); /* 将该 target 挂到 host 上 */
		starget->eh_queued = true;
		need_wait = eh_scan_target_firstly(starget);
	} else { /* 并非第一次进入，即 atomic_read(&starget->eh_starget_state) == EH_QUIESCE，说明之前来过，但是 eh_to_target done 的条件不满足 */
		need_wait = eh_scan_target_no_firstly(starget);
	}

	if (starget->total_sdevs == starget->sdev_failed && (atomic_read(&starget->eh_starget_state) == EH_QUIESCE)) {
		/* 当 target 下面所有的 sdev 都 GG 的时候，target也应该迭代到 EH_SCHEDULED */
		atomic_set(&starget->eh_starget_state, EH_SCHEDULED);
		/* channel 的 target failed++ */
		schannel->starget_failed++;
		pr_err("%s: %s failed, schannel->starget_failed=%d\n",
			 __func__, scsi_eh_locate_starget(starget), schannel->starget_failed);
	}

	pr_err("%s %s need wait(%d)\n", __func__, scsi_eh_locate_starget(starget), need_wait);

	if (need_wait)
		return NEED_WAIT_IO_DONE;
	else
		return DONE;
}

static bool eh_scan_channel_firstly(struct scsi_channel *schannel)
{
	struct scsi_target *starget;
	struct Scsi_Host *shost = schannel->host;
	bool need_wait = false;

	/* 
	* 遍历全部 target
	*  1. 将其从 host 上拿下来，因为目前错误处理粒度是 channel
	*  2. 阻塞所有 target 下所有 sdev 的 I/O
	*/
	/* 遍历channel下的所有target，再遍历target下的全部 sdev，TODO 这个开销看着有点难受哦，一直在遍历 */
	list_for_each_entry(starget, &schannel->targets, same_channel_siblings) { /* 遍历 channel 下的 target */
		if (starget->eh_queued == true) {
			list_del_init(&starget->starget_eh_siblings);
			starget->eh_queued = false;
		}

		if (atomic_read(&starget->eh_starget_state) == EH_SCHEDULED)
			continue;

		if (atomic_read(&starget->eh_starget_state) == EH_NORMAL)
			atomic_set(&starget->eh_starget_state, EH_QUIESCE);

		if (eh_scan_target_firstly(starget))
			need_wait = true;
	}

	if (schannel->total_stargets == schannel->starget_failed && (atomic_read(&schannel->eh_schannel_state) == EH_QUIESCE)) {
		/* 当 channel 下面所有的 target 都是 EH_SCHEDULED 的时候，channel 也应该迭代到 EH_SCHEDULED */
		atomic_set(&schannel->eh_schannel_state, EH_SCHEDULED);
		/* host 的 host failed++ */
		shost->schannel_failed++;
		pr_err("%s: %s failed, schannel->starget_failed=%d\n",
			 __func__, scsi_eh_locate_schannel(schannel), shost->schannel_failed);
	}

	pr_err("%s %s need wait(%d)\n", __func__, scsi_eh_locate_schannel(schannel), need_wait);

	return need_wait;
}

static bool eh_scan_channel_no_firstly(struct scsi_channel *schannel)
{
	struct scsi_target *starget;
	struct Scsi_Host *shost = schannel->host;
	bool need_wait = false;

	list_for_each_entry(starget, &schannel->targets, same_channel_siblings) {
		if (atomic_read(&starget->eh_starget_state) == EH_SCHEDULED)
			continue;

		if (eh_scan_target_no_firstly(starget))
			need_wait = true;
	}

	if (schannel->total_stargets == schannel->starget_failed && (atomic_read(&schannel->eh_schannel_state) == EH_QUIESCE)) {
		/* 当 channel 下面所有的 target 都是 EH_SCHEDULED 的时候，channel 也应该迭代到 EH_SCHEDULED */
		atomic_set(&schannel->eh_schannel_state, EH_SCHEDULED);
		/* host 的 host failed++ */
		shost->schannel_failed++;
		pr_err("%s: %s failed, schannel->starget_failed=%d\n",
			 __func__, scsi_eh_locate_schannel(schannel), shost->schannel_failed);
	}

	pr_err("%s %s need wait(%d)\n", __func__, scsi_eh_locate_schannel(schannel), need_wait);

	return need_wait;
}

/*
 * 调用位置均位于 check point，参考 update_eh_field_to_target
 */
static enum eh_update_result update_eh_field_to_channel(struct scsi_channel *schannel)
{
	struct Scsi_Host *shost = schannel->host;
	bool need_wait = false;

	if (atomic_read(&schannel->eh_schannel_state) == EH_SCHEDULED || atomic_read(&schannel->eh_schannel_state) == EH_RUNNING)
		return DONE;

	if (atomic_read(&schannel->eh_schannel_state) == EH_NORMAL) {
		atomic_set(&schannel->eh_schannel_state, EH_QUIESCE); /* 修改 channel 状态 */
		list_add_tail(&schannel->schannel_eh_siblings, &shost->eh_schannel); /* 将该 channel 挂到 host 上 */
		schannel->eh_queued = true;
		pr_err("%s queued %s\n", __func__, scsi_eh_locate_schannel(schannel));
		need_wait = eh_scan_channel_firstly(schannel);
	} else { /* 并非第一次进入，即 atomic_read(&schannel->eh_schannel_state) == EH_QUIESCE */
		need_wait = eh_scan_channel_no_firstly(schannel);
	}

	if (schannel->total_stargets == schannel->starget_failed && (atomic_read(&schannel->eh_schannel_state) == EH_QUIESCE)) {
		/* 当 channel 下面所有的 target 都是 EH_SCHEDULED 的时候，channel 也应该迭代到 EH_SCHEDULED */
		atomic_set(&schannel->eh_schannel_state, EH_SCHEDULED);
		shost->schannel_failed++; /* host 的 host failed++ */
		pr_err("%s: %s failed, schannel->starget_failed=%d\n",
			 __func__, scsi_eh_locate_schannel(schannel), shost->schannel_failed);
	}

	pr_err("%s %s need wait(%d)\n", __func__, scsi_eh_locate_schannel(schannel), need_wait);

	if (need_wait)
		return NEED_WAIT_IO_DONE;
	else
		return DONE;
}

/*
 * 调用位置均位于 check point，参考 update_eh_field_to_target
 */
static enum eh_update_result update_eh_field_to_host(struct Scsi_Host *shost)
{
	struct scsi_channel *schannel;
	bool need_wait = false;
	unsigned long flags;

	if (atomic_read(&shost->eh_shost_state) == EH_SCHEDULED || atomic_read(&shost->eh_shost_state) == EH_RUNNING)
		return DONE;

	/* 先阻塞 host */
	spin_lock_irqsave(shost->host_lock, flags);
	scsi_host_set_state(shost, SHOST_RECOVERY);
	spin_unlock_irqrestore(shost->host_lock, flags);

	if (atomic_read(&shost->eh_shost_state) == EH_NORMAL) {
		atomic_set(&shost->eh_shost_state, EH_QUIESCE);
		// eh 域 是否在 host 优先直接看状态，不需要 check 挂了多少

		// 遍历 host 下所有的channel，遍历channel下的全部target，遍历target下的全部sdev，TODO 这个开销看着有点难受哦，一直在遍历，其实这里可以直接遍历所有的 sdev，待优化项
		list_for_each_entry(schannel, &shost->schannels, same_host_siblings) {
			if (schannel->eh_queued == true) {
				list_del_init(&schannel->schannel_eh_siblings);
				schannel->eh_queued = false;
			}

			if (atomic_read(&schannel->eh_schannel_state) == EH_SCHEDULED)
				continue;

			if (atomic_read(&schannel->eh_schannel_state) == EH_NORMAL)
				atomic_set(&schannel->eh_schannel_state, EH_QUIESCE);

			if (eh_scan_channel_firstly(schannel))
				need_wait = true;
		}
	} else {
		// 遍历 host 下所有的channel，遍历channel下的全部target，遍历target下的全部sdev，TODO 这个开销看着有点难受哦，一直在遍历，其实这里可以直接遍历所有的 sdev，待优化项
		list_for_each_entry(schannel, &shost->schannels, same_host_siblings) {
			if (atomic_read(&schannel->eh_schannel_state) == EH_SCHEDULED)
				continue;

			if (eh_scan_channel_no_firstly(schannel))
				need_wait = true;
		}
	}

	if (shost->total_channels == shost->schannel_failed) // 当 host 下面所有的 channel 都 EH_SCHEDULED 的时候，host 也应该迭代到 EH_SCHEDULED
		atomic_set(&shost->eh_shost_state, EH_SCHEDULED);

	if (need_wait)
		return NEED_WAIT_IO_DONE;
	else
		return DONE;
}

static void scsi_eh_recover_scmd(struct scsi_device *sdev, struct scsi_cmnd *scmd)
{
	scsi_eh_restore_cmnd(scmd, sdev->ses); /* 恢复 scmd */
	kfree(sdev->ses);
	sdev->ses = NULL;
	scmd->submitter = SUBMITTED_BY_BLOCK_LAYER;
	pr_err("%s: %s recover tur scmd!\n", __func__, scsi_eh_locate_sdev(sdev));
}

static void scsi_eh_recover_sdev(struct scsi_device *sdev)
{
	if (sdev->idle)
		sdev->idle = false;

	atomic_set(&sdev->eh_sdev_state, EH_NORMAL);
	sdev->is_worker_waiting = false;
	sdev->pfaction = OFFLINE_POST_FAULT;
	sdev->eh_reset_level = EH_SDEV;
	if (sdev->eh_queued) {
		sdev->eh_queued = false;
		list_del(&sdev->sdev_eh_siblings);
	}
	pr_err("%s: %s recover eh state!\n", __func__, scsi_eh_locate_sdev(sdev));
}

static void scsi_eh_recover_starget(struct scsi_target *starget)
{
	atomic_set(&starget->eh_starget_state, EH_NORMAL);
	starget->pfaction = OFFLINE_POST_FAULT;
	if (starget->eh_queued) {
		starget->eh_queued = false;
		list_del(&starget->starget_eh_siblings);
	}
	pr_err("%s: %s recover eh state!\n", __func__, scsi_eh_locate_starget(starget));
}

static void scsi_eh_recover_schannel(struct scsi_channel *schannel)
{
	atomic_set(&schannel->eh_schannel_state, EH_NORMAL);
	schannel->pfaction = OFFLINE_POST_FAULT;
	if (schannel->eh_queued) {
		schannel->eh_queued = false;
		list_del(&schannel->schannel_eh_siblings);
	}
	pr_err("%s: %s recover eh state!\n", __func__, scsi_eh_locate_schannel(schannel));
}

static void scsi_eh_recover_shost(struct Scsi_Host *shost)
{
	atomic_set(&shost->eh_shost_state, EH_NORMAL);
	shost->pfaction = OFFLINE_POST_FAULT;
	pr_err("%s: %s recover eh state!\n", __func__, scsi_eh_locate_shost(shost));
}

static void scsi_eh_recover_shost_state(struct Scsi_Host *shost)
{
	unsigned long flags;

	spin_lock_irqsave(shost->host_lock, flags);
	if (scsi_host_set_state(shost, SHOST_RUNNING))
		if (scsi_host_set_state(shost, SHOST_CANCEL))
			BUG_ON(scsi_host_set_state(shost, SHOST_DEL));
	spin_unlock_irqrestore(shost->host_lock, flags);
}

static void scsi_eh_offline_sdev(struct scsi_device *sdev, bool need_run_hw_queue)
{
	mutex_lock(&sdev->state_mutex);
	scsi_device_set_state(sdev, SDEV_OFFLINE);
	mutex_unlock(&sdev->state_mutex);

	if (sdev->idle && need_run_hw_queue)
		blk_mq_run_hw_queues(sdev->request_queue, true);

	scsi_eh_recover_sdev(sdev);

	pr_err("%s: %s offline!\n", __func__, scsi_eh_locate_sdev(sdev));
	scsi_eh_flush_done_q(&sdev->dev_eh_cmd_q);
	pr_err("%s: %s sdev flush scmd done, sdev state=%s!\n", __func__, scsi_eh_locate_sdev(sdev), scsi_device_show_state(sdev->sdev_state));
}

static void scsi_eh_make_sdev_running(struct scsi_device *sdev)
{
	mutex_lock(&sdev->state_mutex);
	scsi_device_set_state(sdev, SDEV_RUNNING);
	mutex_unlock(&sdev->state_mutex);
	scsi_eh_recover_sdev(sdev);
	blk_mq_run_hw_queues(sdev->request_queue, true);
	scsi_rescan_device(sdev);
}

static void scsi_eh_send_tur_to_sdev(struct scsi_device *sdev, struct scsi_cmnd *scmd)
{
	static unsigned char tur_command[6] = {TEST_UNIT_READY, 0, 0, 0, 0, 0};

	mutex_lock(&sdev->state_mutex);
	scsi_device_set_state(sdev, SDEV_RUNNING);
	mutex_unlock(&sdev->state_mutex);
	if(!sdev->ses)
		sdev->ses = kzalloc(sizeof(struct scsi_eh_save), GFP_KERNEL);
	scsi_eh_prep_cmnd(scmd, sdev->ses, tur_command, 6, 0);
	scmd->submitter = SUBMITTED_BY_NEW_SCSI_ERROR_HANDLER;
	init_completion(&sdev->eh_wait_tur_done);
	pr_err("%s: send tur to %s done!\n", __func__, scsi_eh_locate_sdev(sdev));
}

static int scsi_eh_schannel_total_sdevs(struct scsi_channel *schannel)
{
	struct scsi_target *starget;
	int total_sdevs = 0;

	list_for_each_entry(starget, &schannel->targets, same_channel_siblings)
		total_sdevs += starget->total_sdevs;
	
	return total_sdevs;
}

static int scsi_eh_shost_total_sdevs(struct Scsi_Host *shost)
{
	struct scsi_channel *schannel;
	struct scsi_target *starget;
	int total_sdevs = 0;

	list_for_each_entry(schannel, &shost->schannels, same_host_siblings) {
		list_for_each_entry(starget, &schannel->targets, same_channel_siblings) {
			total_sdevs += starget->total_sdevs;
		}
	}

	return total_sdevs;
}

/* 最关键的 checkpoint */
void scsi_eh_check_point(struct work_struct *work)
{
	struct scsi_device *sdev = container_of(work, struct scsi_device, checkpoint_work.work);
	struct Scsi_Host *shost = sdev->host;
	struct scsi_target *starget = sdev->sdev_target;
	struct scsi_channel *schannel = sdev->schannel;
	const struct scsi_host_template *hostt = shost->hostt;

	pr_err("%s check_point wakeup!\n", __func__);
	// queue_delayed_work(shost->eh_debug, &sdev->eh_debug_work, 3 * HZ);
	/* 底层驱动实现 handler 的可能性不同，这里需要评估策略，最简单的就是一个大case，根据底层不同的实现先分开 */
	if ((hostt->eh_device_reset_handler) && (!hostt->eh_target_reset_handler && !hostt->eh_bus_reset_handler && !hostt->eh_host_reset_handler)) {
		/* ::: 异常 sdev 功德圆满 GG 后，判断其所属 target 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围在 sdev**），do sdev reset，失败离线，成功万事大吉; 
		*  2. 其它（**无法明确错误范围仅在 sdev**），但是可以无代价阻塞 target。
		*  && 此时只能尝试 do sdev reset，失败离线即可，成功完事大吉。
		*  && 实际上无论返回什么，都仅能够 do sdev reset，其实压根没有判断的必要（当然这个取决于代码的写法）
		*/
		// 讨论 target 是否健康没有意义，只能执行 sdev reset，成功万事大吉，失败直接离线
		pr_err("%s Implement eh_device_reset_handler\n", __func__);
		sdev->pfaction = OFFLINE_POST_FAULT; // 其实是这一刻的现状
		sdev->eh_reset_level = EH_SDEV;
		// eh_host_statue_show(sdev);
		queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
	} else if ((hostt->eh_target_reset_handler) && (!hostt->eh_device_reset_handler && !hostt->eh_bus_reset_handler && !hostt->eh_host_reset_handler)) {
		/* ::: 只要有异常 sdev，直接阻塞对应 target（**这个是host的选择没有办法**），异常 sdev 所在的 target 功德圆满后 GG 后；判断其所属 channel 是否健康：
		*   1. SENTITY_ANY_RUNNING（**明确错误范围仅在 starget**），do target reset，失败离线即可，成功万事大吉；
		*   2. 其它（**无法明确错误范围仅在 starget**），但是可以无代价阻塞 channel。
		*   && 此时只能尝试 do target reset，失败离线即可，成功万事大吉。
		*   && 实际上无论返回什么，都仅能够 do target reset，其实压根没有判断的必要（当然这个取决于代码的写法）
		*/
		// 讨论 channel 是否健康没有意义，只能执行 starget reset，成功万事大吉，失败直接离线
		pr_err("%s Implement eh_target_reset_handler\n", __func__);
		if (update_eh_field_to_target(starget) == NEED_WAIT_IO_DONE) {
			pr_err("%s update_eh_field_to_target need wait I/O done\n", __func__);
			// eh_host_statue_show(sdev);
			queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
		} else {
			pr_err("%s update_eh_field_to_target no need wait I/O done\n", __func__);
			// eh_host_statue_show(sdev);
			starget->pfaction = OFFLINE_POST_FAULT;
			sdev->eh_reset_level = EH_STARGET;
			queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
		}
	} else if ((hostt->eh_bus_reset_handler) && (!hostt->eh_device_reset_handler && !hostt->eh_target_reset_handler && !hostt->eh_host_reset_handler)) {
		/* ::: 只要有异常 sdev，直接阻塞对应 channel（**这个是host的选择没有办法**）。异常 sdev 所在的 channel 功德圆满 GG 后，判断其所属 host 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围仅在 schannel**），do bus reset；
		*  2. 其它（**无法明确错误范围仅在 schannel**），但是可以无代价阻塞 host。
		*  && 此时只能尝试 do bus reset，失败离线即可，成功万事大吉。 
		*  && 实际上无论返回什么，都仅能够 do host reset，其实压根没有判断的必要（当然这个取决于代码的写法）
		*/
		// 讨论 host 是否健康没有意义，只能执行 schannel reset，成功万事大吉，失败直接离线
		pr_err("%s Implement eh_bus_reset_handler\n", __func__);
		if (update_eh_field_to_channel(schannel) == NEED_WAIT_IO_DONE) {
			queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
		} else {
			schannel->pfaction = OFFLINE_POST_FAULT;
			sdev->eh_reset_level = EH_SCHANNEL;
			queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
		}
	} else if ((hostt->eh_host_reset_handler) && (!hostt->eh_device_reset_handler && !hostt->eh_target_reset_handler && !hostt->eh_bus_reset_handler)) {
		/* ::: 只要有异常 sdev，直接阻塞整个 Host（**这个是host的选择没有办法**），异常 host 功德圆满 GG 后，直接执行 host reset，无需考虑任何返回值等 */
		pr_err("%s Implement eh_host_reset_handler\n", __func__);
		if (update_eh_field_to_host(shost) == NEED_WAIT_IO_DONE) {
			queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
		} else {
			shost->pfaction = OFFLINE_POST_FAULT;
			sdev->eh_reset_level = EH_SHOST;
			queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
		}
	} else if ((hostt->eh_device_reset_handler && hostt->eh_target_reset_handler) && (!hostt->eh_bus_reset_handler && !hostt->eh_host_reset_handler)) {
		/* ::: 异常 sdev 功德圆满 GG 后，判断其所属 target 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围在 sdev**），do sdev reset，失败离线，成功万事大吉; 
		*  2. 其它（**无法明确错误范围仅在 sdev**），但是可以无代价阻塞 target，这种情况下可以认为 target 异常，异常 target 功德圆满 GG 后；判断其所属 channel 是否健康：
		*     1. SENTITY_ANY_RUNNING（**明确错误范围在 starget**），do target reset，失败离线，成功万事大吉；
		*     2. 其它（**无法明确错误范围仅在 starget**），但是可以无代价阻塞 channel。&& 此时只能尝试 do target reset，失败离线即可。
		*     && 实际上无论返回什么，都仅能够 do target reset，其实压根没有判断的必要（当然这个取决于代码的写法）
		*/
		pr_err("%s Implement eh_device_reset_handler, eh_target_reset_handler\n", __func__);
		if (target_is_healthy(starget) == SENTITY_ANY_RUNNING) {
			sdev->pfaction = OFFLINE_POST_FAULT;
			sdev->eh_reset_level = EH_SDEV;
			queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
		} else {
			if (update_eh_field_to_target(starget) == NEED_WAIT_IO_DONE) {
				queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
			} else {
				starget->pfaction = OFFLINE_POST_FAULT;
				sdev->eh_reset_level = EH_STARGET;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			}
		}
	} else if ((hostt->eh_device_reset_handler && hostt->eh_bus_reset_handler) && (!hostt->eh_target_reset_handler && !hostt->eh_host_reset_handler)) {
		/* ::: 异常 sdev 功德圆满 GG 后，判断其所属 target 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围仅在 sdev**），do sdev reset，失败离线，成功万事大吉；
		*  2. 其它（**无法明确错误范围仅在 sdev**），但是可以无代价阻塞 target，这种情况下可以认为 target 异常，但是 target reset 未实现，只能退而求其次，先 do sdev reset（**仅 sdev GG 的可能性是存在的**），如果成功，万事大吉。如果失败，则明确至少是 target 异常。
		*  所以第一阶段无论返回什么，都需要执行 sdev reset，无非是有可能直接离线设备，有可能需要继续升级
		*  **开始统一逻辑**，target 异常，直接阻塞对应的 bus（**可以理解为 Host 的选择或暗示**）。bus 功德圆满 GG 后，判断其所属 host 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围在 bus**），do bus reset，失败离线，成功万事大吉; 
		*  2. 其它（**无法明确错误范围仅在 bus**），但是可以无代价阻塞 host。&& 此时只能尝试 do bus reset，失败离线即可。&& 实际上无论返回什么，都仅能够 do bu reset，其实压根没有判断的必要（当然这个取决于代码的写法）
		*/
		pr_err("%s Implement eh_device_reset_handler, eh_bus_reset_handler\n", __func__);
		if (sdev->pfaction == UPGRADE_TO_BUS_RESET_POST_FAULT) {
			if (update_eh_field_to_channel(schannel) == NEED_WAIT_IO_DONE) {
				queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
			} else {
				schannel->pfaction = OFFLINE_POST_FAULT;
				sdev->eh_reset_level = EH_SCHANNEL;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			}
		} else {
			if (target_is_healthy(starget) == SENTITY_ANY_RUNNING) {
				sdev->pfaction = OFFLINE_POST_FAULT;
				sdev->eh_reset_level = EH_SDEV;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			} else {
				sdev->pfaction = UPGRADE_TO_BUS_RESET_POST_FAULT;
				sdev->eh_reset_level = EH_SDEV;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			}
		}
	} else if ((hostt->eh_device_reset_handler && hostt->eh_host_reset_handler) && (!hostt->eh_target_reset_handler && !hostt->eh_bus_reset_handler)) {
		/* ::: 异常 sdev 功德圆满 GG 后，判断其所属 target 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围仅在 sdev**），do sdev reset，失败离线，成功万事大吉；
		*  2. 其它（**无法明确错误范围仅在 sdev**），但是可以无代价阻塞 target，这种情况下可以认为 target 异常，但是 target reset 未实现，只能退而求其次，先 do sdev reset（**仅 sdev GG 的可能性是存在的**），如果成功，完事大吉。如果失败，则明确至少是 target 异常。
		*  **开始统一逻辑**，target异常，仅有 host reset 方法，直接阻塞 host（**可以理解为 Host 的选择或暗示**）。直接reset host，成功完事大吉，失败做对应的离线
		*/
		pr_err("%s Implement eh_device_reset_handler, eh_host_reset_handler\n", __func__);
		if (sdev->pfaction == UPGRADE_TO_HOST_RESET_POST_FAULT) {
			if (update_eh_field_to_host(shost) == NEED_WAIT_IO_DONE) {
				queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
			} else {
				shost->pfaction = OFFLINE_POST_FAULT;
				sdev->eh_reset_level = EH_SHOST;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			}
		} else {
			if (target_is_healthy(starget) == SENTITY_ANY_RUNNING) {
				sdev->pfaction = OFFLINE_POST_FAULT;
				sdev->eh_reset_level = EH_SDEV;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			} else {
				sdev->pfaction = UPGRADE_TO_HOST_RESET_POST_FAULT;
				sdev->eh_reset_level = EH_SDEV;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			}
		}
	} else if ((hostt->eh_target_reset_handler && hostt->eh_bus_reset_handler) && (!hostt->eh_device_reset_handler && !hostt->eh_host_reset_handler)) {
		/* ::: 异常 sdev 功德圆满 GG 后，直接阻塞对应的 target（**这个是host的选择没有办法**），异常 sdev 所在的 target 功德圆满 GG 后；判断其所属 channel 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围仅在 starget**），do target reset，失败离线即可，成功万事大吉；
		*  2. 其它（**无法明确错误范围仅在 starget**），但是可以无代价阻塞其对应的 channel，这种情况下可以认为 channel 异常，channel 功德圆满 GG 后，判断其所属 Host 是否健康：
		*   1. SENTITY_ANY_RUNNING（**明确错误范围在 schannel**），do bus reset，失败离线，成功万事大吉；
		*   2. 其它（**无法明确错误范围仅在 schannel**），但是可以无代价阻塞 host。
		*  && 此时只能尝试 do bus reset，失败离线即可。 
		*  && 实际上无论返回什么，都仅能够 do bus reset，其实压根没有判断的必要（当然这个取决于代码的写法）
		*/
		pr_err("%s Implement eh_target_reset_handler, eh_bus_reset_handler\n", __func__);
		if (update_eh_field_to_target(starget) == NEED_WAIT_IO_DONE) {
			queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
		} else {
			if (channel_is_healthy(schannel) == SENTITY_ANY_RUNNING) {
				starget->pfaction = OFFLINE_POST_FAULT;
				sdev->eh_reset_level = EH_STARGET;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			} else {
				if (update_eh_field_to_channel(schannel) == NEED_WAIT_IO_DONE) {
					queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
				} else {
					schannel->pfaction = OFFLINE_POST_FAULT;
					sdev->eh_reset_level = EH_SCHANNEL;
					queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
				}
			}
		}
	} else if ((hostt->eh_target_reset_handler && hostt->eh_host_reset_handler) && (!hostt->eh_device_reset_handler && !hostt->eh_bus_reset_handler)) {
		/* ::: 异常 sdev 功德圆满 GG 后，直接阻塞对应 target（**这个是host的选择没有办法**），异常 sdev 所在的 target 功德圆满后 GG 后；判断其所属 channel 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围仅在 starget**），do target reset，失败离线即可，成功万事大吉；
		*  2. 其它（**无法明确错误范围仅在 starget**），但是可以无代价阻塞 channel,这种情况下认为 channel 异常，但是 bus reset 未实现，只能退而求其次，先 do target reset（**仅 target GG 的可能性是存在的**），如果成功，万事大吉，。如果失败，则明确至少是 bus 异常。
		*  **开始统一逻辑**，channel 异常，仅有host reset 方法，直接阻塞 Host（**可以理解为 Host 的选择或暗示**）。直接reset host，成功完事大吉，失败做对应的离线 
		*/
		pr_err("%s Implement eh_target_reset_handler, eh_host_reset_handler\n", __func__);
		if (starget->pfaction == UPGRADE_TO_HOST_RESET_POST_FAULT) {
			if (update_eh_field_to_host(shost) == NEED_WAIT_IO_DONE) {
				queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
			} else {
				shost->pfaction = OFFLINE_POST_FAULT;
				sdev->eh_reset_level = EH_SHOST;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			}
		} else {
			if (update_eh_field_to_target(starget) == NEED_WAIT_IO_DONE) {
				queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
			} else {
				if (channel_is_healthy(schannel) == SENTITY_ANY_RUNNING) {
					starget->pfaction = OFFLINE_POST_FAULT;
					sdev->eh_reset_level = EH_STARGET;
					queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
				} else {
					starget->pfaction = UPGRADE_TO_HOST_RESET_POST_FAULT;
					sdev->eh_reset_level = EH_STARGET;
					queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
				}
			}
		}
	} else if ((hostt->eh_bus_reset_handler && hostt->eh_host_reset_handler) && (!hostt->eh_device_reset_handler && !hostt->eh_target_reset_handler)) {
		/* ::: 异常 sdev 功德圆满 GG 后，直接阻塞对应 bus（**这个是host的选择没有办法**），异常 sdev 所在的 bus 功德圆满后 GG 后；判断其所属 host 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围仅在 bus**），do bus reset，失败离线即可，成功万事大吉；
		*  2. 其它（**无法明确错误范围仅在 bus**），但是可以无代价阻塞 host，这种情况下认为 channel 异常，直接执行 host reset，失败离线，成功万事大吉
		*/
		pr_err("%s Implement eh_bus_reset_handler, eh_host_reset_handler\n", __func__);
		if (update_eh_field_to_channel(schannel) == NEED_WAIT_IO_DONE) {
			queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
		} else {
			if (shost_is_healthy(shost) == SENTITY_ANY_RUNNING) {
				schannel->pfaction = OFFLINE_POST_FAULT;
				sdev->eh_reset_level = EH_SCHANNEL;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			} else {
				if (update_eh_field_to_host(shost) == NEED_WAIT_IO_DONE) {
					queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
				} else {
					shost->pfaction = OFFLINE_POST_FAULT;
					sdev->eh_reset_level = EH_SHOST;
					queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
				}
			}
		}
	} else if ((hostt->eh_device_reset_handler && hostt->eh_target_reset_handler && hostt->eh_bus_reset_handler) && (!hostt->eh_host_reset_handler)) {
		/* ::: 异常 sdev 功德圆满 GG 后，判断其所属 target 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围在 sdev**），do sdev reset，失败离线，成功万事大吉; 
		*  2. 其它（**无法明确错误范围仅在 sdev**），但是可以无代价阻塞 target，这种情况下可以认为 target 异常，异常 target 功德圆满 GG 后；判断其所属 channel 是否健康：
		*     1. SENTITY_ANY_RUNNING（**明确错误范围在 starget**），do target reset，失败离线，成功万事大吉；
		*     2. 其它（**无法明确错误范围仅在 starget**），但是可以无代价阻塞 channel，这种情况下认为 channel 异常，异常 channel 功德圆满 GG 后；判断其所属 Host 是否健康：
		*         1. SENTITY_ANY_RUNNING（**明确错误范围在 bus**），do bus reset，失败离线，成功万事大吉；
		*         2. 其它（**无法明确错误范围仅在 bus**），但是可以无代价阻塞 host。&& 此时只能尝试 do bus reset，失败离线即可。
		*         && 实际上无论返回什么，都仅能够 do bus reset，其实压根没有判断的必要（当然这个取决于代码的写法）
		*/
		pr_err("%s Implement eh_device_reset_handler, eh_target_reset_handler, eh_bus_reset_handler\n", __func__);
		if (target_is_healthy(starget) == SENTITY_ANY_RUNNING) {
			sdev->pfaction = OFFLINE_POST_FAULT;
			sdev->eh_reset_level = EH_SDEV;
			queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
		} else {
			if (update_eh_field_to_target(starget) == NEED_WAIT_IO_DONE) {
				queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
			} else {
				if (channel_is_healthy(schannel) == SENTITY_ANY_RUNNING) {
					starget->pfaction = OFFLINE_POST_FAULT;
					sdev->eh_reset_level = EH_STARGET;
					queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
				} else {
					if (update_eh_field_to_channel(schannel) == NEED_WAIT_IO_DONE) {
						queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
					} else {
						schannel->pfaction = OFFLINE_POST_FAULT;
						sdev->eh_reset_level = EH_SCHANNEL;
						queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
					}
				}
			}
		}
	} else if ((hostt->eh_device_reset_handler && hostt->eh_target_reset_handler && hostt->eh_host_reset_handler) && (!hostt->eh_bus_reset_handler)) {
		/* ::: 异常 sdev 功德圆满 GG 后，判断其所属 target 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围在 sdev**），do sdev reset，失败离线，成功万事大吉; 
		*  2. 其它（**无法明确错误范围仅在 sdev**），但是可以无代价阻塞 target，这种情况下可以认为 target 异常，异常 target 功德圆满 GG 后；判断其所属 channel 是否健康：
		*     1. SENTITY_ANY_RUNNING（**明确错误范围在 starget**），do target reset，失败离线，成功万事大吉；
		*     2. 其它（**无法明确错误范围仅在 starget**），但是可以无代价阻塞 channel，这种情况下认为 channel 异常，但是 bus reset 未实现，只能退而求其次，先 do bus reset（**仅 channel GG 的可能性是存在的**），如果成功，万事大吉。如果失败，则明确至少是 channel 异常。
		*     **开始统一逻辑**，channel 异常，仅有 host reset 方法，直接阻塞 host（**可以理解为 Host 的选择或暗示**）。直接reset host，成功完事大吉，失败做对应的离线 
		*/
		pr_err("%s Implement eh_device_reset_handler, eh_target_reset_handler, eh_host_reset_handler!\n", __func__);
		// eh_host_statue_show(sdev);
		if (starget->pfaction == UPGRADE_TO_HOST_RESET_POST_FAULT) {
			pr_err("%s starget->pfaction == UPGRADE_TO_HOST_RESET_POST_FAULT, update to host!\n", __func__);
			// eh_host_statue_show(sdev);
			if (update_eh_field_to_host(shost) == NEED_WAIT_IO_DONE) {
				pr_err("%s need wait update to host done!\n", __func__);
				// eh_host_statue_show(sdev);
				queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
			} else {
				pr_err("%s no need wait update to host done!\n", __func__);
				// eh_host_statue_show(sdev);
				shost->pfaction = OFFLINE_POST_FAULT;
				sdev->eh_reset_level = EH_SHOST;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			}
		} else {
			pr_err("%s starget->pfaction != UPGRADE_TO_HOST_RESET_POST_FAULT!\n", __func__);
			// eh_host_statue_show(sdev);
			if (target_is_healthy(starget) == SENTITY_ANY_RUNNING) {
				pr_err("%s target is healthy!\n", __func__);
				// eh_host_statue_show(sdev);
				sdev->pfaction = OFFLINE_POST_FAULT;
				sdev->eh_reset_level = EH_SDEV;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			} else {
				pr_err("%s no way to confirm target is healthy, update eh to target!\n", __func__);
				// eh_host_statue_show(sdev);
				if (update_eh_field_to_target(starget) == NEED_WAIT_IO_DONE) {
					pr_err("%s need wait update to target done!\n", __func__);
					// eh_host_statue_show(sdev);
					queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
				} else {
					pr_err("%s no need wait update to target done!\n", __func__);
					// eh_host_statue_show(sdev);
					if (channel_is_healthy(schannel) == SENTITY_ANY_RUNNING) {
						pr_err("%s channel is healthy!\n", __func__);
						// eh_host_statue_show(sdev);
						starget->pfaction = OFFLINE_POST_FAULT;
						sdev->eh_reset_level = EH_STARGET;
						queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
					} else {
						pr_err("%s no way to confirm channel is healthy, reset firstly, if failure, reset host again!\n", __func__);
						// eh_host_statue_show(sdev);
						starget->pfaction = UPGRADE_TO_HOST_RESET_POST_FAULT;
						sdev->eh_reset_level = EH_STARGET;
						queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
					}
				}
			}
		}
	} else if ((hostt->eh_device_reset_handler && hostt->eh_bus_reset_handler && hostt->eh_host_reset_handler) && (!hostt->eh_target_reset_handler)) {
		/* ::: 异常 sdev 功德圆满 GG 后，判断其所属 target 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围仅在 sdev**），do sdev reset，失败离线，成功万事大吉；
		*  2. 其它（**无法明确错误范围仅在 sdev**），但是可以无代价阻塞 target，这种情况下可以认为 target 异常，但是 target reset 未实现，只能退而求其次，先 do sdev reset（**仅 sdev GG 的可能性是存在的**），如果成功，万事大吉。如果失败，则明确至少是 target 异常。
		*  **开始统一逻辑**，target 异常，直接阻塞对应的 bus（**可以理解为 Host 的选择或暗示**）。bus 功德圆满 GG 后，判断其所属 host 是否健康：
		*      1. SENTITY_ANY_RUNNING（**明确错误范围在 bus**），do bus reset，失败离线，成功万事大吉; 
		*      2. 其它（**无法明确错误范围仅在 bus**），但是可以无代价阻塞 host。直接 reset host，失败离线，成功万事大吉。
		*/
		pr_err("%s Implement eh_device_reset_handler, eh_bus_reset_handler, eh_host_reset_handler\n", __func__);
		if (sdev->pfaction == UPGRADE_TO_BUS_RESET_POST_FAULT) {
			if (update_eh_field_to_channel(schannel) == NEED_WAIT_IO_DONE) {
				queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
			} else {
				if (shost_is_healthy(shost) == SENTITY_ANY_RUNNING) {
					schannel->pfaction = OFFLINE_POST_FAULT;
					sdev->eh_reset_level = EH_SCHANNEL;
					queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
				} else {
					if (update_eh_field_to_host(shost) == NEED_WAIT_IO_DONE) {
						queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
					} else {
						shost->pfaction = OFFLINE_POST_FAULT;
						sdev->eh_reset_level = EH_SHOST;
						queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
					}
				}
			}
		} else {
			if (target_is_healthy(starget) == SENTITY_ANY_RUNNING) {
				sdev->pfaction = OFFLINE_POST_FAULT;
				sdev->eh_reset_level = EH_SDEV;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			} else {
				sdev->pfaction = UPGRADE_TO_BUS_RESET_POST_FAULT;
				sdev->eh_reset_level = EH_SDEV;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			}
		}
	} else if ((hostt->eh_target_reset_handler && hostt->eh_bus_reset_handler && hostt->eh_host_reset_handler) && (!hostt->eh_device_reset_handler)) {
		/* ::: 异常 sdev 功德圆满 GG 后，直接阻塞对应的 target（**这个是host的选择没有办法**），异常 sdev 所在的 target 功德圆满 GG 后；判断其所属 channel 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围仅在 starget**），do target reset，失败离线即可，成功万事大吉；
		*  2. 其它（**无法明确错误范围仅在 starget**），但是可以无代价阻塞其对应的 channel，这种情况下可以认为 channel 异常，channel 功德圆满 GG 后，判断其所属 Host 是否健康：
		*      1. SENTITY_ANY_RUNNING（**明确错误范围在 schannel**），do bus reset，失败离线，成功万事大吉；
		*      2. 其它（**无法明确错误范围仅在 schannel**），但是可以无代价阻塞 host。直接 reset host，失败离线，成功万事大吉。
		*/
		pr_err("%s Implement eh_target_reset_handler, eh_bus_reset_handler, eh_host_reset_handler\n", __func__);
		if (update_eh_field_to_target(starget) == NEED_WAIT_IO_DONE) {
			queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
		} else {
			if (channel_is_healthy(schannel) == SENTITY_ANY_RUNNING) {
				starget->pfaction = OFFLINE_POST_FAULT;
				sdev->eh_reset_level = EH_STARGET;
				queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
			} else {
				if (update_eh_field_to_channel(schannel) == NEED_WAIT_IO_DONE) {
					queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
				} else {
					if (shost_is_healthy(shost) == SENTITY_ANY_RUNNING) {
						schannel->pfaction = OFFLINE_POST_FAULT;
						sdev->eh_reset_level = EH_SCHANNEL;
						queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
					} else {
						if (update_eh_field_to_host(shost) == NEED_WAIT_IO_DONE) {
							queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
						} else {
							shost->pfaction = OFFLINE_POST_FAULT;
							sdev->eh_reset_level = EH_SHOST;
							queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
						}
					}
				}
			}
		}
	} else if ((hostt->eh_device_reset_handler && hostt->eh_target_reset_handler && hostt->eh_bus_reset_handler && hostt->eh_host_reset_handler)) {
		/* ::: 异常 sdev 功德圆满 GG 后，判断其所属 target 是否健康：
		*  1. SENTITY_ANY_RUNNING（**明确错误范围在 sdev**），do sdev reset，失败离线，成功万事大吉; 
		*  2. 其它（**无法明确错误范围仅在 sdev**），但是可以无代价阻塞 target，这种情况下可以认为 target 异常，异常 target 功德圆满 GG 后；判断其所属 channel 是否健康：
		*      1. SENTITY_ANY_RUNNING（**明确错误范围在 starget**），do target reset，失败离线，成功万事大吉；
		*      2. 其它（**无法明确错误范围仅在 starget**），但是可以无代价阻塞 channel，这种情况下认为 channel 异常，异常 channel 功德圆满 GG 后；判断其所属 Host 是否健康：
		*          1. SENTITY_ANY_RUNNING（**明确错误范围在 bus**），do bus reset，失败离线，成功万事大吉；
		*          2. 其它（**无法明确错误范围仅在 bus**），但是可以无代价阻塞 host。直接 reset host，失败离线，成功万事大吉。
		*/
		pr_err("%s Implement eh_device_reset_handler, eh_target_reset_handler, eh_bus_reset_handler, eh_host_reset_handler\n", __func__);
		if (target_is_healthy(starget) == SENTITY_ANY_RUNNING) { /* 遍历 sdev */
			sdev->pfaction = OFFLINE_POST_FAULT;
			sdev->eh_reset_level = EH_SDEV;
			queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
		} else {
			if (update_eh_field_to_target(starget) == NEED_WAIT_IO_DONE) { /* 可能有的 sdev GG 还在路上（比如说全部都超时了，但是仅过了10s），也可以提前终结掉；但是 IDLE 的一定全部都 stop 掉了 */
				queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
			} else {
				if (channel_is_healthy(schannel) == SENTITY_ANY_RUNNING) {
					starget->pfaction = OFFLINE_POST_FAULT;
					sdev->eh_reset_level = EH_STARGET;
					queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
				} else {
					if (update_eh_field_to_channel(schannel) == NEED_WAIT_IO_DONE) {
						queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
					} else {
						if (shost_is_healthy(shost) == SENTITY_ANY_RUNNING) {
							schannel->pfaction = OFFLINE_POST_FAULT;
							sdev->eh_reset_level = EH_SCHANNEL;
							queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
						} else {
							if (update_eh_field_to_host(shost) == NEED_WAIT_IO_DONE) {
								queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
						} else {
							shost->pfaction = OFFLINE_POST_FAULT;
							sdev->eh_reset_level = EH_SHOST;
							queue_delayed_work(shost->eh_process, &sdev->eh_reset_work, HZ / 100);
						}
						}
					}
				}
			}
		}
	} else {
		pr_err("%s Implement nothing!\n", __func__);
		/* ::: 一旦 sdev 异常，直接离线即可，因为底层没有任何 reset 手段 */
		scsi_eh_offline_sdev(sdev, false);
	}

	return;
}

/**
 * scsi_eh_scmd_add_to_sdev - add scsi cmd to sdev.
 * @scmd:	scmd to run eh on.
 */
void scsi_eh_scmd_add_to_sdev(struct scsi_cmnd *scmd)
{
	struct Scsi_Host *shost = scmd->device->host;
	struct scsi_device *sdev = scmd->device;
	struct scsi_target *starget = sdev->sdev_target;

	pr_err("%s BC-EH: set sdev to EH_QUIESCE!\n", __func__);

	sdev->scmd_failed++;
	list_add_tail(&scmd->eh_entry, &sdev->dev_eh_cmd_q);
	if (atomic_read(&sdev->eh_sdev_state) == EH_NORMAL) {
		list_add_tail(&sdev->sdev_eh_siblings, &shost->eh_sdev);
		sdev->eh_queued = true;
		mutex_lock(&sdev->state_mutex);
		scsi_device_set_state(sdev, SDEV_BLOCK);
		mutex_unlock(&sdev->state_mutex);
		atomic_set(&sdev->eh_sdev_state, EH_QUIESCE);
	}
	pr_err("%s: %s vendor = %s, busy,scmd_failed(%d, %d)\n",
		__func__, scsi_eh_locate_sdev(sdev), sdev->vendor, scsi_device_busy(sdev), sdev->scmd_failed);

	if (sdev->scmd_failed == scsi_device_busy(sdev)) {
		starget->sdev_failed++;
		pr_err("%s: %s failed totally!\n", __func__, scsi_eh_locate_sdev(sdev));
		/* 
		 * 每一个 sdev 功德圆满后，都会尝试唤醒 checkpoint 去搞一波，但是后期的实现不是线程了，而是工作队列，所以这里不能无脑噻队列了
		 * 有 2 种可能性
		 * 	一种是等待 I/O 完成 —— 不会路过这个位置，也不会涉及新的work的到达
		 * 	一种是等待错误处理超时完成 —— 超时逻辑一定会走到这里来，而且只要满足 EH_QUIESCE，那就说明大家都在等你。好像又弄错了，刚错的时候 eh 就已经变成 EH_QUIESCE
		 * 那究竟应该如何区分是否拉起 eh worker 呢？
		 * host 新增一个域，用于判断这个 checkpoint 是否真正流转
		 */
		BUG_ON(atomic_read(&sdev->eh_sdev_state) == EH_RUNNING || atomic_read(&sdev->eh_sdev_state) == EH_SCHEDULED);
		if (!sdev->is_worker_waiting) { /* 如果当前的 sdev 已经被上一个 sequence 接管，那自然无需做额外的工作 */
			/*
			 * 1. 现在 GG 的 sdev 可能依然是上一个 work sequence（A）的延续，假设 A 触发了 reset 失败后再升级的逻辑。那么由 A 拉起的 work sequence 就会重复
			 * 2. 所以 A 不应该轻易拉起这个 checkpoint，最直观的解法：
			 * 	等上一个 work sequence 结束（即所有的 work sequence 都是严格串行的）；可能存在潜在的时间浪费；
			 * 3. 追求效率的解法
			 * 	在明确 work sequence 可以相互独立后，后一个 work sequence 就随之启动；尽管底层驱动 reset 的位置会互斥，但是可以最快，但是这个岂不是会造成可能潜在的 reset 超时
			 * 4. 还是应该精细化控制
			 * 	保持严格串行，在新的设计实现中，最后一个 reset 完成或超时后才可以拉起下一个 work sequence
			 */
			/*
			 * 在 sdev 未被接管的情况下，存在一种可能性，reset 失败后的升级（引入了一个新的数据结构 struct scsi_eh_work_sequence）
			 */
			if (shost->eh_work_sequence == NULL) { /* 纯粹的第一个 */
				shost->eh_work_sequence = kzalloc(sizeof(struct scsi_eh_work_sequence), GFP_KERNEL);
				BUG_ON(!shost->eh_work_sequence);
				shost->eh_work_sequence->prev_eh_work_seq= NULL;
				shost->eh_work_sequence->next_eh_work_seq = NULL;
				atomic_set(&sdev->eh_sdev_state, EH_SCHEDULED);
				queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ / 100);
			} else {
				/*
				 * 存在 eh_work_sequence，判断 eh_work_sequence 的进度，即 end reset 前 or reset 后
				 * 如果是reset前，那么这个 sdev 就得等，如果是 end reset 之后，那就直接拉起新的 eh_work_sequence，判断
				 */
				// TODO
			}
		}
	}
}

static void eh_scsi_restart_operations(struct Scsi_Host *shost)
{
	unsigned long flags;

	/*
	 * next free up anything directly waiting upon the host.  this
	 * will be requests for character device operations, and also for
	 * ioctls to queued block devices.
	 */
	pr_err("%s waking up host to restart\n", __func__);

	spin_lock_irqsave(shost->host_lock, flags);
	if (scsi_host_set_state(shost, SHOST_RUNNING))
		if (scsi_host_set_state(shost, SHOST_CANCEL))
			BUG_ON(scsi_host_set_state(shost, SHOST_DEL));
	spin_unlock_irqrestore(shost->host_lock, flags);

	wake_up(&shost->host_wait);

	/*
	 * finally we need to re-initiate requests that may be pending.  we will
	 * have had everything blocked while error handling is taking place, and
	 * now that error recovery is done, we will need to ensure that these
	 * requests are started.
	 */
	scsi_run_host_queues(shost);

	/*
	 * if eh is active and host_eh_scheduled is pending we need to re-run
	 * recovery.  we do this check after scsi_run_host_queues() to allow
	 * everything pent up since the last eh run a chance to make forward
	 * progress before we sync again.  Either we'll immediately re-run
	 * recovery or scsi_device_unbusy() will wake us again when these
	 * pending commands complete.
	 */
	spin_lock_irqsave(shost->host_lock, flags);
	if (shost->host_eh_scheduled) /* TODO 目前是跑不到的，但是后期我得考虑 */
		if (scsi_host_set_state(shost, SHOST_RECOVERY))
			WARN_ON(scsi_host_set_state(shost, SHOST_CANCEL_RECOVERY));
	spin_unlock_irqrestore(shost->host_lock, flags);
}

/* reset tips
 * 	1. 本次 reset 有了结果之后就需要恢复状态，只有再次入队了，可以不恢复状态 
 *	2. TODO reset 本身的超时检测
 */
static void scsi_eh_sdev_reset(struct scsi_device *sdev)
{
	struct Scsi_Host *shost = sdev->host;
	const struct scsi_host_template *hostt = shost->hostt;
	enum scsi_disposition rtn;
	struct scsi_cmnd *scmd;

	scmd = list_first_entry(&sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
	BUG_ON(!scmd);

	pr_err("%s: %s op reset!\n", __func__, scsi_eh_locate_sdev(sdev));
	rtn = hostt->eh_device_reset_handler(scmd);
	if (rtn == SUCCESS) {
		pr_err("%s: %s reset success!\n", __func__, scsi_eh_locate_sdev(sdev));
		scsi_eh_send_tur_to_sdev(sdev, scmd);
		rtn = shost->hostt->queuecommand(shost, scmd);
		if (!rtn) {
			unsigned long time_ret;
			pr_err("%s: %s send tur success!\n", __func__, scsi_eh_locate_sdev(sdev));
			time_ret = wait_for_completion_timeout(&sdev->eh_wait_tur_done, 10*HZ);
			scsi_eh_recover_scmd(sdev, scmd);

			if (!time_ret) {
				mutex_lock(&sdev->state_mutex);
				scsi_device_set_state(sdev, SDEV_BLOCK);
				mutex_unlock(&sdev->state_mutex);
				pr_err("%s: %s tur timeout!\n", __func__, scsi_eh_locate_sdev(sdev));
				goto reset_fault;
			}

			pr_err("%s: %s tur success!\n", __func__, scsi_eh_locate_sdev(sdev));
			scsi_eh_flush_done_q(&sdev->dev_eh_cmd_q);
			scsi_eh_make_sdev_running(sdev);
			pr_err("%s: %s sdev flush scmd done, sdev state=%s!\n", __func__,
				 scsi_eh_locate_sdev(sdev), scsi_device_show_state(sdev->sdev_state));
		} else {
			pr_err("%s: %s tur failure!\n", __func__, scsi_eh_locate_sdev(sdev));
			scsi_eh_recover_scmd(sdev, scmd);
			mutex_lock(&sdev->state_mutex);
			scsi_device_set_state(sdev, SDEV_BLOCK);
			mutex_unlock(&sdev->state_mutex);
			goto reset_fault;
		}
	} else {
		pr_err("%s: %s reset failure!\n", __func__, scsi_eh_locate_sdev(sdev));
reset_fault:
		if (sdev->pfaction == OFFLINE_POST_FAULT) {
			pr_err("%s: ready to offline %s!\n", __func__, scsi_eh_locate_sdev(sdev));
			scsi_eh_offline_sdev(sdev, false);
		} else { /* UPGRADE_TO_TARGET_RESET_POST_FAULT, UPGRADE_TO_BUS_RESET_POST_FAULT, UPGRADE_TO_HOST_RESET_POST_FAULT */
			atomic_set(&sdev->eh_sdev_state, EH_RUNNING);
			queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
		}
	}

	return;
}

static void scsi_eh_starget_reset(struct scsi_device *sdev, struct scsi_target *starget)
{
	struct Scsi_Host *shost = sdev->host;
	const struct scsi_host_template *hostt = shost->hostt;
	enum scsi_disposition rtn;
	struct scsi_cmnd *scmd, *_scmd;
	struct scsi_device *_sdev;
	int sdev_tur_failure_in_target = 0;
	int sdev_idle_in_target = 0;
	int sdev_tur_complete_in_target = 0;
	int loop_count = 0;
	bool real_reset_failure = false;

	scmd = list_first_entry(&sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
	BUG_ON(!scmd);

	pr_err("%s: %s op reset!\n", __func__, scsi_eh_locate_starget(starget));
	rtn = hostt->eh_target_reset_handler(scmd);
	if (rtn == SUCCESS) {
		pr_err("%s: %s reset success!\n", __func__, scsi_eh_locate_starget(starget));
		/* 尝试对 target 下的所有 sdev 并行发起 tur，只要有一个 sdev 是成功的，那么这个 target reset 就是成功的，就无法离线 target 下的所有设备 */
		sdev_idle_in_target = 0;
		list_for_each_entry(_sdev, &starget->devices, same_target_siblings) {
			_sdev->reset_tur_wait_timeout_done = false;
			_scmd = list_first_entry(&_sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
			if (!_sdev->idle)
				BUG_ON(!_scmd);

			if (_sdev->idle) {
				sdev_idle_in_target++;
				continue;
			}

			scsi_eh_send_tur_to_sdev(_sdev, _scmd);
			rtn = shost->hostt->queuecommand(shost, _scmd);
			if (rtn)
				sdev_tur_failure_in_target++;
		}

		/* 除了 idle 的，所有 sdev 的 tur 都是失败的，那就直接失败 */
		if (sdev_tur_failure_in_target + sdev_idle_in_target == starget->sdev_failed) {
			pr_err("%s: %s tur failure, sdev_tur_failure_in_target=%d, sdev_idle_in_target=%d, starget->sdev_failed=%d\n",
				__func__, scsi_eh_locate_starget(starget), sdev_tur_failure_in_target, sdev_idle_in_target, starget->sdev_failed);
			goto reset_fault;
		}

		/* 
		 * 接下来要检查超时的问题
		 *	需要检查所有的超时，理论上 for 循环检查 eh_wait_tur_done 的 done 就可以了
		 */
		pr_err("%s: %s send tur success, wait for!\n", __func__, scsi_eh_locate_starget(starget));
		sdev_idle_in_target = 0;
		while (true) { /* 如果遇到超时，这个循环的逻辑必须是可重入的 */
			list_for_each_entry(_sdev, &starget->devices, same_target_siblings) {				
				if (_sdev->reset_tur_wait_timeout_done) /* 对应的逻辑处理已结束 */
					continue;

				_scmd = list_first_entry(&_sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
				if (!_sdev->idle)
					BUG_ON(!_scmd);

				if (_sdev->idle) {
					sdev_idle_in_target++;
					_sdev->reset_tur_wait_timeout_done = true;
					continue;
				}

				if (completion_done(&_sdev->eh_wait_tur_done)) {
					pr_err("%s: %s tur complete!\n", __func__, scsi_eh_locate_sdev(_sdev));
					sdev_tur_complete_in_target++;
					/* 这里只要有一个成功的，所有的 sdev，以及 starget 的状态都需要恢复，那怕是为了下一次的错误处理 */
					scsi_eh_recover_scmd(_sdev, _scmd);
					scsi_eh_recover_sdev(_sdev);
					scsi_eh_flush_done_q(&_sdev->dev_eh_cmd_q);
					_sdev->reset_tur_wait_timeout_done = true;
					pr_err("%s: %s sdev flush scmd done, sdev state=%s!\n",
						__func__, scsi_eh_locate_sdev(_sdev), scsi_device_show_state(_sdev->sdev_state));
				}
			}

			if (sdev_tur_complete_in_target + sdev_idle_in_target == starget->total_sdevs)
				break;

			msleep(1000);
			loop_count++;
			if (loop_count > 10)
				break;
		}

		/* 只要有一个成功的，那么 target reset 就算是成功的 */
		if (!sdev_tur_complete_in_target)
			goto reset_fault;

		/* sdev 的二阶段处理 */
		list_for_each_entry(_sdev, &starget->devices, same_target_siblings) {
			_sdev->reset_tur_wait_timeout_done = false;
			_scmd = list_first_entry(&_sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
			if (!_sdev->idle)
				BUG_ON(!_scmd);

			if (_sdev->idle) {
				scsi_eh_make_sdev_running(_sdev);
				continue;
			}

			if (completion_done(&_sdev->eh_wait_tur_done))
				continue;

			scsi_eh_recover_scmd(_sdev, _scmd);
			scsi_eh_offline_sdev(_sdev, false); /* tur 超时的 sdev */
		}

		scsi_eh_recover_starget(starget); /* 恢复 starget 状态 */
		pr_err("%s: %s finish eh reset!\n", __func__, scsi_eh_locate_starget(starget));
	} else {
		real_reset_failure = true;
		pr_err("%s: %s reset fault!\n", __func__, scsi_eh_locate_starget(starget));
reset_fault:
		/* target reset 的直接失败与 target reset 成功后 tur 失败导致运行到这个位置的处理结果是不同的，很关键 */
		if (starget->pfaction == OFFLINE_POST_FAULT) {
			if (real_reset_failure) { /* 如果是真的失败了，那几全部离线，包括可能的 idel sdev */
				list_for_each_entry(_sdev, &starget->devices, same_target_siblings) {
					_sdev->reset_tur_wait_timeout_done = false;
					pr_err("%s: ready to offline %s!\n", __func__, scsi_eh_locate_sdev(_sdev));
					scsi_eh_offline_sdev(_sdev, true);
				}
				scsi_eh_recover_starget(starget);
				pr_err("%s: %s finish eh reset, offline all sdevs!\n", __func__, scsi_eh_locate_starget(starget));
			} else { /* 如果不是真的失败，idle 的设备保持不变，只离线确实出问题的设备 */
				list_for_each_entry(_sdev, &starget->devices, same_target_siblings) {
					_sdev->reset_tur_wait_timeout_done = false;
					_scmd = list_first_entry(&_sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
					if (!_sdev->idle)
						BUG_ON(!_scmd);

					if (_sdev->idle) {
						scsi_eh_make_sdev_running(_sdev);
						continue;
					}

					scsi_eh_recover_scmd(_sdev, _scmd);
					pr_err("%s: ready to offline %s!\n", __func__, scsi_eh_locate_sdev(_sdev));
					scsi_eh_offline_sdev(_sdev, false);
				}
				scsi_eh_recover_starget(starget);
				pr_err("%s: %s finish eh reset, offline no idle sdevs!\n", __func__, scsi_eh_locate_starget(starget));
			}
		} else { /* UPGRADE_TO_TARGET_RESET_POST_FAULT, UPGRADE_TO_BUS_RESET_POST_FAULT, UPGRADE_TO_HOST_RESET_POST_FAULT */
			atomic_set(&starget->eh_starget_state, EH_RUNNING);
			queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
		}
	}

	return;
}

static void scsi_eh_schannel_reset(struct scsi_device *sdev,
				   struct scsi_target *starget,
				   struct scsi_channel *schannel)
{
	struct Scsi_Host *shost = sdev->host;
	const struct scsi_host_template *hostt = shost->hostt;
	enum scsi_disposition rtn;
	struct scsi_cmnd *scmd, *_scmd;
	struct scsi_target *_starget;
	struct scsi_device *_sdev;
	int sdev_tur_failure_in_channel = 0;
	int sdev_idle_in_channel = 0;
	int sdev_tur_complete_in_channel = 0;
	int loop_count = 0;
	bool real_reset_failure = false;

	scmd = list_first_entry(&sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
	BUG_ON(!scmd);

	pr_err("%s: %s op reset!\n", __func__, scsi_eh_locate_schannel(schannel));
	rtn = hostt->eh_bus_reset_handler(scmd);
	if (rtn == SUCCESS) {
		pr_err("%s: %s reset success!\n", __func__, scsi_eh_locate_schannel(schannel));
		/* 尝试对 schannel 下的所有 sdev 并行发起 tur，只要有一个 sdev 是成功的，那么这个 schannel reset 就是成功的，就无法离线 schannel 下的所有设备 */
		sdev_tur_failure_in_channel = 0;
		sdev_idle_in_channel = 0;
		list_for_each_entry(_starget, &schannel->targets, same_channel_siblings) {
			list_for_each_entry(_sdev, &_starget->devices, same_target_siblings) {
				_sdev->reset_tur_wait_timeout_done = false;
				_scmd = list_first_entry(&_sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
				if (!_sdev->idle)
					BUG_ON(!_scmd);

				if (_sdev->idle) {
					sdev_idle_in_channel++;
					continue;
				}

				scsi_eh_send_tur_to_sdev(_sdev, _scmd);
				rtn = shost->hostt->queuecommand(shost, _scmd);
				if (rtn)
					sdev_tur_failure_in_channel++;
			}
		}

		/* 除了 idle 的，所有 sdev 的 tur 都是失败的，那就直接失败 */
		if (sdev_tur_failure_in_channel + sdev_idle_in_channel == scsi_eh_schannel_total_sdevs(schannel)) {
			pr_err("%s: %s tur failure, sdev_tur_failure_in_channel=%d, sdev_idle_in_channel=%d, scsi_eh_schannel_total_sdevs=%d\n",
				__func__, scsi_eh_locate_schannel(schannel), sdev_tur_failure_in_channel, sdev_idle_in_channel, scsi_eh_schannel_total_sdevs(schannel));
			goto reset_fault;
		}

		pr_err("%s: %s send tur success, wait for!\n", __func__, scsi_eh_locate_schannel(schannel));
		sdev_idle_in_channel = 0;
		sdev_tur_complete_in_channel = 0;
		while (true) { /* 如果遇到超时，这个循环的逻辑必须是可重入的 */
			list_for_each_entry(_starget, &schannel->targets, same_channel_siblings) {
				list_for_each_entry(_sdev, &_starget->devices, same_target_siblings) {
					if (_sdev->reset_tur_wait_timeout_done) /* 对应的逻辑处理已结束 */
						continue;

					_scmd = list_first_entry(&_sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
					if (!_sdev->idle)
						BUG_ON(!_scmd);

					if (_sdev->idle) {
						sdev_idle_in_channel++;
						_sdev->reset_tur_wait_timeout_done = true;
						continue;
					}

					if (completion_done(&_sdev->eh_wait_tur_done)) {
						pr_err("%s: %s tur complete!\n", __func__, scsi_eh_locate_sdev(_sdev));
						sdev_tur_complete_in_channel++;
						/* 这里只要有一个成功的，所有的 sdev，以及 channel 的状态都需要恢复，那怕是为了下一次的错误处理 */
						scsi_eh_recover_sdev(_sdev);
						scsi_eh_recover_scmd(_sdev, _scmd);
						scsi_eh_flush_done_q(&_sdev->dev_eh_cmd_q);
						_sdev->reset_tur_wait_timeout_done = true;
						pr_err("%s: %s sdev flush scmd done, sdev state=%s!\n",
							__func__, scsi_eh_locate_sdev(_sdev), scsi_device_show_state(_sdev->sdev_state));
					}
				}
			}

			if (sdev_tur_complete_in_channel + sdev_idle_in_channel == scsi_eh_schannel_total_sdevs(schannel))
				break;

			msleep(1000);
			loop_count++;
			if (loop_count > 10)
				break;
		}

		if (!sdev_tur_complete_in_channel)
			goto reset_fault;

		list_for_each_entry(_starget, &schannel->targets, same_channel_siblings) {
			list_for_each_entry(_sdev, &_starget->devices, same_target_siblings) {
				_sdev->reset_tur_wait_timeout_done = false;
				_scmd = list_first_entry(&_sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
				if (!_sdev->idle)
					BUG_ON(!_scmd);

				if (_sdev->idle) {
					scsi_eh_make_sdev_running(_sdev);
					continue;
				}

				if (completion_done(&_sdev->eh_wait_tur_done))
					continue;

				scsi_eh_recover_scmd(_sdev, _scmd);
				scsi_eh_offline_sdev(_sdev, false);
			}
			scsi_eh_recover_starget(_starget); /* 恢复 starget 状态 */
		}
		scsi_eh_recover_schannel(schannel); /* 恢复 schannel 状态 */
		pr_err("%s: %s finish eh reset!\n", __func__, scsi_eh_locate_schannel(schannel));
	} else {
		real_reset_failure = true;
		pr_err("%s: %s reset fault!\n", __func__, scsi_eh_locate_schannel(schannel));
reset_fault:
		if (schannel->pfaction == OFFLINE_POST_FAULT) {
			if (real_reset_failure) { /* 如果是真的失败了，那几全部离线，包括可能的 idel sdev，eh 的错误状态也需要全部恢复 */
				list_for_each_entry(_starget, &schannel->targets, same_channel_siblings) {
					list_for_each_entry(_sdev, &_starget->devices, same_target_siblings) {
						_sdev->reset_tur_wait_timeout_done = false;
						pr_err("%s: ready to offline %s!\n", __func__, scsi_eh_locate_sdev(_sdev));
						scsi_eh_offline_sdev(_sdev, true);
					}
					scsi_eh_recover_starget(_starget);
				}
				scsi_eh_recover_schannel(schannel); /* 恢复 channel 数据结构的状态 */
				pr_err("%s: %s finish eh reset, offline all sdevs!\n", __func__, scsi_eh_locate_schannel(schannel));
			} else { /* 如果不是真的失败，idle 的设备保持不变，只离线确实出问题的设备，eh 的错误状态也需要全部恢复 */
				list_for_each_entry(_starget, &schannel->targets, same_channel_siblings) {
					list_for_each_entry(_sdev, &_starget->devices, same_target_siblings) {
						_sdev->reset_tur_wait_timeout_done = false;
						_scmd = list_first_entry(&_sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
						if (!_sdev->idle)
							BUG_ON(!_scmd);

						if (_sdev->idle) {
							scsi_eh_make_sdev_running(_sdev);
							continue;
						}

						scsi_eh_recover_scmd(_sdev, _scmd);
						pr_err("%s: ready to offline %s!\n", __func__, scsi_eh_locate_sdev(_sdev));
						scsi_eh_offline_sdev(_sdev, false);
					}
					scsi_eh_recover_starget(_starget);
				}
				scsi_eh_recover_schannel(schannel);
				pr_err("%s: %s finish eh reset, offline no idle sdevs!\n", __func__, scsi_eh_locate_schannel(schannel));
			}
		} else { /* UPGRADE_TO_TARGET_RESET_POST_FAULT, UPGRADE_TO_BUS_RESET_POST_FAULT, UPGRADE_TO_HOST_RESET_POST_FAULT */
			atomic_set(&schannel->eh_schannel_state, EH_RUNNING);
			queue_delayed_work(shost->eh_checkpoint, &sdev->checkpoint_work, HZ);
		}
	}

	return;
}

static void scsi_eh_shost_reset(struct scsi_device *sdev,
				   struct scsi_target *starget,
				   struct scsi_channel *schannel,
				   struct Scsi_Host *shost)
{
	enum scsi_disposition rtn;
	const struct scsi_host_template *hostt = shost->hostt;
	struct scsi_channel *_schannel;
	struct scsi_target *_starget;
	struct scsi_device *_sdev;
	struct scsi_cmnd *scmd, *_scmd;
	int sdev_tur_failure_in_host = 0;
	int sdev_idle_in_host = 0;
	int sdev_tur_complete_in_host = 0;
	int loop_count = 0;
	bool real_reset_failure = false;

	scmd = list_first_entry(&sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
	BUG_ON(!scmd);

	pr_err("%s: %s op reset!\n", __func__, scsi_eh_locate_shost(shost));
	rtn = hostt->eh_host_reset_handler(scmd);
	if (rtn == SUCCESS) {
		pr_err("%s: %s reset success!\n", __func__, scsi_eh_locate_shost(shost));
		/* 尝试对 host 下的所有 sdev 并行发起 tur，只要有一个 sdev 是成功的，那么这个 host reset 就是成功的，就无法离线 shost 下的所有设备 */
		sdev_tur_failure_in_host = 0;
		sdev_idle_in_host = 0;
		list_for_each_entry(_schannel, &shost->schannels, same_host_siblings) {
			list_for_each_entry(_starget, &_schannel->targets, same_channel_siblings) {
				list_for_each_entry(_sdev, &_starget->devices, same_target_siblings) {
					_sdev->reset_tur_wait_timeout_done = false;
					_scmd = list_first_entry(&_sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
					if (!_sdev->idle)
						BUG_ON(!_scmd);

					if (_sdev->idle) {
						sdev_idle_in_host++;
						continue;
					}

					scsi_eh_send_tur_to_sdev(_sdev, _scmd);
					rtn = shost->hostt->queuecommand(shost, _scmd);
					if (rtn)
						sdev_tur_failure_in_host++;
				}
			}
		}

		/* 除了 idle 的，所有 sdev 的 tur 都是失败的，那就直接失败 */
		if (sdev_tur_failure_in_host + sdev_idle_in_host == scsi_eh_shost_total_sdevs(shost)) {
			pr_err("%s: %s tur failure, sdev_tur_failure_in_host=%d, sdev_idle_in_host=%d, scsi_eh_shost_total_sdevs=%d\n",
				__func__, scsi_eh_locate_schannel(schannel), sdev_tur_failure_in_host, sdev_idle_in_host, scsi_eh_shost_total_sdevs(shost));
			goto reset_fault;
		}

		pr_err("%s: %s send tur success, wait for!\n", __func__, scsi_eh_locate_shost(shost));
		sdev_idle_in_host = 0;
		sdev_tur_complete_in_host = 0;
		while (true) { /* 如果遇到超时，这个循环的逻辑必须是可重入的 */
			list_for_each_entry(_schannel, &shost->schannels, same_host_siblings) {
				list_for_each_entry(_starget, &_schannel->targets, same_channel_siblings) {
					list_for_each_entry(_sdev, &_starget->devices, same_target_siblings) {
						if (_sdev->reset_tur_wait_timeout_done) /* 对应的逻辑处理已结束 */
							continue;

						_scmd = list_first_entry(&_sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
						if (!_sdev->idle)
							BUG_ON(!_scmd);

						if (_sdev->idle) {
							sdev_idle_in_host++;
							_sdev->reset_tur_wait_timeout_done = true;
							continue;
						}

						if (completion_done(&_sdev->eh_wait_tur_done)) {
							pr_err("%s: %s(%s) tur complete!\n", __func__, scsi_eh_locate_sdev(_sdev), _sdev->vendor);
							sdev_tur_complete_in_host++;
							/* 这里只要有一个成功的，所有的 sdev，以及 host 的状态都需要恢复，那怕是为了下一次的错误处理 */
							scsi_eh_recover_sdev(_sdev);
							scsi_eh_recover_scmd(_sdev, _scmd);
							scsi_eh_flush_done_q(&_sdev->dev_eh_cmd_q);
							_sdev->reset_tur_wait_timeout_done = true;
							pr_err("%s: %s(%s) flush scmd done, sdev state=%s!\n",
								__func__, scsi_eh_locate_sdev(_sdev), _sdev->vendor, scsi_device_show_state(_sdev->sdev_state));
						}
					}
				}
			}

			if (sdev_tur_complete_in_host + sdev_idle_in_host == scsi_eh_shost_total_sdevs(shost))
				break;

			msleep(1000);
			loop_count++;
			if (loop_count > 10)
				break;
		}

		if (!sdev_tur_complete_in_host)
			goto reset_fault;

		/* 这里 host recovery 的状态就可以先恢复了 */
		scsi_eh_recover_shost_state(shost);
		list_for_each_entry(_schannel, &shost->schannels, same_host_siblings) {
			list_for_each_entry(_starget, &_schannel->targets, same_channel_siblings) {
				list_for_each_entry(_sdev, &_starget->devices, same_target_siblings) {
					_sdev->reset_tur_wait_timeout_done = false;
					_scmd = list_first_entry(&_sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
					if (!_sdev->idle)
						BUG_ON(!_scmd);

					if (_sdev->idle) {
						pr_err("%s %s(%s) idle!\n", __func__, scsi_eh_locate_sdev(_sdev), _sdev->vendor);
						scsi_eh_make_sdev_running(_sdev);
						continue;
					}

					if (completion_done(&_sdev->eh_wait_tur_done)) {
						pr_err("%s %s finished!\n", __func__, scsi_eh_locate_sdev(_sdev));
						continue;
					}

					scsi_eh_recover_scmd(_sdev, _scmd);
					pr_err("%s %s offline!\n", __func__, scsi_eh_locate_sdev(_sdev));
					scsi_eh_offline_sdev(_sdev, false);
				}
				pr_err("%s %s!\n", __func__, scsi_eh_locate_starget(_starget));
				scsi_eh_recover_starget(_starget); /* 恢复 target 状态 */
			}
			pr_err("%s %s!\n", __func__, scsi_eh_locate_schannel(_schannel));
			scsi_eh_recover_schannel(_schannel); /* 恢复 schannel 状态 */
		}

		scsi_eh_recover_shost(shost); /* 恢复 shost 状态 */
		pr_err("%s: %s finish eh reset!\n", __func__, scsi_eh_locate_shost(shost));
	} else { /* host reset 失败 */
		real_reset_failure = true;
		pr_err("%s: %s reset fault!\n", __func__, scsi_eh_locate_shost(shost));
reset_fault:
		if (real_reset_failure) {
			list_for_each_entry(_schannel, &shost->schannels, same_host_siblings) {
				list_for_each_entry(_starget, &_schannel->targets, same_channel_siblings) {
					list_for_each_entry(_sdev, &_starget->devices, same_target_siblings) {
						_sdev->reset_tur_wait_timeout_done = false;
						pr_err("%s: ready to offline %s!\n", __func__, scsi_eh_locate_sdev(_sdev));
						scsi_eh_offline_sdev(_sdev, true);
					}
					scsi_eh_recover_starget(_starget);
				}
				scsi_eh_recover_schannel(_schannel);
			}
			scsi_eh_recover_shost(shost);
			pr_err("%s: %s finish eh reset, offline all sdevs!\n", __func__, scsi_eh_locate_shost(shost));
		} else {
			scsi_eh_recover_shost_state(shost);
			list_for_each_entry(_schannel, &shost->schannels, same_host_siblings) {
				list_for_each_entry(_starget, &_schannel->targets, same_channel_siblings) {
					list_for_each_entry(_sdev, &_starget->devices, same_target_siblings) {
						_sdev->reset_tur_wait_timeout_done = false;
						_scmd = list_first_entry(&_sdev->dev_eh_cmd_q, struct scsi_cmnd, eh_entry);
						if (!_sdev->idle)
							BUG_ON(!_scmd);

						if (_sdev->idle) {
							scsi_eh_make_sdev_running(_sdev);
							continue;
						}

						scsi_eh_recover_scmd(_sdev, _scmd);
						pr_err("%s: ready to offline %s!\n", __func__, scsi_eh_locate_sdev(_sdev));
						scsi_eh_offline_sdev(_sdev, false);
					}
					scsi_eh_recover_starget(_starget);
				}
				scsi_eh_recover_schannel(_schannel);
			}
			scsi_eh_recover_shost(shost);
			pr_err("%s: %s finish eh reset, offline no idle sdevs!\n", __func__, scsi_eh_locate_shost(shost));
		}
	}

	eh_scsi_restart_operations(shost);

	return;
}

void scsi_eh_reset_worker(struct work_struct *work) 
{
	struct scsi_device *sdev = container_of(work, struct scsi_device, eh_reset_work.work);
	struct scsi_target *starget = sdev->sdev_target;
	struct scsi_channel *schannel = sdev->schannel;
	struct Scsi_Host *shost = sdev->host;

	pr_err("%s eh begin reset, reset level=%s\n",
		__func__, scsi_eh_reset_level_name(sdev->eh_reset_level));
	eh_host_statue_show(sdev);

	switch(sdev->eh_reset_level){
	case EH_SDEV:
		atomic_set(&sdev->eh_sdev_state, EH_RUNNING);
		scsi_eh_sdev_reset(sdev);
		break;
	case EH_STARGET:
		atomic_set(&starget->eh_starget_state, EH_RUNNING);
		scsi_eh_starget_reset(sdev, starget);
		break;
	case EH_SCHANNEL:
		atomic_set(&schannel->eh_schannel_state, EH_RUNNING);
		scsi_eh_schannel_reset(sdev, starget, schannel);
		break;
	case EH_SHOST:
		atomic_set(&shost->eh_shost_state, EH_RUNNING);
		scsi_eh_shost_reset(sdev, starget, schannel, shost);
		break;
	}
}

void scsi_eh_debug_worker(struct work_struct *work) 
{
	struct scsi_device *sdev = container_of(work, struct scsi_device, eh_debug_work.work);
	// struct scsi_target *starget = sdev->sdev_target;
	// struct scsi_channel *schannel = sdev->schannel;
	struct Scsi_Host *shost = sdev->host;
	// struct request *req;
	// scsi_eh_locate_sdev(sdev);
	// scsi_eh_locate_starget(starget);
	// scsi_eh_locate_schannel(schannel);
	// scsi_eh_locate_shost(shost);

	struct scsi_channel *_schannel;
	struct scsi_target *_starget;
	struct scsi_device *_sdev;

	list_for_each_entry(_schannel, &shost->schannels, same_host_siblings) {
		list_for_each_entry(_starget, &_schannel->targets, same_channel_siblings) {
			list_for_each_entry(_sdev, &_starget->devices, same_target_siblings) {
				pr_err("%s: %s busy=%d,state=%s,eh_state=%s,iorequest_cnt=%d,iodone_cnt=%d,ioerr_cnt=%d,iotmo_cnt=%d\n",
					 __func__, scsi_eh_locate_sdev(_sdev), scsi_device_busy(_sdev),
					 scsi_device_show_state(_sdev->sdev_state), scsi_eh_state_name(atomic_read(&sdev->eh_sdev_state)),
					 atomic_read(&_sdev->iorequest_cnt), atomic_read(&_sdev->iodone_cnt), atomic_read(&_sdev->ioerr_cnt),
					 atomic_read(&_sdev->iotmo_cnt));
			}
		}
	}

	queue_delayed_work(shost->eh_debug, &sdev->eh_debug_work, 3 * HZ);

	return;
}



















/**
 * scsi_timeout - Timeout function for normal scsi commands.
 * @req:	request that is timing out.
 *
 * Notes:
 *     We do not need to lock this.  There is the potential for a race
 *     only in that the normal completion handling might run, but if the
 *     normal completion function determines that the timer has already
 *     fired, then it mustn't do anything.
 */
enum blk_eh_timer_return scsi_timeout(struct request *req)
{
	struct scsi_cmnd *scmd = blk_mq_rq_to_pdu(req);
	struct Scsi_Host *host = scmd->device->host;

	trace_scsi_dispatch_cmd_timeout(scmd);
	scsi_log_completion(scmd, TIMEOUT_ERROR);

	atomic_inc(&scmd->device->iotmo_cnt);
	if (host->eh_deadline != -1 && !host->last_reset)
		host->last_reset = jiffies;

	if (host->hostt->eh_timed_out) {
		switch (host->hostt->eh_timed_out(scmd)) {
		case SCSI_EH_DONE:
			return BLK_EH_DONE;
		case SCSI_EH_RESET_TIMER:
			return BLK_EH_RESET_TIMER;
		case SCSI_EH_NOT_HANDLED:
			break;
		}
	}

	/*
	 * If scsi_done() has already set SCMD_STATE_COMPLETE, do not modify
	 * *scmd.
	 */
	if (test_and_set_bit(SCMD_STATE_COMPLETE, &scmd->state))
		return BLK_EH_DONE;
	atomic_inc(&scmd->device->iodone_cnt);
	if (scsi_abort_command(scmd) != SUCCESS) {
		set_host_byte(scmd, DID_TIME_OUT);
		if (host->eh_mode == SCSI_EH_MODE_HOST)
			scsi_eh_scmd_add(scmd);
		else
			scsi_eh_scmd_add_to_sdev(scmd);
	}

	return BLK_EH_DONE;
}

/**
 * scsi_block_when_processing_errors - Prevent cmds from being queued.
 * @sdev:	Device on which we are performing recovery.
 *
 * Description:
 *     We block until the host is out of error recovery, and then check to
 *     see whether the host or the device is offline.
 *
 * Return value:
 *     0 when dev was taken offline by error recovery. 1 OK to proceed.
 */
int scsi_block_when_processing_errors(struct scsi_device *sdev)
{
	int online;

	wait_event(sdev->host->host_wait, !scsi_host_in_recovery(sdev->host));

	online = scsi_device_online(sdev);

	return online;
}
EXPORT_SYMBOL(scsi_block_when_processing_errors);

#ifdef CONFIG_SCSI_LOGGING
/**
 * scsi_eh_prt_fail_stats - Log info on failures.
 * @shost:	scsi host being recovered.
 * @work_q:	Queue of scsi cmds to process.
 */
static inline void scsi_eh_prt_fail_stats(struct Scsi_Host *shost,
					  struct list_head *work_q)
{
	struct scsi_cmnd *scmd;
	struct scsi_device *sdev;
	int total_failures = 0;
	int cmd_failed = 0;
	int cmd_cancel = 0;
	int devices_failed = 0;

	shost_for_each_device(sdev, shost) {
		list_for_each_entry(scmd, work_q, eh_entry) {
			if (scmd->device == sdev) {
				++total_failures;
				if (scmd->eh_eflags & SCSI_EH_ABORT_SCHEDULED)
					++cmd_cancel;
				else
					++cmd_failed;
			}
		}

		if (cmd_cancel || cmd_failed) {
			SCSI_LOG_ERROR_RECOVERY(3,
				shost_printk(KERN_INFO, shost,
					    "%s: cmds failed: %d, cancel: %d\n",
					    __func__, cmd_failed,
					    cmd_cancel));
			cmd_cancel = 0;
			cmd_failed = 0;
			++devices_failed;
		}
	}

	SCSI_LOG_ERROR_RECOVERY(2, shost_printk(KERN_INFO, shost,
				   "Total of %d commands on %d"
				   " devices require eh work\n",
				   total_failures, devices_failed));
}
#endif

 /**
 * scsi_report_lun_change - Set flag on all *other* devices on the same target
 *                          to indicate that a UNIT ATTENTION is expected.
 * @sdev:	Device reporting the UNIT ATTENTION
 */
static void scsi_report_lun_change(struct scsi_device *sdev)
{
	sdev->sdev_target->expecting_lun_change = 1;
}

/**
 * scsi_report_sense - Examine scsi sense information and log messages for
 *		       certain conditions, also issue uevents for some of them.
 * @sdev:	Device reporting the sense code
 * @sshdr:	sshdr to be examined
 */
static void scsi_report_sense(struct scsi_device *sdev,
			      struct scsi_sense_hdr *sshdr)
{
	enum scsi_device_event evt_type = SDEV_EVT_MAXBITS;	/* i.e. none */

	if (sshdr->sense_key == UNIT_ATTENTION) {
		if (sshdr->asc == 0x3f && sshdr->ascq == 0x03) {
			evt_type = SDEV_EVT_INQUIRY_CHANGE_REPORTED;
			sdev_printk(KERN_WARNING, sdev,
				    "Inquiry data has changed");
		} else if (sshdr->asc == 0x3f && sshdr->ascq == 0x0e) {
			evt_type = SDEV_EVT_LUN_CHANGE_REPORTED;
			scsi_report_lun_change(sdev);
			sdev_printk(KERN_WARNING, sdev,
				    "LUN assignments on this target have "
				    "changed. The Linux SCSI layer does not "
				    "automatically remap LUN assignments.\n");
		} else if (sshdr->asc == 0x3f)
			sdev_printk(KERN_WARNING, sdev,
				    "Operating parameters on this target have "
				    "changed. The Linux SCSI layer does not "
				    "automatically adjust these parameters.\n");

		if (sshdr->asc == 0x38 && sshdr->ascq == 0x07) {
			evt_type = SDEV_EVT_SOFT_THRESHOLD_REACHED_REPORTED;
			sdev_printk(KERN_WARNING, sdev,
				    "Warning! Received an indication that the "
				    "LUN reached a thin provisioning soft "
				    "threshold.\n");
		}

		if (sshdr->asc == 0x29) {
			evt_type = SDEV_EVT_POWER_ON_RESET_OCCURRED;
			/*
			 * Do not print message if it is an expected side-effect
			 * of runtime PM.
			 */
			if (!sdev->silence_suspend)
				sdev_printk(KERN_WARNING, sdev,
					    "Power-on or device reset occurred\n");
		}

		if (sshdr->asc == 0x2a && sshdr->ascq == 0x01) {
			evt_type = SDEV_EVT_MODE_PARAMETER_CHANGE_REPORTED;
			sdev_printk(KERN_WARNING, sdev,
				    "Mode parameters changed");
		} else if (sshdr->asc == 0x2a && sshdr->ascq == 0x06) {
			evt_type = SDEV_EVT_ALUA_STATE_CHANGE_REPORTED;
			sdev_printk(KERN_WARNING, sdev,
				    "Asymmetric access state changed");
		} else if (sshdr->asc == 0x2a && sshdr->ascq == 0x09) {
			evt_type = SDEV_EVT_CAPACITY_CHANGE_REPORTED;
			sdev_printk(KERN_WARNING, sdev,
				    "Capacity data has changed");
		} else if (sshdr->asc == 0x2a)
			sdev_printk(KERN_WARNING, sdev,
				    "Parameters changed");
	}

	if (evt_type != SDEV_EVT_MAXBITS) {
		set_bit(evt_type, sdev->pending_events);
		schedule_work(&sdev->event_work);
	}
}

static inline void set_scsi_ml_byte(struct scsi_cmnd *cmd, u8 status)
{
	cmd->result = (cmd->result & 0xffff00ff) | (status << 8);
}

/**
 * scsi_check_sense - Examine scsi cmd sense
 * @scmd:	Cmd to have sense checked.
 *
 * Return value:
 *	SUCCESS or FAILED or NEEDS_RETRY or ADD_TO_MLQUEUE
 *
 * Notes:
 *	When a deferred error is detected the current command has
 *	not been executed and needs retrying.
 */
enum scsi_disposition scsi_check_sense(struct scsi_cmnd *scmd)
{
	struct request *req = scsi_cmd_to_rq(scmd);
	struct scsi_device *sdev = scmd->device;
	struct scsi_sense_hdr sshdr;

	if (! scsi_command_normalize_sense(scmd, &sshdr))
		return FAILED;	/* no valid sense data */

	scsi_report_sense(sdev, &sshdr);

	if (sshdr.sense_key == UNIT_ATTENTION) {
		/*
		 * Increment the counters for Power on/Reset or New Media so
		 * that all ULDs interested in these can see that those have
		 * happened, even if someone else gets the sense data.
		 */
		if (sshdr.asc == 0x28)
			atomic_inc(&sdev->ua_new_media_ctr);
		else if (sshdr.asc == 0x29)
			atomic_inc(&sdev->ua_por_ctr);
	}

	if (scsi_sense_is_deferred(&sshdr))
		return NEEDS_RETRY;

	if (sdev->handler && sdev->handler->check_sense) {
		enum scsi_disposition rc;

		rc = sdev->handler->check_sense(sdev, &sshdr);
		if (rc != SCSI_RETURN_NOT_HANDLED)
			return rc;
		/* handler does not care. Drop down to default handling */
	}

	if (scmd->cmnd[0] == TEST_UNIT_READY &&
	    scmd->submitter != SUBMITTED_BY_SCSI_ERROR_HANDLER)
		/*
		 * nasty: for mid-layer issued TURs, we need to return the
		 * actual sense data without any recovery attempt.  For eh
		 * issued ones, we need to try to recover and interpret
		 */
		return SUCCESS;

	/*
	 * Previous logic looked for FILEMARK, EOM or ILI which are
	 * mainly associated with tapes and returned SUCCESS.
	 */
	if (sshdr.response_code == 0x70) {
		/* fixed format */
		if (scmd->sense_buffer[2] & 0xe0)
			return SUCCESS;
	} else {
		/*
		 * descriptor format: look for "stream commands sense data
		 * descriptor" (see SSC-3). Assume single sense data
		 * descriptor. Ignore ILI from SBC-2 READ LONG and WRITE LONG.
		 */
		if ((sshdr.additional_length > 3) &&
		    (scmd->sense_buffer[8] == 0x4) &&
		    (scmd->sense_buffer[11] & 0xe0))
			return SUCCESS;
	}

	switch (sshdr.sense_key) {
	case NO_SENSE:
		return SUCCESS;
	case RECOVERED_ERROR:
		return /* soft_error */ SUCCESS;

	case ABORTED_COMMAND:
		if (sshdr.asc == 0x10) /* DIF */
			return SUCCESS;

		/*
		 * Check aborts due to command duration limit policy:
		 * ABORTED COMMAND additional sense code with the
		 * COMMAND TIMEOUT BEFORE PROCESSING or
		 * COMMAND TIMEOUT DURING PROCESSING or
		 * COMMAND TIMEOUT DURING PROCESSING DUE TO ERROR RECOVERY
		 * additional sense code qualifiers.
		 */
		if (sshdr.asc == 0x2e &&
		    sshdr.ascq >= 0x01 && sshdr.ascq <= 0x03) {
			set_scsi_ml_byte(scmd, SCSIML_STAT_DL_TIMEOUT);
			req->cmd_flags |= REQ_FAILFAST_DEV;
			req->rq_flags |= RQF_QUIET;
			return SUCCESS;
		}

		if (sshdr.asc == 0x44 && sdev->sdev_bflags & BLIST_RETRY_ITF)
			return ADD_TO_MLQUEUE;
		if (sshdr.asc == 0xc1 && sshdr.ascq == 0x01 &&
		    sdev->sdev_bflags & BLIST_RETRY_ASC_C1)
			return ADD_TO_MLQUEUE;

		return NEEDS_RETRY;
	case NOT_READY:
	case UNIT_ATTENTION:
		/*
		 * if we are expecting a cc/ua because of a bus reset that we
		 * performed, treat this just as a retry.  otherwise this is
		 * information that we should pass up to the upper-level driver
		 * so that we can deal with it there.
		 */
		if (scmd->device->expecting_cc_ua) {
			/*
			 * Because some device does not queue unit
			 * attentions correctly, we carefully check
			 * additional sense code and qualifier so as
			 * not to squash media change unit attention.
			 */
			if (sshdr.asc != 0x28 || sshdr.ascq != 0x00) {
				scmd->device->expecting_cc_ua = 0;
				return NEEDS_RETRY;
			}
		}
		/*
		 * we might also expect a cc/ua if another LUN on the target
		 * reported a UA with an ASC/ASCQ of 3F 0E -
		 * REPORTED LUNS DATA HAS CHANGED.
		 */
		if (scmd->device->sdev_target->expecting_lun_change &&
		    sshdr.asc == 0x3f && sshdr.ascq == 0x0e)
			return NEEDS_RETRY;
		/*
		 * if the device is in the process of becoming ready, we
		 * should retry.
		 */
		if ((sshdr.asc == 0x04) &&
		    (sshdr.ascq == 0x01 || sshdr.ascq == 0x0a))
			return NEEDS_RETRY;
		/*
		 * if the device is not started, we need to wake
		 * the error handler to start the motor
		 */
		if (scmd->device->allow_restart &&
		    (sshdr.asc == 0x04) && (sshdr.ascq == 0x02))
			return FAILED;
		/*
		 * Pass the UA upwards for a determination in the completion
		 * functions.
		 */
		return SUCCESS;

		/* these are not supported */
	case DATA_PROTECT:
		if (sshdr.asc == 0x27 && sshdr.ascq == 0x07) {
			/* Thin provisioning hard threshold reached */
			set_scsi_ml_byte(scmd, SCSIML_STAT_NOSPC);
			return SUCCESS;
		}
		fallthrough;
	case COPY_ABORTED:
	case VOLUME_OVERFLOW:
	case MISCOMPARE:
	case BLANK_CHECK:
		set_scsi_ml_byte(scmd, SCSIML_STAT_TGT_FAILURE);
		return SUCCESS;

	case MEDIUM_ERROR:
		if (sshdr.asc == 0x11 || /* UNRECOVERED READ ERR */
		    sshdr.asc == 0x13 || /* AMNF DATA FIELD */
		    sshdr.asc == 0x14) { /* RECORD NOT FOUND */
			set_scsi_ml_byte(scmd, SCSIML_STAT_MED_ERROR);
			return SUCCESS;
		}
		return NEEDS_RETRY;

	case HARDWARE_ERROR:
		if (scmd->device->retry_hwerror)
			return ADD_TO_MLQUEUE;
		else
			set_scsi_ml_byte(scmd, SCSIML_STAT_TGT_FAILURE);
		fallthrough;

	case ILLEGAL_REQUEST:
		if (sshdr.asc == 0x20 || /* Invalid command operation code */
		    sshdr.asc == 0x21 || /* Logical block address out of range */
		    sshdr.asc == 0x22 || /* Invalid function */
		    sshdr.asc == 0x24 || /* Invalid field in cdb */
		    sshdr.asc == 0x26 || /* Parameter value invalid */
		    sshdr.asc == 0x27) { /* Write protected */
			set_scsi_ml_byte(scmd, SCSIML_STAT_TGT_FAILURE);
		}
		return SUCCESS;

	case COMPLETED:
		/*
		 * A command using command duration limits (CDL) with a
		 * descriptor set with policy 0xD may be completed with success
		 * and the sense data DATA CURRENTLY UNAVAILABLE, indicating
		 * that the command was in fact aborted because it exceeded its
		 * duration limit. Never retry these commands.
		 */
		if (sshdr.asc == 0x55 && sshdr.ascq == 0x0a) {
			set_scsi_ml_byte(scmd, SCSIML_STAT_DL_TIMEOUT);
			req->cmd_flags |= REQ_FAILFAST_DEV;
			req->rq_flags |= RQF_QUIET;
		}
		return SUCCESS;

	default:
		return SUCCESS;
	}
}
EXPORT_SYMBOL_GPL(scsi_check_sense);

static void scsi_handle_queue_ramp_up(struct scsi_device *sdev)
{
	const struct scsi_host_template *sht = sdev->host->hostt;
	struct scsi_device *tmp_sdev;

	if (!sht->track_queue_depth ||
	    sdev->queue_depth >= sdev->max_queue_depth)
		return;

	if (time_before(jiffies,
	    sdev->last_queue_ramp_up + sdev->queue_ramp_up_period))
		return;

	if (time_before(jiffies,
	    sdev->last_queue_full_time + sdev->queue_ramp_up_period))
		return;

	/*
	 * Walk all devices of a target and do
	 * ramp up on them.
	 */
	shost_for_each_device(tmp_sdev, sdev->host) {
		if (tmp_sdev->channel != sdev->channel ||
		    tmp_sdev->id != sdev->id ||
		    tmp_sdev->queue_depth == sdev->max_queue_depth)
			continue;

		scsi_change_queue_depth(tmp_sdev, tmp_sdev->queue_depth + 1);
		sdev->last_queue_ramp_up = jiffies;
	}
}

static void scsi_handle_queue_full(struct scsi_device *sdev)
{
	const struct scsi_host_template *sht = sdev->host->hostt;
	struct scsi_device *tmp_sdev;

	if (!sht->track_queue_depth)
		return;

	shost_for_each_device(tmp_sdev, sdev->host) {
		if (tmp_sdev->channel != sdev->channel ||
		    tmp_sdev->id != sdev->id)
			continue;
		/*
		 * We do not know the number of commands that were at
		 * the device when we got the queue full so we start
		 * from the highest possible value and work our way down.
		 */
		scsi_track_queue_full(tmp_sdev, tmp_sdev->queue_depth - 1);
	}
}

/**
 * scsi_eh_completed_normally - Disposition a eh cmd on return from LLD.
 * @scmd:	SCSI cmd to examine.
 *
 * Notes:
 *    This is *only* called when we are examining the status of commands
 *    queued during error recovery.  the main difference here is that we
 *    don't allow for the possibility of retries here, and we are a lot
 *    more restrictive about what we consider acceptable.
 */
static enum scsi_disposition scsi_eh_completed_normally(struct scsi_cmnd *scmd)
{
	/*
	 * first check the host byte, to see if there is anything in there
	 * that would indicate what we need to do.
	 */
	if (host_byte(scmd->result) == DID_RESET) {
		/*
		 * rats.  we are already in the error handler, so we now
		 * get to try and figure out what to do next.  if the sense
		 * is valid, we have a pretty good idea of what to do.
		 * if not, we mark it as FAILED.
		 */
		return scsi_check_sense(scmd);
	}
	if (host_byte(scmd->result) != DID_OK)
		return FAILED;

	/*
	 * now, check the status byte to see if this indicates
	 * anything special.
	 */
	switch (get_status_byte(scmd)) {
	case SAM_STAT_GOOD:
		scsi_handle_queue_ramp_up(scmd->device);
		if (scmd->sense_buffer && SCSI_SENSE_VALID(scmd))
			/*
			 * If we have sense data, call scsi_check_sense() in
			 * order to set the correct SCSI ML byte (if any).
			 * No point in checking the return value, since the
			 * command has already completed successfully.
			 */
			scsi_check_sense(scmd);
		fallthrough;
	case SAM_STAT_COMMAND_TERMINATED:
		return SUCCESS;
	case SAM_STAT_CHECK_CONDITION:
		return scsi_check_sense(scmd);
	case SAM_STAT_CONDITION_MET:
	case SAM_STAT_INTERMEDIATE:
	case SAM_STAT_INTERMEDIATE_CONDITION_MET:
		/*
		 * who knows?  FIXME(eric)
		 */
		return SUCCESS;
	case SAM_STAT_RESERVATION_CONFLICT:
		if (scmd->cmnd[0] == TEST_UNIT_READY)
			/* it is a success, we probed the device and
			 * found it */
			return SUCCESS;
		/* otherwise, we failed to send the command */
		return FAILED;
	case SAM_STAT_TASK_SET_FULL:
		scsi_handle_queue_full(scmd->device);
		fallthrough;
	case SAM_STAT_BUSY:
		return NEEDS_RETRY;
	default:
		return FAILED;
	}
	return FAILED;
}

/**
 * scsi_eh_done - Completion function for error handling.
 * @scmd:	Cmd that is done.
 */
void scsi_eh_done(struct scsi_cmnd *scmd)
{
	struct completion *eh_action;

	SCSI_LOG_ERROR_RECOVERY(3, scmd_printk(KERN_INFO, scmd,
			"%s result: %x\n", __func__, scmd->result));

	eh_action = scmd->device->host->eh_action;
	if (eh_action)
		complete(eh_action);
}

void new_scsi_eh_done(struct scsi_cmnd *scmd)
{
	struct scsi_device *sdev = scmd->device;

	complete(&sdev->eh_wait_tur_done);
}

/**
 * scsi_try_host_reset - ask host adapter to reset itself
 * @scmd:	SCSI cmd to send host reset.
 */
static enum scsi_disposition scsi_try_host_reset(struct scsi_cmnd *scmd)
{
	unsigned long flags;
	enum scsi_disposition rtn;
	struct Scsi_Host *host = scmd->device->host;
	const struct scsi_host_template *hostt = host->hostt;

	SCSI_LOG_ERROR_RECOVERY(3,
		shost_printk(KERN_INFO, host, "Snd Host RST\n"));

	if (!hostt->eh_host_reset_handler)
		return FAILED;

	rtn = hostt->eh_host_reset_handler(scmd);

	if (rtn == SUCCESS) {
		if (!hostt->skip_settle_delay)
			ssleep(HOST_RESET_SETTLE_TIME);
		spin_lock_irqsave(host->host_lock, flags);
		scsi_report_bus_reset(host, scmd_channel(scmd));
		spin_unlock_irqrestore(host->host_lock, flags);
	}

	return rtn;
}

/**
 * scsi_try_bus_reset - ask host to perform a bus reset
 * @scmd:	SCSI cmd to send bus reset.
 */
static enum scsi_disposition scsi_try_bus_reset(struct scsi_cmnd *scmd)
{
	unsigned long flags;
	enum scsi_disposition rtn;
	struct Scsi_Host *host = scmd->device->host;
	const struct scsi_host_template *hostt = host->hostt;

	SCSI_LOG_ERROR_RECOVERY(3, scmd_printk(KERN_INFO, scmd,
		"%s: Snd Bus RST\n", __func__));

	if (!hostt->eh_bus_reset_handler)
		return FAILED;

	rtn = hostt->eh_bus_reset_handler(scmd);

	if (rtn == SUCCESS) {
		if (!hostt->skip_settle_delay)
			ssleep(BUS_RESET_SETTLE_TIME);
		spin_lock_irqsave(host->host_lock, flags);
		scsi_report_bus_reset(host, scmd_channel(scmd));
		spin_unlock_irqrestore(host->host_lock, flags);
	}

	return rtn;
}

static void __scsi_report_device_reset(struct scsi_device *sdev, void *data)
{
	sdev->was_reset = 1;
	sdev->expecting_cc_ua = 1;
}

/**
 * scsi_try_target_reset - Ask host to perform a target reset
 * @scmd:	SCSI cmd used to send a target reset
 *
 * Notes:
 *    There is no timeout for this operation.  if this operation is
 *    unreliable for a given host, then the host itself needs to put a
 *    timer on it, and set the host back to a consistent state prior to
 *    returning.
 */
static enum scsi_disposition scsi_try_target_reset(struct scsi_cmnd *scmd)
{
	unsigned long flags;
	enum scsi_disposition rtn;
	struct Scsi_Host *host = scmd->device->host;
	const struct scsi_host_template *hostt = host->hostt;

	if (!hostt->eh_target_reset_handler)
		return FAILED;

	rtn = hostt->eh_target_reset_handler(scmd);
	if (rtn == SUCCESS) {
		spin_lock_irqsave(host->host_lock, flags);
		__starget_for_each_device(scsi_target(scmd->device), NULL,
					  __scsi_report_device_reset);
		spin_unlock_irqrestore(host->host_lock, flags);
	}

	return rtn;
}

/**
 * scsi_try_bus_device_reset - Ask host to perform a BDR on a dev
 * @scmd:	SCSI cmd used to send BDR
 *
 * Notes:
 *    There is no timeout for this operation.  if this operation is
 *    unreliable for a given host, then the host itself needs to put a
 *    timer on it, and set the host back to a consistent state prior to
 *    returning.
 */
static enum scsi_disposition scsi_try_bus_device_reset(struct scsi_cmnd *scmd)
{
	enum scsi_disposition rtn;
	const struct scsi_host_template *hostt = scmd->device->host->hostt;

	if (!hostt->eh_device_reset_handler)
		return FAILED;

	rtn = hostt->eh_device_reset_handler(scmd);
	if (rtn == SUCCESS)
		__scsi_report_device_reset(scmd->device, NULL);
	return rtn;
}

/**
 * scsi_try_to_abort_cmd - Ask host to abort a SCSI command
 * @hostt:	SCSI driver host template
 * @scmd:	SCSI cmd used to send a target reset
 *
 * Return value:
 *	SUCCESS, FAILED, or FAST_IO_FAIL
 *
 * Notes:
 *    SUCCESS does not necessarily indicate that the command
 *    has been aborted; it only indicates that the LLDDs
 *    has cleared all references to that command.
 *    LLDDs should return FAILED only if an abort was required
 *    but could not be executed. LLDDs should return FAST_IO_FAIL
 *    if the device is temporarily unavailable (eg due to a
 *    link down on FibreChannel)
 */
static enum scsi_disposition
scsi_try_to_abort_cmd(const struct scsi_host_template *hostt, struct scsi_cmnd *scmd)
{
	if (!hostt->eh_abort_handler)
		return FAILED;

	return hostt->eh_abort_handler(scmd);
}

static void scsi_abort_eh_cmnd(struct scsi_cmnd *scmd)
{
	if (scsi_try_to_abort_cmd(scmd->device->host->hostt, scmd) != SUCCESS)
		if (scsi_try_bus_device_reset(scmd) != SUCCESS)
			if (scsi_try_target_reset(scmd) != SUCCESS)
				if (scsi_try_bus_reset(scmd) != SUCCESS)
					scsi_try_host_reset(scmd);
}

/**
 * scsi_eh_prep_cmnd  - Save a scsi command info as part of error recovery
 * @scmd:       SCSI command structure to hijack
 * @ses:        structure to save restore information
 * @cmnd:       CDB to send. Can be NULL if no new cmnd is needed
 * @cmnd_size:  size in bytes of @cmnd (must be <= MAX_COMMAND_SIZE)
 * @sense_bytes: size of sense data to copy. or 0 (if != 0 @cmnd is ignored)
 *
 * This function is used to save a scsi command information before re-execution
 * as part of the error recovery process.  If @sense_bytes is 0 the command
 * sent must be one that does not transfer any data.  If @sense_bytes != 0
 * @cmnd is ignored and this functions sets up a REQUEST_SENSE command
 * and cmnd buffers to read @sense_bytes into @scmd->sense_buffer.
 */
void scsi_eh_prep_cmnd(struct scsi_cmnd *scmd, struct scsi_eh_save *ses,
			unsigned char *cmnd, int cmnd_size, unsigned sense_bytes)
{
	struct scsi_device *sdev = scmd->device;

	/*
	 * We need saved copies of a number of fields - this is because
	 * error handling may need to overwrite these with different values
	 * to run different commands, and once error handling is complete,
	 * we will need to restore these values prior to running the actual
	 * command.
	 */
	ses->cmd_len = scmd->cmd_len;
	ses->data_direction = scmd->sc_data_direction;
	ses->sdb = scmd->sdb;
	ses->result = scmd->result;
	ses->resid_len = scmd->resid_len;
	ses->underflow = scmd->underflow;
	ses->prot_op = scmd->prot_op;
	ses->eh_eflags = scmd->eh_eflags;

	scmd->prot_op = SCSI_PROT_NORMAL;
	scmd->eh_eflags = 0;
	memcpy(ses->cmnd, scmd->cmnd, sizeof(ses->cmnd));
	memset(scmd->cmnd, 0, sizeof(scmd->cmnd));
	memset(&scmd->sdb, 0, sizeof(scmd->sdb));
	scmd->result = 0;
	scmd->resid_len = 0;

	if (sense_bytes) {
		scmd->sdb.length = min_t(unsigned, SCSI_SENSE_BUFFERSIZE,
					 sense_bytes);
		sg_init_one(&ses->sense_sgl, scmd->sense_buffer,
			    scmd->sdb.length);
		scmd->sdb.table.sgl = &ses->sense_sgl;
		scmd->sc_data_direction = DMA_FROM_DEVICE;
		scmd->sdb.table.nents = scmd->sdb.table.orig_nents = 1;
		scmd->cmnd[0] = REQUEST_SENSE;
		scmd->cmnd[4] = scmd->sdb.length;
		scmd->cmd_len = COMMAND_SIZE(scmd->cmnd[0]);
	} else {
		scmd->sc_data_direction = DMA_NONE;
		if (cmnd) {
			BUG_ON(cmnd_size > sizeof(scmd->cmnd));
			memcpy(scmd->cmnd, cmnd, cmnd_size);
			scmd->cmd_len = COMMAND_SIZE(scmd->cmnd[0]);
		}
	}

	scmd->underflow = 0;

	if (sdev->scsi_level <= SCSI_2 && sdev->scsi_level != SCSI_UNKNOWN)
		scmd->cmnd[1] = (scmd->cmnd[1] & 0x1f) |
			(sdev->lun << 5 & 0xe0);

	/*
	 * Zero the sense buffer.  The scsi spec mandates that any
	 * untransferred sense data should be interpreted as being zero.
	 */
	memset(scmd->sense_buffer, 0, SCSI_SENSE_BUFFERSIZE);
}
EXPORT_SYMBOL(scsi_eh_prep_cmnd);

/**
 * scsi_eh_restore_cmnd  - Restore a scsi command info as part of error recovery
 * @scmd:       SCSI command structure to restore
 * @ses:        saved information from a coresponding call to scsi_eh_prep_cmnd
 *
 * Undo any damage done by above scsi_eh_prep_cmnd().
 */
void scsi_eh_restore_cmnd(struct scsi_cmnd* scmd, struct scsi_eh_save *ses)
{
	/*
	 * Restore original data
	 */
	scmd->cmd_len = ses->cmd_len;
	memcpy(scmd->cmnd, ses->cmnd, sizeof(ses->cmnd));
	scmd->sc_data_direction = ses->data_direction;
	scmd->sdb = ses->sdb;
	scmd->result = ses->result;
	scmd->resid_len = ses->resid_len;
	scmd->underflow = ses->underflow;
	scmd->prot_op = ses->prot_op;
	scmd->eh_eflags = ses->eh_eflags;
}
EXPORT_SYMBOL(scsi_eh_restore_cmnd);

/**
 * scsi_send_eh_cmnd  - submit a scsi command as part of error recovery
 * @scmd:       SCSI command structure to hijack
 * @cmnd:       CDB to send
 * @cmnd_size:  size in bytes of @cmnd
 * @timeout:    timeout for this request
 * @sense_bytes: size of sense data to copy or 0
 *
 * This function is used to send a scsi command down to a target device
 * as part of the error recovery process. See also scsi_eh_prep_cmnd() above.
 *
 * Return value:
 *    SUCCESS or FAILED or NEEDS_RETRY
 */
static enum scsi_disposition scsi_send_eh_cmnd(struct scsi_cmnd *scmd,
	unsigned char *cmnd, int cmnd_size, int timeout, unsigned sense_bytes)
{
	struct scsi_device *sdev = scmd->device;
	struct Scsi_Host *shost = sdev->host;
	DECLARE_COMPLETION_ONSTACK(done);
	unsigned long timeleft = timeout, delay;
	struct scsi_eh_save ses;
	const unsigned long stall_for = msecs_to_jiffies(100);
	int rtn;

retry:
	scsi_eh_prep_cmnd(scmd, &ses, cmnd, cmnd_size, sense_bytes);
	shost->eh_action = &done;

	scsi_log_send(scmd);
	scmd->submitter = SUBMITTED_BY_SCSI_ERROR_HANDLER;
	scmd->flags |= SCMD_LAST;

	/*
	 * Lock sdev->state_mutex to avoid that scsi_device_quiesce() can
	 * change the SCSI device state after we have examined it and before
	 * .queuecommand() is called.
	 */
	mutex_lock(&sdev->state_mutex);
	while (sdev->sdev_state == SDEV_BLOCK && timeleft > 0) {
		mutex_unlock(&sdev->state_mutex);
		SCSI_LOG_ERROR_RECOVERY(5, sdev_printk(KERN_DEBUG, sdev,
			"%s: state %d <> %d\n", __func__, sdev->sdev_state,
			SDEV_BLOCK));
		delay = min(timeleft, stall_for);
		timeleft -= delay;
		msleep(jiffies_to_msecs(delay));
		mutex_lock(&sdev->state_mutex);
	}
	if (sdev->sdev_state != SDEV_BLOCK)
		rtn = shost->hostt->queuecommand(shost, scmd);
	else
		rtn = FAILED;
	mutex_unlock(&sdev->state_mutex);

	if (rtn) {
		if (timeleft > stall_for) {
			scsi_eh_restore_cmnd(scmd, &ses);

			timeleft -= stall_for;
			msleep(jiffies_to_msecs(stall_for));
			goto retry;
		}
		/* signal not to enter either branch of the if () below */
		timeleft = 0;
		rtn = FAILED;
	} else {
		timeleft = wait_for_completion_timeout(&done, timeout);
		rtn = SUCCESS;
	}

	shost->eh_action = NULL;

	scsi_log_completion(scmd, rtn);

	SCSI_LOG_ERROR_RECOVERY(3, scmd_printk(KERN_INFO, scmd,
			"%s timeleft: %ld\n",
			__func__, timeleft));

	/*
	 * If there is time left scsi_eh_done got called, and we will examine
	 * the actual status codes to see whether the command actually did
	 * complete normally, else if we have a zero return and no time left,
	 * the command must still be pending, so abort it and return FAILED.
	 * If we never actually managed to issue the command, because
	 * ->queuecommand() kept returning non zero, use the rtn = FAILED
	 * value above (so don't execute either branch of the if)
	 */
	if (timeleft) {
		rtn = scsi_eh_completed_normally(scmd);
		SCSI_LOG_ERROR_RECOVERY(3, scmd_printk(KERN_INFO, scmd,
			"%s: scsi_eh_completed_normally %x\n", __func__, rtn));

		switch (rtn) {
		case SUCCESS:
		case NEEDS_RETRY:
		case FAILED:
			break;
		case ADD_TO_MLQUEUE:
			rtn = NEEDS_RETRY;
			break;
		default:
			rtn = FAILED;
			break;
		}
	} else if (rtn != FAILED) {
		scsi_abort_eh_cmnd(scmd);
		rtn = FAILED;
	}

	scsi_eh_restore_cmnd(scmd, &ses);

	return rtn;
}

/**
 * scsi_request_sense - Request sense data from a particular target.
 * @scmd:	SCSI cmd for request sense.
 *
 * Notes:
 *    Some hosts automatically obtain this information, others require
 *    that we obtain it on our own. This function will *not* return until
 *    the command either times out, or it completes.
 */
static enum scsi_disposition scsi_request_sense(struct scsi_cmnd *scmd)
{
	return scsi_send_eh_cmnd(scmd, NULL, 0, scmd->device->eh_timeout, ~0);
}

static enum scsi_disposition
scsi_eh_action(struct scsi_cmnd *scmd, enum scsi_disposition rtn)
{
	if (!blk_rq_is_passthrough(scsi_cmd_to_rq(scmd))) {
		struct scsi_driver *sdrv = scsi_cmd_to_driver(scmd);
		if (sdrv->eh_action)
			rtn = sdrv->eh_action(scmd, rtn);
	}
	return rtn;
}

/**
 * scsi_eh_finish_cmd - Handle a cmd that eh is finished with.
 * @scmd:	Original SCSI cmd that eh has finished.
 * @done_q:	Queue for processed commands.
 *
 * Notes:
 *    We don't want to use the normal command completion while we are are
 *    still handling errors - it may cause other commands to be queued,
 *    and that would disturb what we are doing.  Thus we really want to
 *    keep a list of pending commands for final completion, and once we
 *    are ready to leave error handling we handle completion for real.
 */
void scsi_eh_finish_cmd(struct scsi_cmnd *scmd, struct list_head *done_q)
{
	list_move_tail(&scmd->eh_entry, done_q);
}
EXPORT_SYMBOL(scsi_eh_finish_cmd);

/**
 * scsi_eh_get_sense - Get device sense data.
 * @work_q:	Queue of commands to process.
 * @done_q:	Queue of processed commands.
 *
 * Description:
 *    See if we need to request sense information.  if so, then get it
 *    now, so we have a better idea of what to do.
 *
 * Notes:
 *    This has the unfortunate side effect that if a shost adapter does
 *    not automatically request sense information, we end up shutting
 *    it down before we request it.
 *
 *    All drivers should request sense information internally these days,
 *    so for now all I have to say is tough noogies if you end up in here.
 *
 *    XXX: Long term this code should go away, but that needs an audit of
 *         all LLDDs first.
 */
int scsi_eh_get_sense(struct list_head *work_q,
		      struct list_head *done_q)
{
	struct scsi_cmnd *scmd, *next;
	struct Scsi_Host *shost;
	enum scsi_disposition rtn;

	/*
	 * If SCSI_EH_ABORT_SCHEDULED has been set, it is timeout IO,
	 * should not get sense.
	 */
	list_for_each_entry_safe(scmd, next, work_q, eh_entry) {
		if ((scmd->eh_eflags & SCSI_EH_ABORT_SCHEDULED) ||
		    SCSI_SENSE_VALID(scmd))
			continue;

		shost = scmd->device->host;
		if (scsi_host_eh_past_deadline(shost)) {
			SCSI_LOG_ERROR_RECOVERY(3,
				scmd_printk(KERN_INFO, scmd,
					    "%s: skip request sense, past eh deadline\n",
					     current->comm));
			break;
		}
		if (!scsi_status_is_check_condition(scmd->result))
			/*
			 * don't request sense if there's no check condition
			 * status because the error we're processing isn't one
			 * that has a sense code (and some devices get
			 * confused by sense requests out of the blue)
			 */
			continue;

		SCSI_LOG_ERROR_RECOVERY(2, scmd_printk(KERN_INFO, scmd,
						  "%s: requesting sense\n",
						  current->comm));
		rtn = scsi_request_sense(scmd);
		if (rtn != SUCCESS)
			continue;

		SCSI_LOG_ERROR_RECOVERY(3, scmd_printk(KERN_INFO, scmd,
			"sense requested, result %x\n", scmd->result));
		SCSI_LOG_ERROR_RECOVERY(3, scsi_print_sense(scmd));

		rtn = scsi_decide_disposition(scmd);

		/*
		 * if the result was normal, then just pass it along to the
		 * upper level.
		 */
		if (rtn == SUCCESS)
			/*
			 * We don't want this command reissued, just finished
			 * with the sense data, so set retries to the max
			 * allowed to ensure it won't get reissued. If the user
			 * has requested infinite retries, we also want to
			 * finish this command, so force completion by setting
			 * retries and allowed to the same value.
			 */
			if (scmd->allowed == SCSI_CMD_RETRIES_NO_LIMIT)
				scmd->retries = scmd->allowed = 1;
			else
				scmd->retries = scmd->allowed;
		else if (rtn != NEEDS_RETRY)
			continue;

		scsi_eh_finish_cmd(scmd, done_q);
	}

	return list_empty(work_q);
}
EXPORT_SYMBOL_GPL(scsi_eh_get_sense);

/**
 * scsi_eh_tur - Send TUR to device.
 * @scmd:	&scsi_cmnd to send TUR
 *
 * Return value:
 *    0 - Device is ready. 1 - Device NOT ready.
 */
static int scsi_eh_tur(struct scsi_cmnd *scmd)
{
	static unsigned char tur_command[6] = {TEST_UNIT_READY, 0, 0, 0, 0, 0};
	int retry_cnt = 1;
	enum scsi_disposition rtn;

	pr_err("%s TUR START!\n", __func__);

retry_tur:
	rtn = scsi_send_eh_cmnd(scmd, tur_command, 6,
				scmd->device->eh_timeout, 0);
	if (rtn == SUCCESS)
		pr_err("%s TUR SUCCESS rtn=0x%x\n", __func__, rtn);

	SCSI_LOG_ERROR_RECOVERY(3, scmd_printk(KERN_INFO, scmd,
		"%s return: %x\n", __func__, rtn));

	switch (rtn) {
	case NEEDS_RETRY:
		if (retry_cnt--)
			goto retry_tur;
		fallthrough;
	case SUCCESS:
		return 0;
	default:
		return 1;
	}
}

/**
 * scsi_eh_test_devices - check if devices are responding from error recovery.
 * @cmd_list:	scsi commands in error recovery.
 * @work_q:	queue for commands which still need more error recovery
 * @done_q:	queue for commands which are finished
 * @try_stu:	boolean on if a STU command should be tried in addition to TUR.
 *
 * Decription:
 *    Tests if devices are in a working state.  Commands to devices now in
 *    a working state are sent to the done_q while commands to devices which
 *    are still failing to respond are returned to the work_q for more
 *    processing.
 **/
static int scsi_eh_test_devices(struct list_head *cmd_list,
				struct list_head *work_q,
				struct list_head *done_q, int try_stu)
{
	struct scsi_cmnd *scmd, *next;
	struct scsi_device *sdev;
	int finish_cmds;

	while (!list_empty(cmd_list)) {
		scmd = list_entry(cmd_list->next, struct scsi_cmnd, eh_entry);
		sdev = scmd->device;

		if (!try_stu) {
			if (scsi_host_eh_past_deadline(sdev->host)) {
				/* Push items back onto work_q */
				list_splice_init(cmd_list, work_q);
				SCSI_LOG_ERROR_RECOVERY(3,
					sdev_printk(KERN_INFO, sdev,
						    "%s: skip test device, past eh deadline",
						    current->comm));
				break;
			}
		}

		finish_cmds = !scsi_device_online(scmd->device) ||
			(try_stu && !scsi_eh_try_stu(scmd) &&
			 !scsi_eh_tur(scmd)) ||
			!scsi_eh_tur(scmd);

		list_for_each_entry_safe(scmd, next, cmd_list, eh_entry)
			if (scmd->device == sdev) {
				if (finish_cmds &&
				    (try_stu ||
				     scsi_eh_action(scmd, SUCCESS) == SUCCESS))
					scsi_eh_finish_cmd(scmd, done_q);
				else
					list_move_tail(&scmd->eh_entry, work_q);
			}
	}
	return list_empty(work_q);
}

/**
 * scsi_eh_try_stu - Send START_UNIT to device.
 * @scmd:	&scsi_cmnd to send START_UNIT
 *
 * Return value:
 *    0 - Device is ready. 1 - Device NOT ready.
 */
static int scsi_eh_try_stu(struct scsi_cmnd *scmd)
{
	static unsigned char stu_command[6] = {START_STOP, 0, 0, 0, 1, 0};

	if (scmd->device->allow_restart) {
		int i;
		enum scsi_disposition rtn = NEEDS_RETRY;

		for (i = 0; rtn == NEEDS_RETRY && i < 2; i++)
			rtn = scsi_send_eh_cmnd(scmd, stu_command, 6,
						scmd->device->eh_timeout, 0);

		if (rtn == SUCCESS)
			return 0;
	}

	return 1;
}

 /**
 * scsi_eh_stu - send START_UNIT if needed
 * @shost:	&scsi host being recovered.
 * @work_q:	&list_head for pending commands.
 * @done_q:	&list_head for processed commands.
 *
 * Notes:
 *    If commands are failing due to not ready, initializing command required,
 *	try revalidating the device, which will end up sending a start unit.
 */
static int scsi_eh_stu(struct Scsi_Host *shost,
			      struct list_head *work_q,
			      struct list_head *done_q)
{
	struct scsi_cmnd *scmd, *stu_scmd, *next;
	struct scsi_device *sdev;

	shost_for_each_device(sdev, shost) {
		if (scsi_host_eh_past_deadline(shost)) {
			SCSI_LOG_ERROR_RECOVERY(3,
				sdev_printk(KERN_INFO, sdev,
					    "%s: skip START_UNIT, past eh deadline\n",
					    current->comm));
			scsi_device_put(sdev);
			break;
		}
		stu_scmd = NULL;
		list_for_each_entry(scmd, work_q, eh_entry)
			if (scmd->device == sdev && SCSI_SENSE_VALID(scmd) &&
			    scsi_check_sense(scmd) == FAILED ) {
				stu_scmd = scmd;
				break;
			}

		if (!stu_scmd)
			continue;

		SCSI_LOG_ERROR_RECOVERY(3,
			sdev_printk(KERN_INFO, sdev,
				     "%s: Sending START_UNIT\n",
				    current->comm));

		if (!scsi_eh_try_stu(stu_scmd)) {
			if (!scsi_device_online(sdev) ||
			    !scsi_eh_tur(stu_scmd)) {
				list_for_each_entry_safe(scmd, next,
							  work_q, eh_entry) {
					if (scmd->device == sdev &&
					    scsi_eh_action(scmd, SUCCESS) == SUCCESS)
						scsi_eh_finish_cmd(scmd, done_q);
				}
			}
		} else {
			SCSI_LOG_ERROR_RECOVERY(3,
				sdev_printk(KERN_INFO, sdev,
					    "%s: START_UNIT failed\n",
					    current->comm));
		}
	}

	return list_empty(work_q);
}


/**
 * scsi_eh_bus_device_reset - send bdr if needed
 * @shost:	scsi host being recovered.
 * @work_q:	&list_head for pending commands.
 * @done_q:	&list_head for processed commands.
 *
 * Notes:
 *    Try a bus device reset.  Still, look to see whether we have multiple
 *    devices that are jammed or not - if we have multiple devices, it
 *    makes no sense to try bus_device_reset - we really would need to try
 *    a bus_reset instead.
 */
static int scsi_eh_bus_device_reset(struct Scsi_Host *shost,
				    struct list_head *work_q,
				    struct list_head *done_q)
{
	struct scsi_cmnd *scmd, *bdr_scmd, *next;
	struct scsi_device *sdev;
	enum scsi_disposition rtn;

	shost_for_each_device(sdev, shost) {
		if (scsi_host_eh_past_deadline(shost)) {
			SCSI_LOG_ERROR_RECOVERY(3,
				sdev_printk(KERN_INFO, sdev,
					    "%s: skip BDR, past eh deadline\n",
					     current->comm));
			scsi_device_put(sdev);
			break;
		}
		bdr_scmd = NULL;
		list_for_each_entry(scmd, work_q, eh_entry)
			if (scmd->device == sdev) {
				bdr_scmd = scmd;
				break;
			}

		if (!bdr_scmd)
			continue;

		SCSI_LOG_ERROR_RECOVERY(3,
			sdev_printk(KERN_INFO, sdev,
				     "%s: Sending BDR\n", current->comm));
		rtn = scsi_try_bus_device_reset(bdr_scmd);
		pr_err("%s after scsi_try_bus_device_reset rtn=0x%x\n", __func__, rtn);
		if (rtn == SUCCESS || rtn == FAST_IO_FAIL) {
			if (!scsi_device_online(sdev) ||
			    rtn == FAST_IO_FAIL ||
			    !scsi_eh_tur(bdr_scmd)) {
				list_for_each_entry_safe(scmd, next,
							 work_q, eh_entry) {
					if (scmd->device == sdev &&
					    scsi_eh_action(scmd, rtn) != FAILED)
						scsi_eh_finish_cmd(scmd,
								   done_q);
				}
			}
		} else {
			SCSI_LOG_ERROR_RECOVERY(3,
				sdev_printk(KERN_INFO, sdev,
					    "%s: BDR failed\n", current->comm));
		}
	}

	return list_empty(work_q);
}

/**
 * scsi_eh_target_reset - send target reset if needed
 * @shost:	scsi host being recovered.
 * @work_q:	&list_head for pending commands.
 * @done_q:	&list_head for processed commands.
 *
 * Notes:
 *    Try a target reset.
 */
static int scsi_eh_target_reset(struct Scsi_Host *shost,
				struct list_head *work_q,
				struct list_head *done_q)
{
	LIST_HEAD(tmp_list);
	LIST_HEAD(check_list);

	list_splice_init(work_q, &tmp_list);

	while (!list_empty(&tmp_list)) {
		struct scsi_cmnd *next, *scmd;
		enum scsi_disposition rtn;
		unsigned int id;

		if (scsi_host_eh_past_deadline(shost)) {
			/* push back on work queue for further processing */
			list_splice_init(&check_list, work_q);
			list_splice_init(&tmp_list, work_q);
			SCSI_LOG_ERROR_RECOVERY(3,
				shost_printk(KERN_INFO, shost,
					    "%s: Skip target reset, past eh deadline\n",
					     current->comm));
			return list_empty(work_q);
		}

		scmd = list_entry(tmp_list.next, struct scsi_cmnd, eh_entry);
		id = scmd_id(scmd);

		SCSI_LOG_ERROR_RECOVERY(3,
			shost_printk(KERN_INFO, shost,
				     "%s: Sending target reset to target %d\n",
				     current->comm, id));
		rtn = scsi_try_target_reset(scmd);
		if (rtn != SUCCESS && rtn != FAST_IO_FAIL)
			SCSI_LOG_ERROR_RECOVERY(3,
				shost_printk(KERN_INFO, shost,
					     "%s: Target reset failed"
					     " target: %d\n",
					     current->comm, id));
		list_for_each_entry_safe(scmd, next, &tmp_list, eh_entry) {
			if (scmd_id(scmd) != id)
				continue;

			if (rtn == SUCCESS)
				list_move_tail(&scmd->eh_entry, &check_list);
			else if (rtn == FAST_IO_FAIL)
				scsi_eh_finish_cmd(scmd, done_q);
			else
				/* push back on work queue for further processing */
				list_move(&scmd->eh_entry, work_q);
		}
	}

	return scsi_eh_test_devices(&check_list, work_q, done_q, 0);
}

/**
 * scsi_eh_bus_reset - send a bus reset
 * @shost:	&scsi host being recovered.
 * @work_q:	&list_head for pending commands.
 * @done_q:	&list_head for processed commands.
 */
static int scsi_eh_bus_reset(struct Scsi_Host *shost,
			     struct list_head *work_q,
			     struct list_head *done_q)
{
	struct scsi_cmnd *scmd, *chan_scmd, *next;
	LIST_HEAD(check_list);
	unsigned int channel;
	enum scsi_disposition rtn;

	/*
	 * we really want to loop over the various channels, and do this on
	 * a channel by channel basis.  we should also check to see if any
	 * of the failed commands are on soft_reset devices, and if so, skip
	 * the reset.
	 */

	for (channel = 0; channel <= shost->max_channel; channel++) {
		if (scsi_host_eh_past_deadline(shost)) {
			list_splice_init(&check_list, work_q);
			SCSI_LOG_ERROR_RECOVERY(3,
				shost_printk(KERN_INFO, shost,
					    "%s: skip BRST, past eh deadline\n",
					     current->comm));
			return list_empty(work_q);
		}

		chan_scmd = NULL;
		list_for_each_entry(scmd, work_q, eh_entry) {
			if (channel == scmd_channel(scmd)) {
				chan_scmd = scmd;
				break;
				/*
				 * FIXME add back in some support for
				 * soft_reset devices.
				 */
			}
		}

		if (!chan_scmd)
			continue;
		SCSI_LOG_ERROR_RECOVERY(3,
			shost_printk(KERN_INFO, shost,
				     "%s: Sending BRST chan: %d\n",
				     current->comm, channel));
		rtn = scsi_try_bus_reset(chan_scmd);
		if (rtn == SUCCESS || rtn == FAST_IO_FAIL) {
			list_for_each_entry_safe(scmd, next, work_q, eh_entry) {
				if (channel == scmd_channel(scmd)) {
					if (rtn == FAST_IO_FAIL)
						scsi_eh_finish_cmd(scmd,
								   done_q);
					else
						list_move_tail(&scmd->eh_entry,
							       &check_list);
				}
			}
		} else {
			SCSI_LOG_ERROR_RECOVERY(3,
				shost_printk(KERN_INFO, shost,
					     "%s: BRST failed chan: %d\n",
					     current->comm, channel));
		}
	}
	return scsi_eh_test_devices(&check_list, work_q, done_q, 0);
}

/**
 * scsi_eh_host_reset - send a host reset
 * @shost:	host to be reset.
 * @work_q:	&list_head for pending commands.
 * @done_q:	&list_head for processed commands.
 */
static int scsi_eh_host_reset(struct Scsi_Host *shost,
			      struct list_head *work_q,
			      struct list_head *done_q)
{
	struct scsi_cmnd *scmd, *next;
	LIST_HEAD(check_list);
	enum scsi_disposition rtn;

	if (!list_empty(work_q)) {
		scmd = list_entry(work_q->next,
				  struct scsi_cmnd, eh_entry);

		SCSI_LOG_ERROR_RECOVERY(3,
			shost_printk(KERN_INFO, shost,
				     "%s: Sending HRST\n",
				     current->comm));

		rtn = scsi_try_host_reset(scmd);
		if (rtn == SUCCESS) {
			list_splice_init(work_q, &check_list);
		} else if (rtn == FAST_IO_FAIL) {
			list_for_each_entry_safe(scmd, next, work_q, eh_entry) {
					scsi_eh_finish_cmd(scmd, done_q);
			}
		} else {
			SCSI_LOG_ERROR_RECOVERY(3,
				shost_printk(KERN_INFO, shost,
					     "%s: HRST failed\n",
					     current->comm));
		}
	}
	return scsi_eh_test_devices(&check_list, work_q, done_q, 1);
}

/**
 * scsi_eh_offline_sdevs - offline scsi devices that fail to recover
 * @work_q:	&list_head for pending commands.
 * @done_q:	&list_head for processed commands.
 */
static void scsi_eh_offline_sdevs(struct list_head *work_q,
				  struct list_head *done_q)
{
	struct scsi_cmnd *scmd, *next;
	struct scsi_device *sdev;

	list_for_each_entry_safe(scmd, next, work_q, eh_entry) {
		sdev_printk(KERN_INFO, scmd->device, "Device offlined - "
			    "not ready after error recovery\n");
		sdev = scmd->device;

		mutex_lock(&sdev->state_mutex);
		scsi_device_set_state(sdev, SDEV_OFFLINE);
		mutex_unlock(&sdev->state_mutex);

		scsi_eh_finish_cmd(scmd, done_q);
	}
	return;
}

/**
 * scsi_noretry_cmd - determine if command should be failed fast
 * @scmd:	SCSI cmd to examine.
 */
bool scsi_noretry_cmd(struct scsi_cmnd *scmd)
{
	struct request *req = scsi_cmd_to_rq(scmd);

	switch (host_byte(scmd->result)) {
	case DID_OK:
		break;
	case DID_TIME_OUT:
		goto check_type;
	case DID_BUS_BUSY:
		return !!(req->cmd_flags & REQ_FAILFAST_TRANSPORT);
	case DID_PARITY:
		return !!(req->cmd_flags & REQ_FAILFAST_DEV);
	case DID_ERROR:
		if (get_status_byte(scmd) == SAM_STAT_RESERVATION_CONFLICT)
			return false;
		fallthrough;
	case DID_SOFT_ERROR:
		return !!(req->cmd_flags & REQ_FAILFAST_DRIVER);
	}

	/* Never retry commands aborted due to a duration limit timeout */
	if (scsi_ml_byte(scmd->result) == SCSIML_STAT_DL_TIMEOUT)
		return true;

	if (!scsi_status_is_check_condition(scmd->result))
		return false;

check_type:
	/*
	 * assume caller has checked sense and determined
	 * the check condition was retryable.
	 */
	if (req->cmd_flags & REQ_FAILFAST_DEV || blk_rq_is_passthrough(req))
		return true;

	return false;
}

/**
 * scsi_decide_disposition - Disposition a cmd on return from LLD.
 * @scmd:	SCSI cmd to examine.
 *
 * Notes:
 *    This is *only* called when we are examining the status after sending
 *    out the actual data command.  any commands that are queued for error
 *    recovery (e.g. test_unit_ready) do *not* come through here.
 *
 *    When this routine returns failed, it means the error handler thread
 *    is woken.  In cases where the error code indicates an error that
 *    doesn't require the error handler read (i.e. we don't need to
 *    abort/reset), this function should return SUCCESS.
 */
enum scsi_disposition scsi_decide_disposition(struct scsi_cmnd *scmd)
{
	enum scsi_disposition rtn;

	/*
	 * if the device is offline, then we clearly just pass the result back
	 * up to the top level.
	 */
	if (!scsi_device_online(scmd->device)) {
		SCSI_LOG_ERROR_RECOVERY(5, scmd_printk(KERN_INFO, scmd,
			"%s: device offline - report as SUCCESS\n", __func__));
		return SUCCESS;
	}

	/*
	 * first check the host byte, to see if there is anything in there
	 * that would indicate what we need to do.
	 */
	switch (host_byte(scmd->result)) {
	case DID_PASSTHROUGH:
		/*
		 * no matter what, pass this through to the upper layer.
		 * nuke this special code so that it looks like we are saying
		 * did_ok.
		 */
		scmd->result &= 0xff00ffff;
		return SUCCESS;
	case DID_OK:
		/*
		 * looks good.  drop through, and check the next byte.
		 */
		break;
	case DID_ABORT:
		if (scmd->eh_eflags & SCSI_EH_ABORT_SCHEDULED) {
			set_host_byte(scmd, DID_TIME_OUT);
			return SUCCESS;
		}
		fallthrough;
	case DID_NO_CONNECT:
	case DID_BAD_TARGET:
		/*
		 * note - this means that we just report the status back
		 * to the top level driver, not that we actually think
		 * that it indicates SUCCESS.
		 */
		return SUCCESS;
	case DID_SOFT_ERROR:
		/*
		 * when the low level driver returns did_soft_error,
		 * it is responsible for keeping an internal retry counter
		 * in order to avoid endless loops (db)
		 */
		goto maybe_retry;
	case DID_IMM_RETRY:
		return NEEDS_RETRY;

	case DID_REQUEUE:
		return ADD_TO_MLQUEUE;
	case DID_TRANSPORT_DISRUPTED:
		/*
		 * LLD/transport was disrupted during processing of the IO.
		 * The transport class is now blocked/blocking,
		 * and the transport will decide what to do with the IO
		 * based on its timers and recovery capablilities if
		 * there are enough retries.
		 */
		goto maybe_retry;
	case DID_TRANSPORT_FAILFAST:
		/*
		 * The transport decided to failfast the IO (most likely
		 * the fast io fail tmo fired), so send IO directly upwards.
		 */
		return SUCCESS;
	case DID_TRANSPORT_MARGINAL:
		/*
		 * caller has decided not to do retries on
		 * abort success, so send IO directly upwards
		 */
		return SUCCESS;
	case DID_ERROR:
		if (get_status_byte(scmd) == SAM_STAT_RESERVATION_CONFLICT)
			/*
			 * execute reservation conflict processing code
			 * lower down
			 */
			break;
		fallthrough;
	case DID_BUS_BUSY:
	case DID_PARITY:
		goto maybe_retry;
	case DID_TIME_OUT:
		/*
		 * when we scan the bus, we get timeout messages for
		 * these commands if there is no device available.
		 * other hosts report did_no_connect for the same thing.
		 */
		if ((scmd->cmnd[0] == TEST_UNIT_READY ||
		     scmd->cmnd[0] == INQUIRY)) {
			return SUCCESS;
		} else {
			return FAILED;
		}
	case DID_RESET:
		return SUCCESS;
	default:
		return FAILED;
	}

	/*
	 * check the status byte to see if this indicates anything special.
	 */
	switch (get_status_byte(scmd)) {
	case SAM_STAT_TASK_SET_FULL:
		scsi_handle_queue_full(scmd->device);
		/*
		 * the case of trying to send too many commands to a
		 * tagged queueing device.
		 */
		fallthrough;
	case SAM_STAT_BUSY:
		/*
		 * device can't talk to us at the moment.  Should only
		 * occur (SAM-3) when the task queue is empty, so will cause
		 * the empty queue handling to trigger a stall in the
		 * device.
		 */
		return ADD_TO_MLQUEUE;
	case SAM_STAT_GOOD:
		if (scmd->cmnd[0] == REPORT_LUNS)
			scmd->device->sdev_target->expecting_lun_change = 0;
		scsi_handle_queue_ramp_up(scmd->device);
		if (scmd->sense_buffer && SCSI_SENSE_VALID(scmd))
			/*
			 * If we have sense data, call scsi_check_sense() in
			 * order to set the correct SCSI ML byte (if any).
			 * No point in checking the return value, since the
			 * command has already completed successfully.
			 */
			scsi_check_sense(scmd);
		fallthrough;
	case SAM_STAT_COMMAND_TERMINATED:
		return SUCCESS;
	case SAM_STAT_TASK_ABORTED:
		goto maybe_retry;
	case SAM_STAT_CHECK_CONDITION:
		rtn = scsi_check_sense(scmd);
		if (rtn == NEEDS_RETRY)
			goto maybe_retry;
		/* if rtn == FAILED, we have no sense information;
		 * returning FAILED will wake the error handler thread
		 * to collect the sense and redo the decide
		 * disposition */
		return rtn;
	case SAM_STAT_CONDITION_MET:
	case SAM_STAT_INTERMEDIATE:
	case SAM_STAT_INTERMEDIATE_CONDITION_MET:
	case SAM_STAT_ACA_ACTIVE:
		/*
		 * who knows?  FIXME(eric)
		 */
		return SUCCESS;

	case SAM_STAT_RESERVATION_CONFLICT:
		sdev_printk(KERN_INFO, scmd->device,
			    "reservation conflict\n");
		set_scsi_ml_byte(scmd, SCSIML_STAT_RESV_CONFLICT);
		return SUCCESS; /* causes immediate i/o error */
	}
	return FAILED;

maybe_retry:

	/* we requeue for retry because the error was retryable, and
	 * the request was not marked fast fail.  Note that above,
	 * even if the request is marked fast fail, we still requeue
	 * for queue congestion conditions (QUEUE_FULL or BUSY) */
	if (scsi_cmd_retry_allowed(scmd) && !scsi_noretry_cmd(scmd)) {
		return NEEDS_RETRY;
	} else {
		/*
		 * no more retries - report this one back to upper level.
		 */
		return SUCCESS;
	}
}

static enum rq_end_io_ret eh_lock_door_done(struct request *req,
					    blk_status_t status)
{
	blk_mq_free_request(req);
	return RQ_END_IO_NONE;
}

/**
 * scsi_eh_lock_door - Prevent medium removal for the specified device
 * @sdev:	SCSI device to prevent medium removal
 *
 * Locking:
 * 	We must be called from process context.
 *
 * Notes:
 * 	We queue up an asynchronous "ALLOW MEDIUM REMOVAL" request on the
 * 	head of the devices request queue, and continue.
 */
static void scsi_eh_lock_door(struct scsi_device *sdev)
{
	struct scsi_cmnd *scmd;
	struct request *req;

	req = scsi_alloc_request(sdev->request_queue, REQ_OP_DRV_IN, 0);
	if (IS_ERR(req))
		return;
	scmd = blk_mq_rq_to_pdu(req);

	scmd->cmnd[0] = ALLOW_MEDIUM_REMOVAL;
	scmd->cmnd[1] = 0;
	scmd->cmnd[2] = 0;
	scmd->cmnd[3] = 0;
	scmd->cmnd[4] = SCSI_REMOVAL_PREVENT;
	scmd->cmnd[5] = 0;
	scmd->cmd_len = COMMAND_SIZE(scmd->cmnd[0]);
	scmd->allowed = 5;

	req->rq_flags |= RQF_QUIET;
	req->timeout = 10 * HZ;
	req->end_io = eh_lock_door_done;

	blk_execute_rq_nowait(req, true);
}

/**
 * scsi_restart_operations - restart io operations to the specified host.
 * @shost:	Host we are restarting.
 *
 * Notes:
 *    When we entered the error handler, we blocked all further i/o to
 *    this device.  we need to 'reverse' this process.
 */
static void scsi_restart_operations(struct Scsi_Host *shost)
{
	struct scsi_device *sdev;
	unsigned long flags;

	/*
	 * If the door was locked, we need to insert a door lock request
	 * onto the head of the SCSI request queue for the device.  There
	 * is no point trying to lock the door of an off-line device.
	 */
	shost_for_each_device(sdev, shost) {
		if (scsi_device_online(sdev) && sdev->was_reset && sdev->locked) {
			scsi_eh_lock_door(sdev);
			sdev->was_reset = 0;
		}
	}

	/*
	 * next free up anything directly waiting upon the host.  this
	 * will be requests for character device operations, and also for
	 * ioctls to queued block devices.
	 */
	SCSI_LOG_ERROR_RECOVERY(3,
		shost_printk(KERN_INFO, shost, "waking up host to restart\n"));

	spin_lock_irqsave(shost->host_lock, flags);
	if (scsi_host_set_state(shost, SHOST_RUNNING))
		if (scsi_host_set_state(shost, SHOST_CANCEL))
			BUG_ON(scsi_host_set_state(shost, SHOST_DEL));
	spin_unlock_irqrestore(shost->host_lock, flags);

	wake_up(&shost->host_wait);

	/*
	 * finally we need to re-initiate requests that may be pending.  we will
	 * have had everything blocked while error handling is taking place, and
	 * now that error recovery is done, we will need to ensure that these
	 * requests are started.
	 */
	scsi_run_host_queues(shost);

	/*
	 * if eh is active and host_eh_scheduled is pending we need to re-run
	 * recovery.  we do this check after scsi_run_host_queues() to allow
	 * everything pent up since the last eh run a chance to make forward
	 * progress before we sync again.  Either we'll immediately re-run
	 * recovery or scsi_device_unbusy() will wake us again when these
	 * pending commands complete.
	 */
	spin_lock_irqsave(shost->host_lock, flags);
	if (shost->host_eh_scheduled)
		if (scsi_host_set_state(shost, SHOST_RECOVERY))
			WARN_ON(scsi_host_set_state(shost, SHOST_CANCEL_RECOVERY));
	spin_unlock_irqrestore(shost->host_lock, flags);
}

/**
 * scsi_eh_ready_devs - check device ready state and recover if not.
 * @shost:	host to be recovered.
 * @work_q:	&list_head for pending commands.
 * @done_q:	&list_head for processed commands.
 */
void scsi_eh_ready_devs(struct Scsi_Host *shost,
			struct list_head *work_q,
			struct list_head *done_q)
{
	if (!scsi_eh_stu(shost, work_q, done_q))
		if (!scsi_eh_bus_device_reset(shost, work_q, done_q))
			if (!scsi_eh_target_reset(shost, work_q, done_q))
				if (!scsi_eh_bus_reset(shost, work_q, done_q))
					if (!scsi_eh_host_reset(shost, work_q, done_q))
						scsi_eh_offline_sdevs(work_q,
								      done_q);
}
EXPORT_SYMBOL_GPL(scsi_eh_ready_devs);

/**
 * scsi_eh_flush_done_q - finish processed commands or retry them.
 * @done_q:	list_head of processed commands.
 */
void scsi_eh_flush_done_q(struct list_head *done_q)
{
	struct scsi_cmnd *scmd, *next;

	list_for_each_entry_safe(scmd, next, done_q, eh_entry) {
		struct scsi_device *sdev = scmd->device;

		list_del_init(&scmd->eh_entry);
		if (scsi_device_online(sdev) && !scsi_noretry_cmd(scmd) &&
		    scsi_cmd_retry_allowed(scmd) &&
		    scsi_eh_should_retry_cmd(scmd)) {
			SCSI_LOG_ERROR_RECOVERY(3,
				scmd_printk(KERN_INFO, scmd,
					     "%s: flush retry cmd\n",
					     current->comm));
				scsi_queue_insert(scmd, SCSI_MLQUEUE_EH_RETRY);
				blk_mq_kick_requeue_list(sdev->request_queue);
		} else {
			/*
			 * If just we got sense for the device (called
			 * scsi_eh_get_sense), scmd->result is already
			 * set, do not set DID_TIME_OUT.
			 */
			if (!scmd->result &&
			    !(scmd->flags & SCMD_FORCE_EH_SUCCESS))
				scmd->result |= (DID_TIME_OUT << 16);
			SCSI_LOG_ERROR_RECOVERY(3,
				scmd_printk(KERN_INFO, scmd,
					     "%s: flush finish cmd\n",
					     current->comm));
			scsi_finish_command(scmd);
		}
	}
}
EXPORT_SYMBOL(scsi_eh_flush_done_q);

/**
 * scsi_unjam_host - Attempt to fix a host which has a cmd that failed.
 * @shost:	Host to unjam.
 *
 * Notes:
 *    When we come in here, we *know* that all commands on the bus have
 *    either completed, failed or timed out.  we also know that no further
 *    commands are being sent to the host, so things are relatively quiet
 *    and we have freedom to fiddle with things as we wish.
 *
 *    This is only the *default* implementation.  it is possible for
 *    individual drivers to supply their own version of this function, and
 *    if the maintainer wishes to do this, it is strongly suggested that
 *    this function be taken as a template and modified.  this function
 *    was designed to correctly handle problems for about 95% of the
 *    different cases out there, and it should always provide at least a
 *    reasonable amount of error recovery.
 *
 *    Any command marked 'failed' or 'timeout' must eventually have
 *    scsi_finish_cmd() called for it.  we do all of the retry stuff
 *    here, so when we restart the host after we return it should have an
 *    empty queue.
 */
static void scsi_unjam_host(struct Scsi_Host *shost)
{
	unsigned long flags;
	LIST_HEAD(eh_work_q);
	LIST_HEAD(eh_done_q);

	spin_lock_irqsave(shost->host_lock, flags);
	list_splice_init(&shost->eh_cmd_q, &eh_work_q);
	spin_unlock_irqrestore(shost->host_lock, flags);

	SCSI_LOG_ERROR_RECOVERY(1, scsi_eh_prt_fail_stats(shost, &eh_work_q));

	if (!scsi_eh_get_sense(&eh_work_q, &eh_done_q))
		scsi_eh_ready_devs(shost, &eh_work_q, &eh_done_q);

	spin_lock_irqsave(shost->host_lock, flags);
	if (shost->eh_deadline != -1)
		shost->last_reset = 0;
	spin_unlock_irqrestore(shost->host_lock, flags);
	scsi_eh_flush_done_q(&eh_done_q);
}

/**
 * scsi_error_handler - SCSI error handler thread
 * @data:	Host for which we are running.
 *
 * Notes:
 *    This is the main error handling loop.  This is run as a kernel thread
 *    for every SCSI host and handles all error handling activity.
 */
int scsi_error_handler(void *data)
{
	struct Scsi_Host *shost = data;

	/*
	 * We use TASK_INTERRUPTIBLE so that the thread is not
	 * counted against the load average as a running process.
	 * We never actually get interrupted because kthread_run
	 * disables signal delivery for the created thread.
	 */
	while (true) {
		/*
		 * The sequence in kthread_stop() sets the stop flag first
		 * then wakes the process.  To avoid missed wakeups, the task
		 * should always be in a non running state before the stop
		 * flag is checked
		 */
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;

		if ((shost->host_failed == 0 && shost->host_eh_scheduled == 0) ||
		    shost->host_failed != scsi_host_busy(shost)) {
			SCSI_LOG_ERROR_RECOVERY(1,
				shost_printk(KERN_INFO, shost,
					     "scsi_eh_%d: sleeping\n",
					     shost->host_no));
			schedule();
			continue;
		}

		__set_current_state(TASK_RUNNING);
		SCSI_LOG_ERROR_RECOVERY(1,
			shost_printk(KERN_INFO, shost,
				     "scsi_eh_%d: waking up %d/%d/%d\n",
				     shost->host_no, shost->host_eh_scheduled,
				     shost->host_failed,
				     scsi_host_busy(shost)));

		/*
		 * We have a host that is failing for some reason.  Figure out
		 * what we need to do to get it up and online again (if we can).
		 * If we fail, we end up taking the thing offline.
		 */
		if (!shost->eh_noresume && scsi_autopm_get_host(shost) != 0) {
			SCSI_LOG_ERROR_RECOVERY(1,
				shost_printk(KERN_ERR, shost,
					     "scsi_eh_%d: unable to autoresume\n",
					     shost->host_no));
			continue;
		}

		if (shost->transportt->eh_strategy_handler)
			shost->transportt->eh_strategy_handler(shost);
		else
			scsi_unjam_host(shost);

		/* All scmds have been handled */
		shost->host_failed = 0;

		/*
		 * Note - if the above fails completely, the action is to take
		 * individual devices offline and flush the queue of any
		 * outstanding requests that may have been pending.  When we
		 * restart, we restart any I/O to any other devices on the bus
		 * which are still online.
		 */
		scsi_restart_operations(shost);
		if (!shost->eh_noresume)
			scsi_autopm_put_host(shost);
	}
	__set_current_state(TASK_RUNNING);

	SCSI_LOG_ERROR_RECOVERY(1,
		shost_printk(KERN_INFO, shost,
			     "Error handler scsi_eh_%d exiting\n",
			     shost->host_no));
	shost->ehandler = NULL;
	return 0;
}

/**
 * scsi_report_bus_reset() - report bus reset observed
 *
 * Utility function used by low-level drivers to report that
 * they have observed a bus reset on the bus being handled.
 *
 * @shost:      Host in question
 * @channel:    channel on which reset was observed.
 *
 * Returns:     Nothing
 *
 * Lock status: Host lock must be held.
 *
 * Notes:       This only needs to be called if the reset is one which
 *		originates from an unknown location.  Resets originated
 *		by the mid-level itself don't need to call this, but there
 *		should be no harm.
 *
 *		The main purpose of this is to make sure that a CHECK_CONDITION
 *		is properly treated.
 */
void scsi_report_bus_reset(struct Scsi_Host *shost, int channel)
{
	struct scsi_device *sdev;

	__shost_for_each_device(sdev, shost) {
		if (channel == sdev_channel(sdev))
			__scsi_report_device_reset(sdev, NULL);
	}
}
EXPORT_SYMBOL(scsi_report_bus_reset);

/**
 * scsi_report_device_reset() - report device reset observed
 *
 * Utility function used by low-level drivers to report that
 * they have observed a device reset on the device being handled.
 *
 * @shost:      Host in question
 * @channel:    channel on which reset was observed
 * @target:     target on which reset was observed
 *
 * Returns:     Nothing
 *
 * Lock status: Host lock must be held
 *
 * Notes:       This only needs to be called if the reset is one which
 *		originates from an unknown location.  Resets originated
 *		by the mid-level itself don't need to call this, but there
 *		should be no harm.
 *
 *		The main purpose of this is to make sure that a CHECK_CONDITION
 *		is properly treated.
 */
void scsi_report_device_reset(struct Scsi_Host *shost, int channel, int target)
{
	struct scsi_device *sdev;

	__shost_for_each_device(sdev, shost) {
		if (channel == sdev_channel(sdev) &&
		    target == sdev_id(sdev))
			__scsi_report_device_reset(sdev, NULL);
	}
}
EXPORT_SYMBOL(scsi_report_device_reset);

/**
 * scsi_ioctl_reset: explicitly reset a host/bus/target/device
 * @dev:	scsi_device to operate on
 * @arg:	reset type (see sg.h)
 */
int
scsi_ioctl_reset(struct scsi_device *dev, int __user *arg)
{
	struct scsi_cmnd *scmd;
	struct Scsi_Host *shost = dev->host;
	struct request *rq;
	unsigned long flags;
	int error = 0, val;
	enum scsi_disposition rtn;

	if (!capable(CAP_SYS_ADMIN) || !capable(CAP_SYS_RAWIO))
		return -EACCES;

	error = get_user(val, arg);
	if (error)
		return error;

	if (scsi_autopm_get_host(shost) < 0)
		return -EIO;

	error = -EIO;
	rq = kzalloc(sizeof(struct request) + sizeof(struct scsi_cmnd) +
			shost->hostt->cmd_size, GFP_KERNEL);
	if (!rq)
		goto out_put_autopm_host;
	blk_rq_init(NULL, rq);

	scmd = (struct scsi_cmnd *)(rq + 1);
	scsi_init_command(dev, scmd);

	scmd->submitter = SUBMITTED_BY_SCSI_RESET_IOCTL;
	scmd->flags |= SCMD_LAST;
	memset(&scmd->sdb, 0, sizeof(scmd->sdb));

	scmd->cmd_len			= 0;

	scmd->sc_data_direction		= DMA_BIDIRECTIONAL;

	spin_lock_irqsave(shost->host_lock, flags);
	shost->tmf_in_progress = 1;
	spin_unlock_irqrestore(shost->host_lock, flags);

	switch (val & ~SG_SCSI_RESET_NO_ESCALATE) {
	case SG_SCSI_RESET_NOTHING:
		rtn = SUCCESS;
		break;
	case SG_SCSI_RESET_DEVICE:
		rtn = scsi_try_bus_device_reset(scmd);
		if (rtn == SUCCESS || (val & SG_SCSI_RESET_NO_ESCALATE))
			break;
		fallthrough;
	case SG_SCSI_RESET_TARGET:
		rtn = scsi_try_target_reset(scmd);
		if (rtn == SUCCESS || (val & SG_SCSI_RESET_NO_ESCALATE))
			break;
		fallthrough;
	case SG_SCSI_RESET_BUS:
		rtn = scsi_try_bus_reset(scmd);
		if (rtn == SUCCESS || (val & SG_SCSI_RESET_NO_ESCALATE))
			break;
		fallthrough;
	case SG_SCSI_RESET_HOST:
		rtn = scsi_try_host_reset(scmd);
		if (rtn == SUCCESS)
			break;
		fallthrough;
	default:
		rtn = FAILED;
		break;
	}

	error = (rtn == SUCCESS) ? 0 : -EIO;

	spin_lock_irqsave(shost->host_lock, flags);
	shost->tmf_in_progress = 0;
	spin_unlock_irqrestore(shost->host_lock, flags);

	/*
	 * be sure to wake up anyone who was sleeping or had their queue
	 * suspended while we performed the TMF.
	 */
	SCSI_LOG_ERROR_RECOVERY(3,
		shost_printk(KERN_INFO, shost,
			     "waking up host to restart after TMF\n"));

	wake_up(&shost->host_wait);
	scsi_run_host_queues(shost);

	kfree(rq);

out_put_autopm_host:
	scsi_autopm_put_host(shost);
	return error;
}

bool scsi_command_normalize_sense(const struct scsi_cmnd *cmd,
				  struct scsi_sense_hdr *sshdr)
{
	return scsi_normalize_sense(cmd->sense_buffer,
			SCSI_SENSE_BUFFERSIZE, sshdr);
}
EXPORT_SYMBOL(scsi_command_normalize_sense);

/**
 * scsi_get_sense_info_fld - get information field from sense data (either fixed or descriptor format)
 * @sense_buffer:	byte array of sense data
 * @sb_len:		number of valid bytes in sense_buffer
 * @info_out:		pointer to 64 integer where 8 or 4 byte information
 *			field will be placed if found.
 *
 * Return value:
 *	true if information field found, false if not found.
 */
bool scsi_get_sense_info_fld(const u8 *sense_buffer, int sb_len,
			     u64 *info_out)
{
	const u8 * ucp;

	if (sb_len < 7)
		return false;
	switch (sense_buffer[0] & 0x7f) {
	case 0x70:
	case 0x71:
		if (sense_buffer[0] & 0x80) {
			*info_out = get_unaligned_be32(&sense_buffer[3]);
			return true;
		}
		return false;
	case 0x72:
	case 0x73:
		ucp = scsi_sense_desc_find(sense_buffer, sb_len,
					   0 /* info desc */);
		if (ucp && (0xa == ucp[1])) {
			*info_out = get_unaligned_be64(&ucp[4]);
			return true;
		}
		return false;
	default:
		return false;
	}
}
EXPORT_SYMBOL(scsi_get_sense_info_fld);
