// Sync IPC specific routines

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include <lcd/cap.h>
#include <lcd/lcd.h>

struct kmem_cache *sync_ipc_cache;

int lcd_ipc_init(void){
	sync_ipc_cache = KMEM_CACHE(sync_ipc, 0);
	if(!sync_ipc_cache){
		printk(KERN_ERR "Failed to allocate cte slab\n");
		return -ENOMEM;
	};
	return 0;
};

int lcd_ipc_exit(void) {
	if (sync_ipc_cache)
		kmem_cache_destroy(sync_ipc_cache);
	return 0;
}

struct sync_ipc * alloc_sync_ipc() {
	struct sync_ipc *rvp; 

	rvp = (struct sync_ipc*) kmem_cache_alloc(sync_ipc_cache, GFP_KERNEL);
	if(!rvp) {
		printk(KERN_ERR "Failed to allocate memory\n");
		return NULL;
	};

	spin_lock_init(&rvp->lock);
	return rvp;
};
EXPORT_SYMBOL(alloc_sync_ipc);

void free_sync_ipc(struct sync_ipc *rvp) {
	kmem_cache_free(sync_ipc_cache, rvp);
	return;
};
EXPORT_SYMBOL(free_sync_ipc);

int ipc_send(capability_t rvp_cap, struct message_info *msg)
{
	struct task_struct *recv_task;
	struct sync_ipc *sync_ipc;
	struct cnode *cnode;
	unsigned long flags;

	printk(KERN_ERR "ipc_send:%s: sending on cap %lld\n", current->comm, rvp_cap);
	
        cnode = lcd_cnode_lookup(&current->cspace, rvp_cap);
	if (cnode == NULL || cnode->type != LCD_TYPE_SYNC_EP) {
		printk(KERN_ERR "ipc_send: can't resolve rendezvous capabilty: %lld\n", rvp_cap);
		return -EINVAL;   
	}

	sync_ipc = (struct sync_ipc *) cnode->object;
	
	BUG_ON(!sync_ipc); 

	// XXX: BU: Maybe I need to do some reference counting for IPC 
	// objects here (before releasing the lock)
	lcd_cnode_release(&cnode);

	spin_lock_irqsave(&sync_ipc->lock, flags); 	
	if (list_empty(&sync_ipc->receivers)) {

		set_current_state(TASK_INTERRUPTIBLE);
		list_add_tail(&current->sync_rendezvous, &sync_ipc->senders);
		
		printk(KERN_ERR "ipc_send:%s: putting myself to sleep\n", current->comm);
		
		spin_unlock_irqrestore(&sync_ipc->lock, flags);
		schedule();
		printk(KERN_ERR "ipc_send: somone woke me up\n");
		return 0; 

	}

	recv_task = list_first_entry(&sync_ipc->receivers, 
					struct task_struct, 
					sync_rendezvous);

        list_del(&recv_task->sync_rendezvous); 
	spin_unlock_irqrestore(&sync_ipc->lock, flags);
	 
	printk(KERN_ERR "ipc_send: found other end %s\n", recv_task->comm);
	
	// copy the message registers
	// XXX: BU: maybe MIN(of valid_regs)?
	memcpy(recv_task->utcb->msg_info.regs, 
		current->utcb->msg_info.regs, 
		sizeof(uint64_t)*recv_task->utcb->msg_info.valid_regs);

	// BU: TODO: transfer capabilities

	wake_up_process(recv_task); 
	printk(KERN_ERR "ipc_send: finished\n");
	return 0;

}
EXPORT_SYMBOL(ipc_send);

int ipc_recv(capability_t rvp_cap, struct message_info *msg)
{
	struct task_struct *send_task;
	struct sync_ipc *sync_ipc;
	struct cnode *cnode;
	unsigned long flags;

	printk(KERN_ERR "ipc_recv:%s: receiving on cap %lld\n", current->comm, rvp_cap);
	
        cnode = lcd_cnode_lookup(&current->cspace, rvp_cap);
	if (cnode == NULL || cnode->type != LCD_TYPE_SYNC_EP) {
		printk(KERN_ERR "ipc_recv: can't resolve capability: %lld\n", rvp_cap);
		return -EINVAL;   
	}

	sync_ipc = (struct sync_ipc *) cnode->object;
	
	BUG_ON(!sync_ipc); 

	// XXX: BU: Maybe I need to do some reference counting for IPC 
	// objects here (before releasing the lock)
	lcd_cnode_release(cnode);

	spin_lock_irqsave(&sync_ipc->lock, flags); 	
	if (list_empty(&sync_ipc->senders)) {

		set_current_state(TASK_INTERRUPTIBLE);
		list_add_tail(&current->sync_rendezvous, &sync_ipc->receivers);
		
		printk(KERN_ERR "ipc_recv:%s: putting myself to sleep\n", current->comm);
		
		spin_unlock_irqrestore(&sync_ipc->lock, flags);
		schedule();		
		printk(KERN_ERR "ipc_recv: somone woke me up\n");
		return 0; 
	}

	send_task = list_first_entry(&sync_ipc->senders,
					struct task_struct, 
					sync_rendezvous);

        list_del(&send_task->sync_rendezvous); 
	spin_unlock_irqrestore(&sync_ipc->lock, flags);
	 
	printk(KERN_ERR "ipc_send: other end %s\n", send_task->comm);
	
	// copy the message registers
	// XXX: BU: maybe MIN(of valid_regs)?
	memcpy(current->utcb->msg_info.regs, 
		send_task->utcb->msg_info.regs, 
		sizeof(uint64_t)*send_task->utcb->msg_info.valid_regs);

	// BU: TODO: transfer capabilities

	wake_up_process(send_task); 
	printk(KERN_ERR "ipc_recv: finished\n");
	return 0;

}
EXPORT_SYMBOL(ipc_recv);


