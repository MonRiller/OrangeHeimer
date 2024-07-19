#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

void *(*orig_g_strdup)(const char*);
int found = 0;

#define TARGET "secure-memory"
#define UNIMP "unimplemented-device"

extern void* get_system_memory(void);
extern void* qdev_new(char*);
extern void memory_region_init_ram(void*, void*, char*, uint64_t, uint64_t*);
extern void memory_region_add_subregion(void*, uint64_t, void*);
extern void sysbus_mmio_map(void*, uint64_t, uint64_t);
extern void sysbus_mmio_map_overlap(void*, uint64_t, uint64_t, int64_t);
extern void sysbus_realize_and_unref(void*, uint64_t*);

extern void object_property_set_int(void*, char*, uint64_t, uint64_t*);
extern void object_property_set_uint(void*, char*, uint64_t, uint64_t*);
extern void object_property_set_str(void*, char*, char*, uint64_t*);

extern void* g_malloc(uint64_t);

void add_unimp(uint64_t address, uint64_t size, char* name)
{
    uint64_t err;
    void *dev;

    dev = qdev_new(UNIMP);
    object_property_set_uint(dev, "size", size, &err);
    object_property_set_str(dev, "name", name, &err);
    sysbus_realize_and_unref(dev, &err);
    sysbus_mmio_map_overlap(dev, 0, address, 1);
}

void add_ram(uint64_t address, uint64_t size, char* name)
{
    uint64_t err;
    void *sysmem = get_system_memory();
    void *mem = g_malloc(0x100);

    memory_region_init_ram(mem, NULL, name, size, &err);
    memory_region_add_subregion(sysmem, address, mem);
}

void add_target_mem_or_devs(void)
{
    //TODO: add any memory or devices you want here, be careful of overwriting things that should exist.
    // add_ram(0x60080100, 0xC000, "rammyzane");
    // start at low addy (and size should be round numbers for RAM page alignment)
    add_unimp(0x60080100, 0x18, "bd");
    add_unimp(0x60080120, 0x18, "hatch");
    add_unimp(0x60080200, 0x18, "wl");
    add_unimp(0x60080220, 0x18, "rl");
    add_unimp(0x60080240, 0x18, "mr");
    add_unimp(0x60080260, 0x18, "tc");
    add_unimp(0x60080280, 0x18, "lc");

    
}

void *g_strdup(const char* buf)
{
    if(orig_g_strdup == NULL)
    {
        orig_g_strdup = dlsym(RTLD_NEXT, "g_strdup");
    }
    if(found == 0 && buf != NULL)
    {
        if(strcmp(buf, TARGET) == 0)
        {
            add_target_mem_or_devs();
            found = 1;
        }        
    }
    return orig_g_strdup(buf);
}
