#include "kinc.h"
#define size_t size_t_
#include <stdarg.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/sockio.h>
#include <netinet/in.h>

////#define FOR_BOOT

#define _SYSCALL_RET_NONE 0

int _NSConcreteGlobalBlock;

#define _assert(x) do { if(!(x)) panic("_assert failure line %d: %s (errno=%d)", __LINE__, #x, errno); } while(0)
#define _assert_zero(x) do { int _val = (x); if(_val) panic("_assert failure line %d: %s was %x", __LINE__, #x, _val); } while(0)


void run_in_milk_thread(void (^action)());

extern struct sysent sysent[];
int errno = 0;
int syscall(int num, uint32_t *uap) {
    /*
    for(int i = 0; i < 6; i++) {
        IOLog("syscall: uap[%d] = %x\n", i, uap[i]);
    }
    IOLog("syscall: sy_call = %p\n", sysent[num].sy_call);
    */

    errno = 0;
    int result, result2 = 0;
    result = sysent[num].sy_call(current_proc(), (void *) uap, &result2);
    if(result == 0) {
        return result2;
    } else {
        errno = result;
        return -1;
    }
}

#define syscall1(num, a) syscall(num, (uint32_t[]) { (uint32_t) (a) })
#define syscall2(num, a, b) syscall(num, (uint32_t[]) { (uint32_t) (a), (uint32_t) (b) })
#define syscall3(num, a, b, c) syscall(num, (uint32_t[]) { (uint32_t) (a), (uint32_t) (b), (uint32_t) (c) })

#define close(args...) syscall1(6, args)
#define socket(args...) syscall3(97, args)
#define ioctl(args...) syscall3(54, args)
#define write(a, b, c) ((ssize_t) syscall(

void loopback_setup_ipv4() {
    IOLog("setting up ipv4\n");

    // borrowed from launchd
    struct ifaliasreq ifra;
    struct ifreq ifr;
    int s;

    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, "lo0", 4);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    _assert(s != -1);

    _assert(!ioctl(s, SIOCGIFFLAGS, &ifr));
    ifr.ifr_flags |= IFF_UP;
    _assert(!ioctl(s, SIOCSIFFLAGS, &ifr));

    memset(&ifra, 0, sizeof(ifra));
    memcpy(ifra.ifra_name, "lo0", 4);
    ((struct sockaddr_in *)&ifra.ifra_addr)->sin_family = AF_INET;
    ((struct sockaddr_in *)&ifra.ifra_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ((struct sockaddr_in *)&ifra.ifra_addr)->sin_len = sizeof(struct sockaddr_in);
    ((struct sockaddr_in *)&ifra.ifra_mask)->sin_family = AF_INET;
    ((struct sockaddr_in *)&ifra.ifra_mask)->sin_addr.s_addr = htonl(IN_CLASSA_NET);
    ((struct sockaddr_in *)&ifra.ifra_mask)->sin_len = sizeof(struct sockaddr_in);

    _assert(!ioctl(s, SIOCAIFADDR, &ifra));

    _assert(!close(s));
}
extern int wtf asm("$vt___ZN9IOService13newUserClientEP4taskPvmP12OSDictionaryPP12IOUserClient");

void userclient_stuff() {
    IOLog("doing user client\n");

    void *properties = OSUnserializeXML(
        "<dict>\n"
        "    <key>USBDeviceCommand</key>\n"
        "    <string>SetDeviceDescription</string>\n"
        "    <key>USBDeviceCommandParameter</key>\n"
        "    <dict>\n"
        "            <key>ConfigurationDescriptors</key>\n"
        "            <array>\n"
        "                <dict>\n"
        "                    <key>Description</key>\n"
        "                    <string>PTP</string>\n"
        "                    <key>Interfaces</key>\n"
        "                    <array>\n"
        "                        <string>PTP</string>\n"
        "                    </array>\n"
        "                </dict>\n"
        "                <dict>\n"
        "                    <key>AccessoryResistorSwap</key>\n"
        "                    <true/>\n"
        "                    <key>Description</key>\n"
        "                    <string>iPod USB Interface</string>\n"
        "                    <key>Interfaces</key>\n"
        "                    <array>\n"
        "                        <string>USBAudioControl</string>\n"
        "                        <string>USBAudioStreaming</string>\n"
        "                        <string>IapOverUsbHid</string>\n"
        "                    </array>\n"
        "                </dict>\n"
        "                <dict>\n"
        "                    <key>DefaultConfiguration</key>\n"
        "                    <true/>\n"
        "                    <key>Description</key>\n"
        "                    <string>PTP + Apple Mobile Device</string>\n"
        "                    <key>Interfaces</key>\n"
        "                    <array>\n"
        "                        <string>PTP</string>\n"
        "                        <string>AppleUSBMux</string>\n"
        "                    </array>\n"
        "                </dict>\n"
        "            </array>\n"
        "            <key>deviceID</key>\n"
        "            <integer>1</integer>\n"
        "            <key>manufacturerString</key>\n"
        "            <string>Apple Inc.</string>\n"
        "            <key>productID</key>\n"
        "            <integer>4765</integer>\n"
        "            <key>productString</key>\n"
        "            <string>iProd</string>\n"
        "            <key>vendorID</key>\n"
        "            <integer>1452</integer>\n"
        "    </dict>\n"
        "</dict>\n"
    , NULL);
    _assert(properties);

    void *interface_matching = OSUnserializeXML("<dict><key>IOProviderClass</key><string>IOUSBDeviceController</string></dict>", NULL);
    _assert(interface_matching);

    void *interface2_matching = OSUnserializeXML("<dict><key>IOProviderClass</key><string>IOUSBDeviceInterface</string><key>IOPropertyMatch</key><dict><key>USBDeviceFunction</key><string>PTP</string></dict></dict>", NULL);
    _assert(interface2_matching);

    void *interface = IOService_waitForMatchingService(interface_matching, (uint64_t) -1);
    _assert(interface);

    IOLog("setProperties = %x\n", IORegistryEntry_setProperties(interface, properties));
    
    void *interface2 = IOService_waitForMatchingService(interface2_matching, (uint64_t) -1);
    _assert(interface2);

    void *client;
    _assert_zero(IOService_newUserClient(interface2, current_task(), current_task(), 0, NULL, &client));
    
    struct IOExternalMethodArguments args;
    uint64_t input[2];
    memset(&input, 0, sizeof(input));
    memset(&args, 0, sizeof(args));
    args.version = 1;
    args.scalarInput = &input[0];

    args.scalarInputCount = 1;
    args.selector = 0;
    IOLog("open = %x\n", IOUserClient_externalMethod(client, args.selector, &args));

    args.scalarInputCount = 2;
    args.selector = 3;
    input[0] = 0xff;
    _assert_zero(IOUserClient_externalMethod(client, args.selector, &args)); 

    args.selector = 4;
    input[0] = 0x50;
    _assert_zero(IOUserClient_externalMethod(client, args.selector, &args)); 
   
    args.selector = 5;
    input[0] = 0x34;
    _assert_zero(IOUserClient_externalMethod(client, args.selector, &args)); 

    args.selector = 11;
    args.scalarInputCount = 0;
    _assert_zero(IOUserClient_externalMethod(client, args.selector, &args)); 

    IOUserClient_clientClose(client); // no assert

    // scalar(0, [0], [])         _open
    // scalar(3, [0xff, 0], [])   _setClassForAlternateSetting
    // scalar(4, [0x50, 0], [])   _setSubClassForAlternateSetting
    // scalar(5, [0x34, 0], [])   _setProtocolForAlternateSetting
    // scalar(11, [], [])         _commitConfiguration

    //OSObject_release(client);
    OSObject_release(properties);
    OSObject_release(interface_matching);
    OSObject_release(interface2_matching);

}


static struct milk_thread_pending {
    void (^action)();
    void *channel;
    struct milk_thread_pending *next;
} *pending;

static lck_grp_t *milk_lck_grp;
static lck_mtx_t *milk_lck; // used as channel

void milk_thread_routine(void *a, int b) {
    lck_mtx_lock(milk_lck);

    while(1) {
        struct milk_thread_pending *p = pending;
        if(p) {
            void (^action)() = p->action;
            if(action) {
                action();
            }
            wakeup(p->channel);
            pending = p->next;
            IOFree(p);
            if(!action) {
                // our cue to stop
                break;
            }
        }
        msleep(&milk_lck, milk_lck, 0, "milk thread", NULL);
    }

    lck_mtx_unlock(milk_lck);
}

void run_in_milk_thread(void (^action)()) {
    int channel;

    lck_mtx_lock(milk_lck);
    struct milk_thread_pending *new = IOMalloc(sizeof(*new));
    new->action = action;
    new->channel = &channel;
    new->next = pending;
    pending = new;
    wakeup(&milk_lck);
    msleep(&channel, milk_lck, 0, "milk waiter", NULL);
    lck_mtx_unlock(milk_lck);
}

__attribute__((constructor))
void init() {
    milk_lck_grp = lck_grp_alloc_init("milk", NULL);
    milk_lck = lck_mtx_alloc_init(milk_lck_grp, NULL);

    mach_port_t thread; 
    _assert_zero(kernel_thread_start(&milk_thread_routine, NULL, &thread));

    run_in_milk_thread(^{
        extern proc_t kernproc;
        IOLog("Hello, current_proc = %p kernproc=%p\n", current_proc(), kernproc);
        loopback_setup_ipv4();
        userclient_stuff();
    });
}

__attribute__((destructor))
void fini() {
    run_in_milk_thread((void (^)()) 0); // cancel

    lck_mtx_free(milk_lck, milk_lck_grp);
    lck_grp_free(milk_lck_grp);
}
