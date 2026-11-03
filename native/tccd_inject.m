// Hooks and a private Mach endpoint inside each tccd.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <os/lock.h>
#import <os/log.h>
#import <xpc/xpc.h>
#include <stdatomic.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#import "Attribution.h"
#import "ControlProtocol.h"

__attribute__((used, visibility("default"))) mach_port_t cyan_tccd_control_receive = 0;
__attribute__((used, visibility("default"))) int cyan_tccd_inject_ready = 0;

static os_log_t gLog;
static dispatch_source_t gReceiveSource;
static mach_port_t gCallback;
static audit_token_t gPeerAudit;
static os_unfair_lock gPeerLock = OS_UNFAIR_LOCK_INIT;
static _Atomic bool gConnected;
static _Atomic uint64_t gExpiry, gGenerated, gSent, gDropped, gOversized;

typedef id (*ContextInitIMP)(id __attribute__((ns_consumed)), SEL, xpc_object_t, id, id *)
    __attribute__((ns_returns_retained));
typedef BOOL (*HasEntitlementIMP)(id, SEL, id, id, unsigned long long);
typedef id (*ChainInitIMP)(id __attribute__((ns_consumed)), SEL, xpc_object_t, BOOL, id)
    __attribute__((ns_returns_retained));

static ContextInitIMP gOriginalInit;
static HasEntitlementIMP gOriginalHasEntitlement;
static ChainInitIMP gOriginalChainInit;

static uint64_t activeExpiry(void) {
    uint64_t expiry = atomic_load(&gExpiry);
    return atomic_load(&gConnected) && expiry > (uint64_t)time(NULL) ? expiry : 0;
}

// Take an extra user reference while holding the lock, so a hook cannot use a
// recycled port name while the control queue disconnects or replaces the peer.
static mach_port_t retainCallback(void) {
    os_unfair_lock_lock(&gPeerLock);
    mach_port_t port = gCallback;
    if (port && mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, 1))
        port = 0;
    os_unfair_lock_unlock(&gPeerLock);
    return port;
}

static void disconnectPeer(void) {
    os_unfair_lock_lock(&gPeerLock);
    mach_port_t old = gCallback;
    gCallback = 0;
    atomic_store(&gConnected, false);
    atomic_store(&gExpiry, 0);
    memset(&gPeerAudit, 0, sizeof(gPeerAudit));
    os_unfair_lock_unlock(&gPeerLock);
    if (old) {
        TCWatchDead(old, 0);
        mach_port_deallocate(mach_task_self(), old);
    }
}

static NSDictionary *state(void) {
    uint64_t expiry = activeExpiry();
    return @{
        @"pid": @(getpid()),
        @"uid": @(geteuid()),
        @"hooks_ready": @((BOOL)(cyan_tccd_inject_ready == 1)),
        @"connected": @(atomic_load(&gConnected)),
        @"enabled": @((BOOL)(expiry != 0)),
        @"expires_at": @(expiry),
        @"logs_generated": @(atomic_load(&gGenerated)),
        @"logs_sent": @(atomic_load(&gSent)),
        @"logs_dropped": @(atomic_load(&gDropped)),
        @"logs_oversized": @(atomic_load(&gOversized))
    };
}

static void sendReply(TCFrame *request, NSDictionary *value, TCOperation operation) {
    mach_port_t callback = retainCallback();
    if (!callback)
        return;
    if (TCSendJSON(callback, operation, request->request, value, 100))
        os_log_error(gLog, "control reply send failed");
    mach_port_deallocate(mach_task_self(), callback);
}

static void handleControl(TCMessage *message) {
    mach_port_t dead = TCDeadName(message);
    if (dead) {
        BOOL current = dead == gCallback;
        mach_port_deallocate(mach_task_self(), dead); // notification's extra reference
        if (current) {
            disconnectPeer();
            os_log(gLog, "helper disconnected; bypass disabled");
        }
        return;
    }

    audit_token_t audit;
    if (!TCValidate(message, &audit)) {
        mach_msg_destroy(&message->frame.header);
        return;
    }

    TCFrame *frame = &message->frame;
    if (audit_token_to_euid(audit) != 0) {
        mach_msg_destroy(&frame->header);
        return;
    }

    if (frame->operation == TCHello) {
        if (MACH_MSGH_BITS_REMOTE(frame->header.msgh_bits) != MACH_MSG_TYPE_PORT_SEND ||
            !MACH_PORT_VALID(frame->header.msgh_remote_port)) {
            mach_msg_destroy(&frame->header);
            return;
        }
        disconnectPeer();
        os_unfair_lock_lock(&gPeerLock);
        gCallback = frame->header.msgh_remote_port;
        frame->header.msgh_remote_port = 0;
        gPeerAudit = audit;
        os_unfair_lock_unlock(&gPeerLock);
        TCWatchDead(gCallback, cyan_tccd_control_receive);
        atomic_store(&gConnected, true);
        sendReply(frame, state(), TCHello);
    } else if (memcmp(&audit, &gPeerAudit, sizeof(audit)) == 0) {
        if (frame->operation == TCEnable) {
            id value = TCDecode(frame);
            id raw = [value isKindOfClass:NSDictionary.class] ? value[@"expires_at"] : nil;
            uint64_t expiry = [raw isKindOfClass:NSNumber.class] ? [raw unsignedLongLongValue] : 0;
            uint64_t now = (uint64_t)time(NULL);
            if (expiry <= now || expiry > now + 86400) {
                sendReply(frame, @{@"error": @"invalid expiry"}, TCError);
            } else {
                atomic_store(&gExpiry, expiry);
                sendReply(frame, state(), TCEnable);
            }
        } else if (frame->operation == TCDisable) {
            atomic_store(&gExpiry, 0);
            sendReply(frame, state(), TCDisable);
        } else if (frame->operation == TCStatus) {
            sendReply(frame, state(), TCStatus);
        }
    }
    mach_msg_destroy(&frame->header);
}

static id hookedInit(id self __attribute__((ns_consumed)), SEL selector, xpc_object_t message,
                     id server, id *error) __attribute__((ns_returns_retained));

static id hookedInit(id self __attribute__((ns_consumed)), SEL selector, xpc_object_t message,
                     id server, id *error) {
    id context = gOriginalInit(self, selector, message, server, error);
    int savedErrno = errno;
    @try {
        if (context)
            TCCaptureAttribution(context);
    } @catch (
        __unused NSException *exception) { /* Missing attribution must not alter TCC behavior. */
    }
    errno = savedErrno;
    return context;
}

static id hookedChainInit(id self __attribute__((ns_consumed)), SEL selector, xpc_object_t message,
                          BOOL evaluate, id processInfo) __attribute__((ns_returns_retained));

static id hookedChainInit(id self __attribute__((ns_consumed)), SEL selector, xpc_object_t message,
                          BOOL evaluate, id processInfo) {
    id chain = gOriginalChainInit(self, selector, message, evaluate, processInfo);
    int savedErrno = errno;
    @try {
        if (chain)
            TCCaptureChain(chain, message);
    } @catch (__unused NSException *exception) { /* Keep the original request outcome. */
    }
    errno = savedErrno;
    return chain;
}

static void sendBypassLog(id process, id service, unsigned long long options, BOOL original,
                          uint64_t expiry) {
    uint64_t sequence = atomic_fetch_add(&gGenerated, 1) + 1;
    mach_port_t callback = retainCallback();
    if (!callback) {
        atomic_fetch_add(&gDropped, 1);
        return;
    }
    NSData *data = TCEncode(TCBypassRecord(process, service, options, original, expiry));
    if (!data || data.length > TCMaxBody) {
        atomic_fetch_add(&gOversized, 1);
        atomic_fetch_add(&gDropped, 1);
    } else {
        TCFrame frame;
        TCPrepare(&frame, TCBypassLog, sequence, data.bytes, (uint32_t)data.length);
        // No queue, retry, file, or os_log copy of the record inside tccd.
        // A full helper receive queue drops this record instead of blocking TCC.
        if (TCPost(&frame, callback, MACH_MSG_TYPE_COPY_SEND, 0, 0, 0))
            atomic_fetch_add(&gDropped, 1);
        else
            atomic_fetch_add(&gSent, 1);
    }
    mach_port_deallocate(mach_task_self(), callback);
}

static BOOL hookedHasEntitlement(id self, SEL selector, id entitlement, id service,
                                 unsigned long long options) {
    BOOL original = gOriginalHasEntitlement(self, selector, entitlement, service, options);
    int savedErrno = errno;
    BOOL result = original;
    if ([entitlement isKindOfClass:NSString.class] &&
        [entitlement isEqualToString:@"com.apple.private.tcc.allow"]) {
        uint64_t expiry = activeExpiry();
        if (expiry) {
            result = YES;
            @try {
                sendBypassLog(self, service, options, original, expiry);
            } @catch (__unused NSException *exception) {
                atomic_fetch_add(&gDropped, 1);
            }
        }
    }
    errno = savedErrno;
    return result;
}

__attribute__((constructor)) static void initializeInject(void) {
    @autoreleasepool {
        gLog = os_log_create(TC_SUBSYSTEM, "lifecycle");
        Class context = objc_getClass("TCCDRequestContext"), process = objc_getClass("TCCDProcess");
        if (!context || !process)
            return;
        SEL init = sel_getUid("initWithRequestMessage:forServer:error:");
        SEL has = sel_getUid("hasEntitlement:containsService:options:");
        Method initMethod = class_getInstanceMethod(context, init),
               hasMethod = class_getInstanceMethod(process, has);
        NSMethodSignature *a = [context instanceMethodSignatureForSelector:init];
        NSMethodSignature *b = [process instanceMethodSignatureForSelector:has];
        if (!initMethod || !hasMethod || a.numberOfArguments != 5 || a.methodReturnType[0] != '@' ||
            b.numberOfArguments != 5 || strcmp(b.methodReturnType, @encode(BOOL)) ||
            strcmp([b getArgumentTypeAtIndex:4], @encode(unsigned long long))) {
            cyan_tccd_inject_ready = -1;
            os_log_error(gLog, "unsupported hook signatures");
            return;
        }
        const void *loaded = (const void *)sel_getUid("me.cyandev.tcc-bypass.loaded");
        @synchronized(process) {
            if (objc_getAssociatedObject(process, loaded)) {
                cyan_tccd_inject_ready = -2;
                return;
            }
            cyan_tccd_control_receive = TCReceivePort();
            if (!cyan_tccd_control_receive) {
                cyan_tccd_inject_ready = -3;
                return;
            }
            // Some entitlement checks precede RequestContext creation. Bind the
            // chain first; the context hook later enriches the same request ID.
            Class chain = objc_getClass("TCCDAttributionChain");
            SEL chainInit = sel_getUid("initWithMessage:evaluateResponsibility:processInfo:");
            Method chainMethod = class_getInstanceMethod(chain, chainInit);
            NSMethodSignature *c = [chain instanceMethodSignatureForSelector:chainInit];
            if (chainMethod && c.numberOfArguments == 5 && c.methodReturnType[0] == '@' &&
                !strcmp([c getArgumentTypeAtIndex:3], @encode(BOOL))) {
                gOriginalChainInit = (ChainInitIMP)method_getImplementation(chainMethod);
                method_setImplementation(chainMethod, (IMP)hookedChainInit);
            } else
                os_log_error(gLog, "chain hook unavailable; context-only attribution");
            gOriginalInit = (ContextInitIMP)method_getImplementation(initMethod);
            method_setImplementation(initMethod, (IMP)hookedInit);
            gOriginalHasEntitlement = (HasEntitlementIMP)method_getImplementation(hasMethod);
            method_setImplementation(hasMethod, (IMP)hookedHasEntitlement);
            objc_setAssociatedObject(process, loaded, @YES, OBJC_ASSOCIATION_RETAIN);
        }
        dispatch_queue_t queue =
            dispatch_queue_create("me.cyandev.tcc-bypass.control", DISPATCH_QUEUE_SERIAL);
        gReceiveSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV,
                                                cyan_tccd_control_receive, 0, queue);
        dispatch_source_set_event_handler(gReceiveSource, ^{
            @autoreleasepool {
                TCMessage message;
                while (TCRead(&message, cyan_tccd_control_receive, 0) == KERN_SUCCESS)
                    handleControl(&message);
            }
        });
        dispatch_activate(gReceiveSource);
        cyan_tccd_inject_ready = 1;
        os_log(gLog, "inject ready pid=%d; bypass disabled until helper enables it", getpid());
    }
}
