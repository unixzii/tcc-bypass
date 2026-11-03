// Shared wire ABI; port names are local to their owning task.

#pragma once

#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <mach/notify.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TC_SERVICE "me.cyandev.tcc-bypass.control"
#define TC_SUBSYSTEM "me.cyandev.tcc-bypass"

enum { TCVersion = 1, TCMagic = 0x54434342, TCMaxBody = 16384 };

typedef enum : uint32_t {
    TCHello = 1,
    TCEnable,
    TCDisable,
    TCStatus,
    TCBypassLog,
    TCAttach,
    TCSubscribe,
    TCReplayBegin,
    TCReplayEnd,
    TCStreamEnd,
    TCGap,
    TCError = 255
} TCOperation;

#pragma pack(push, 4)

typedef struct {
    mach_msg_header_t header;
    uint32_t magic, version, operation, length;
    uint64_t request;
    char body[TCMaxBody];
} TCFrame;

#pragma pack(pop)

typedef struct {
    TCFrame frame;
    mach_msg_max_trailer_t trailer;
} TCMessage;

static inline mach_msg_size_t TCFrameSize(uint32_t length) {
    return (mach_msg_size_t)((offsetof(TCFrame, body) + length + 3) & ~3u);
}

static inline void TCPrepare(TCFrame *frame, TCOperation op, uint64_t request, const void *body,
                             uint32_t length) {
    memset(frame, 0, sizeof(*frame));
    frame->magic = TCMagic;
    frame->version = TCVersion;
    frame->operation = op;
    frame->request = request;
    frame->length = length;
    frame->header.msgh_size = TCFrameSize(length);
    frame->header.msgh_id = TCMagic;
    if (length)
        memcpy(frame->body, body, length);
}

static inline BOOL TCValidate(TCMessage *message, audit_token_t *audit) {
    TCFrame *frame = &message->frame;
    if (frame->header.msgh_size < offsetof(TCFrame, body) ||
        frame->header.msgh_bits & MACH_MSGH_BITS_COMPLEX || frame->magic != TCMagic ||
        frame->version != TCVersion || frame->length > TCMaxBody ||
        frame->header.msgh_size != TCFrameSize(frame->length))
        return NO;

    mach_msg_audit_trailer_t *trailer = (void *)((char *)message + frame->header.msgh_size);
    if (trailer->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 ||
        trailer->msgh_trailer_size < sizeof(*trailer))
        return NO;

    *audit = trailer->msgh_audit;
    return YES;
}

static inline kern_return_t TCPost(TCFrame *frame, mach_port_t destination,
                                   mach_msg_type_name_t disposition, mach_port_t reply,
                                   mach_msg_type_name_t replyDisposition, unsigned timeout) {
    frame->header.msgh_remote_port = destination;
    frame->header.msgh_local_port = reply;
    frame->header.msgh_bits = MACH_MSGH_BITS(disposition, replyDisposition);
    return mach_msg(&frame->header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, frame->header.msgh_size, 0,
                    0, timeout, 0);
}

static inline kern_return_t TCRead(TCMessage *message, mach_port_t port, unsigned timeout) {
    memset(message, 0, sizeof(*message));
    return mach_msg(&message->frame.header,
                    MACH_RCV_MSG | MACH_RCV_TIMEOUT |
                        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
                        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
                    0, sizeof(*message), port, timeout, 0);
}

static inline mach_port_t TCReceivePort(void) {
    mach_port_t port = 0;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port))
        return 0;

    mach_port_limits_t limits = {.mpl_qlimit = 128};
    mach_port_set_attributes(mach_task_self(), port, MACH_PORT_LIMITS_INFO,
                             (mach_port_info_t)&limits, MACH_PORT_LIMITS_INFO_COUNT);
    return port;
}

static inline void TCDestroyReceive(mach_port_t port) {
    if (port)
        mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
}

// A dead-name notification adds a user reference: the caller must release it.
static inline void TCWatchDead(mach_port_t send, mach_port_t notifications) {
    mach_port_t previous = 0;
    mach_port_request_notification(mach_task_self(), send, MACH_NOTIFY_DEAD_NAME, 0, notifications,
                                   notifications ? MACH_MSG_TYPE_MAKE_SEND_ONCE : 0, &previous);
    if (previous)
        mach_port_deallocate(mach_task_self(), previous);
}

static inline mach_port_t TCDeadName(TCMessage *message) {
    // Apple's notification typedef includes a receive trailer, while msgh_size
    // stops before it. Comparing against sizeof would silently miss port death.
    if (message->frame.header.msgh_id != MACH_NOTIFY_DEAD_NAME ||
        message->frame.header.msgh_size != offsetof(mach_dead_name_notification_t, trailer))
        return 0;
    return ((mach_dead_name_notification_t *)message)->not_port;
}

#ifdef __OBJC__

#import <Foundation/Foundation.h>

static inline NSData *TCEncode(id value) {
    return [NSJSONSerialization dataWithJSONObject:value
                                           options:NSJSONWritingSortedKeys
                                             error:NULL];
}

static inline id TCDecode(TCFrame *frame) {
    return [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:frame->body
                                                                  length:frame->length]
                                           options:0
                                             error:NULL];
}

static inline kern_return_t TCSendJSON(mach_port_t destination, TCOperation operation,
                                       uint64_t request, id value, unsigned timeout) {
    NSData *data = TCEncode(value);
    if (!data || data.length > TCMaxBody)
        return MACH_SEND_TOO_LARGE;

    TCFrame frame;
    TCPrepare(&frame, operation, request, data.bytes, (uint32_t)data.length);
    return TCPost(&frame, destination, MACH_MSG_TYPE_COPY_SEND, 0, 0, timeout);
}

#endif
