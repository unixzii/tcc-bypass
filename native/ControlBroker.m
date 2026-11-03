// All mutable broker state belongs to one Mach-port event loop.

#import "ControlHelper.h"
#import "ControlProtocol.h"
#import "LogRing.h"
#include <libproc.h>
#include <os/log.h>
#include <servers/bootstrap.h>
#include <unistd.h>

static NSTimeInterval now(void) {
    return NSProcessInfo.processInfo.systemUptime;
}

static const char *tccdPath = "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd";

@interface TCPeer : NSObject
@property pid_t pid;
@property mach_port_t send, receive;
@property BOOL ready, identified;
@property audit_token_t audit;
@property NSTimeInterval helloDeadline;
@end

@implementation TCPeer
@end

@interface TCRequest : NSObject
@property uint64_t identifier;
@property TCOperation operation;
@property mach_port_t reply;
@property NSTimeInterval deadline;
@property(strong) NSArray<TCPeer *> *peers;
@property(strong) NSMutableDictionary<NSNumber *, id> *results;
@property(strong) NSMutableDictionary<NSNumber *, NSString *> *errors;
@end

@implementation TCRequest
@end

@interface TCSubscriber : NSObject
@property mach_port_t send;
@property uint64_t cursor, boundary;
@property BOOL began, replayEnded, follow;
@end

@implementation TCSubscriber
@end

static NSArray<NSNumber *> *liveTccd(void) {
    int count = proc_listallpids(NULL, 0);
    if (count <= 0)
        return nil;
    NSMutableData *storage =
        [NSMutableData dataWithLength:(NSUInteger)(count + 64) * sizeof(pid_t)];
    count = proc_listallpids(storage.mutableBytes, (int)storage.length);
    if (count < 0)
        return nil;
    NSMutableArray *result = [NSMutableArray new];
    pid_t *pids = storage.mutableBytes;
    int available = MIN(count, (int)(storage.length / sizeof(pid_t)));
    for (int i = 0; i < available; i++) {
        char path[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strcmp(path, tccdPath) == 0)
            [result addObject:@(pids[i])];
    }
    return [result sortedArrayUsingSelector:@selector(compare:)];
}

static void oneReply(mach_port_t reply, TCOperation operation, uint64_t request, id value) {
    NSData *data = TCEncode(value);
    if (!data || data.length > TCMaxBody) {
        operation = TCError;
        data = TCEncode(@{@"ok": @NO, @"error": @"response_too_large"});
    }
    TCFrame frame;
    TCPrepare(&frame, operation, request, data.bytes, (uint32_t)data.length);
    if (TCPost(&frame, reply, MACH_MSG_TYPE_MOVE_SEND_ONCE, 0, 0, 100))
        mach_port_deallocate(mach_task_self(), reply);
}

@interface TCBroker : NSObject
- (instancetype)initWithCapacity:(NSUInteger)capacity;
- (int)run:(NSArray<NSDictionary *> *)connections;
@end

@implementation TCBroker {
    mach_port_t _clients, _notifications, _portSet;
    NSMutableDictionary<NSNumber *, TCPeer *> *_peers;
    NSMutableDictionary<NSNumber *, TCPeer *> *_receivers;
    NSMutableDictionary<NSNumber *, TCRequest *> *_requests;
    NSMutableDictionary<NSNumber *, TCSubscriber *> *_subscribers;
    TCLogRing *_ring;
    NSString *_session;
    uint64_t _nextRequest, _oversized;
    BOOL _hadPeers;
    os_log_t _logger;
}

- (instancetype)initWithCapacity:(NSUInteger)capacity {
    if ((self = [super init])) {
        _peers = [NSMutableDictionary new];
        _receivers = [NSMutableDictionary new];
        _requests = [NSMutableDictionary new];
        _subscribers = [NSMutableDictionary new];
        _ring = [[TCLogRing alloc] initWithCapacity:capacity byteLimit:8 * 1024 * 1024];
        _session = NSUUID.UUID.UUIDString;
        _nextRequest = 1;
        _logger = os_log_create(TC_SUBSYSTEM, "helper");
    }
    return self;
}

- (NSDictionary *)ringState {
    return @{
        @"records": @(_ring.count),
        @"bytes": @(_ring.bytes),
        @"first_sequence": @(_ring.firstSequence),
        @"last_sequence": @(_ring.lastSequence),
        @"evicted": @(_ring.evicted),
        @"oversized": @(_oversized)
    };
}

- (NSString *)addConnection:(NSDictionary *)value {
    if (![value isKindOfClass:NSDictionary.class] ||
        ![value[@"pid"] isKindOfClass:NSNumber.class] ||
        ![value[@"receive"] isKindOfClass:NSNumber.class])
        return @"invalid_connection";
    pid_t pid = [value[@"pid"] intValue];
    mach_port_t targetName = [value[@"receive"] unsignedIntValue];
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (pid <= 0 || !targetName || proc_pidpath(pid, path, sizeof(path)) <= 0 ||
        strcmp(path, tccdPath))
        return @"target_is_not_tccd";
    if (_peers[@(pid)])
        return nil; // Repeated start/renew does not reset an existing channel.
    task_t task = 0;
    mach_port_t send = 0, receive = 0;
    mach_msg_type_name_t type = 0;
    kern_return_t result = task_for_pid(mach_task_self(), pid, &task);
    if (result)
        return [NSString stringWithFormat:@"task_for_pid:%d", result];
    result = mach_port_extract_right(task, targetName, MACH_MSG_TYPE_MAKE_SEND, &send, &type);
    mach_port_deallocate(mach_task_self(), task); // The resident helper never retains task ports.
    if (result || type != MACH_MSG_TYPE_PORT_SEND)
        return @"port_handoff_failed";
    receive = TCReceivePort();
    if (!receive) {
        mach_port_deallocate(mach_task_self(), send);
        return @"receive_port_failed";
    }
    TCPeer *peer = [TCPeer new];
    peer.pid = pid;
    peer.send = send;
    peer.receive = receive;
    peer.helloDeadline = now() + 3;
    _peers[@(pid)] = peer;
    _receivers[@(receive)] = peer;
    _hadPeers = YES;
    mach_port_move_member(mach_task_self(), receive, _portSet);
    TCWatchDead(send, _notifications);
    TCFrame hello;
    TCPrepare(&hello, TCHello, 0, NULL, 0);
    if (TCPost(&hello, send, MACH_MSG_TYPE_COPY_SEND, receive, MACH_MSG_TYPE_MAKE_SEND, 100)) {
        [self removePeer:peer reason:@"handshake_send_failed"];
        return @"handshake_send_failed";
    }
    return nil;
}

- (void)removePeer:(TCPeer *)peer reason:(NSString *)reason {
    if (!peer || _peers[@(peer.pid)] != peer)
        return;
    [_peers removeObjectForKey:@(peer.pid)];
    [_receivers removeObjectForKey:@(peer.receive)];
    for (TCRequest *request in _requests.allValues) {
        if ([request.peers containsObject:peer] && !request.results[@(peer.pid)])
            request.errors[@(peer.pid)] = reason;
    }
    TCWatchDead(peer.send, 0);
    mach_port_deallocate(mach_task_self(), peer.send);
    TCDestroyReceive(peer.receive);
    peer.send = 0;
    peer.receive = 0;
    os_log(_logger, "tccd disconnected pid=%d", peer.pid);
}

- (void)removeSubscriber:(TCSubscriber *)subscriber {
    [_subscribers removeObjectForKey:@(subscriber.send)];
    TCWatchDead(subscriber.send, 0);
    mach_port_deallocate(mach_task_self(), subscriber.send);
}

- (void)handleDeath:(mach_port_t)name {
    mach_port_deallocate(mach_task_self(), name); // extra dead-name notification reference
    TCSubscriber *subscriber = _subscribers[@(name)];
    if (subscriber) {
        [self removeSubscriber:subscriber];
        return;
    }
    for (TCPeer *peer in _peers.allValues)
        if (peer.send == name) {
            [self removePeer:peer reason:@"port_dead"];
            return;
        }
}

- (void)beginRequest:(TCOperation)operation
               value:(NSDictionary *)value
               reply:(mach_port_t)reply
              errors:(NSDictionary *)errors {
    if (_requests.count >= 64) {
        oneReply(reply, TCError, 0, @{@"ok": @NO, @"error": @"busy"});
        return;
    }
    TCRequest *request = [TCRequest new];
    request.identifier = _nextRequest++;
    request.operation = operation;
    request.reply = reply;
    request.deadline = now() + 2;
    request.peers =
        [_peers.allValues sortedArrayUsingComparator:^NSComparisonResult(TCPeer *a, TCPeer *b) {
            return [@(a.pid) compare:@(b.pid)];
        }];
    request.results = [NSMutableDictionary new];
    request.errors = errors ? [errors mutableCopy] : [NSMutableDictionary new];
    _requests[@(request.identifier)] = request;
    NSData *data = TCEncode(value ?: @{});
    for (TCPeer *peer in request.peers) {
        TCFrame frame;
        TCPrepare(&frame, operation == TCAttach ? TCStatus : operation, request.identifier,
                  data.bytes, (uint32_t)data.length);
        if (TCPost(&frame, peer.send, MACH_MSG_TYPE_COPY_SEND, 0, 0, 100))
            request.errors[@(peer.pid)] = @"send_failed";
    }
}

- (void)handleClient:(TCMessage *)message audit:(audit_token_t)audit {
    TCFrame *frame = &message->frame;
    mach_port_t reply = frame->header.msgh_remote_port;
    frame->header.msgh_remote_port = 0;
    BOOL stream = frame->operation == TCSubscribe;
    mach_msg_type_name_t expected = stream ? MACH_MSG_TYPE_PORT_SEND : MACH_MSG_TYPE_PORT_SEND_ONCE;
    if (!MACH_PORT_VALID(reply) || MACH_MSGH_BITS_REMOTE(frame->header.msgh_bits) != expected) {
        if (reply)
            mach_port_deallocate(mach_task_self(), reply);
        return;
    }
    if (audit_token_to_euid(audit) != 0) {
        if (stream) {
            TCSendJSON(reply, TCStreamEnd, 0, @{@"type": @"end", @"error": @"root_required"}, 0);
            mach_port_deallocate(mach_task_self(), reply);
        } else
            oneReply(reply, TCError, 0, @{@"ok": @NO, @"error": @"root_required"});
        return;
    }
    id value = TCDecode(frame);
    if (![value isKindOfClass:NSDictionary.class]) {
        if (stream)
            mach_port_deallocate(mach_task_self(), reply);
        else
            oneReply(reply, TCError, 0, @{@"ok": @NO, @"error": @"invalid_request"});
        return;
    }
    if (stream) {
        if (_subscribers.count >= 16) {
            TCSendJSON(reply, TCStreamEnd, 0, @{@"type": @"end", @"error": @"too_many_subscribers"},
                       0);
            mach_port_deallocate(mach_task_self(), reply);
            return;
        }
        TCSubscriber *subscriber = [TCSubscriber new];
        subscriber.send = reply;
        subscriber.cursor = _ring.firstSequence;
        subscriber.boundary = _ring.lastSequence;
        subscriber.follow = ![value[@"snapshot"] boolValue];
        _subscribers[@(reply)] = subscriber;
        TCWatchDead(reply, _notifications);
    } else if (frame->operation == TCAttach) {
        NSMutableDictionary *errors = [NSMutableDictionary new];
        id connections = value[@"connections"];
        if (![connections isKindOfClass:NSArray.class]) {
            oneReply(reply, TCError, 0, @{@"ok": @NO, @"error": @"invalid_connections"});
            return;
        }
        for (NSDictionary *connection in connections) {
            NSString *error = [self addConnection:connection];
            if (error) {
                id pid = [connection isKindOfClass:NSDictionary.class] ? connection[@"pid"] : nil;
                errors[[pid isKindOfClass:NSNumber.class] ? pid : @0] = error;
            }
        }
        [self beginRequest:TCAttach value:@{} reply:reply errors:errors];
    } else if (frame->operation == TCEnable || frame->operation == TCDisable ||
               frame->operation == TCStatus) {
        [self beginRequest:(TCOperation)frame->operation value:value reply:reply errors:nil];
    } else
        oneReply(reply, TCError, 0, @{@"ok": @NO, @"error": @"unsupported_operation"});
}

- (void)handlePeer:(TCMessage *)message peer:(TCPeer *)peer audit:(audit_token_t)audit {
    TCFrame *frame = &message->frame;
    audit_token_t expected = peer.audit;
    if (audit_token_to_pid(audit) != peer.pid ||
        (peer.identified && memcmp(&audit, &expected, sizeof(audit))))
        return;
    id value = TCDecode(frame);
    if (![value isKindOfClass:NSDictionary.class])
        return;
    if (frame->operation == TCHello) {
        if (![value[@"hooks_ready"] boolValue]) {
            [self removePeer:peer reason:@"injection_invalid"];
            return;
        }
        peer.audit = audit;
        peer.identified = YES;
        peer.ready = YES;
    } else if (frame->operation == TCBypassLog && peer.ready) {
        NSDictionary *record = @{
            @"type": @"record",
            @"helper_session": _session,
            @"source_pid": @(peer.pid),
            @"source_uid": @(audit_token_to_euid(audit)),
            @"source_pid_version": @(audit_token_to_pidversion(audit)),
            @"source_sequence": @(frame->request),
            @"record": value
        };
        if (![_ring append:record])
            _oversized++;
    } else {
        TCRequest *request = _requests[@(frame->request)];
        if (!request || ![request.peers containsObject:peer])
            return;
        if (frame->operation == TCError)
            request.errors[@(peer.pid)] = value[@"error"] ?: @"target_error";
        else if (![value[@"hooks_ready"] boolValue])
            request.errors[@(peer.pid)] = @"injection_invalid";
        else
            request.results[@(peer.pid)] = value;
    }
}

- (void)finishRequests {
    for (NSNumber *key in _requests.allKeys) {
        TCRequest *request = _requests[key];
        BOOL complete = YES;
        for (TCPeer *peer in request.peers)
            if (!request.results[@(peer.pid)] && !request.errors[@(peer.pid)])
                complete = NO;
        if (!complete && now() < request.deadline)
            continue;
        for (TCPeer *peer in request.peers)
            if (!request.results[@(peer.pid)] && !request.errors[@(peer.pid)])
                request.errors[@(peer.pid)] = @"timeout";
        NSArray *live = liveTccd();
        NSMutableArray *missing = [NSMutableArray new], *results = [NSMutableArray new],
                       *errors = [NSMutableArray new];
        for (NSNumber *pid in live)
            if (!_peers[pid])
                [missing addObject:pid];
        BOOL allEnabled = request.peers.count != 0;
        for (TCPeer *peer in request.peers) {
            id state = request.results[@(peer.pid)];
            if (state) {
                [results addObject:state];
                allEnabled &= [state[@"enabled"] boolValue];
            } else
                allEnabled = NO;
        }
        for (NSNumber *pid in request.errors)
            [errors addObject:@{@"pid": pid, @"error": request.errors[pid]}];
        BOOL ok = live && live.count && request.errors.count == 0 && missing.count == 0 &&
                  results.count == live.count && results.count == request.peers.count;
        NSMutableDictionary *value = [@{
            @"ok": @(ok),
            @"enabled": @((BOOL)(ok && allEnabled)),
            @"helper_pid": @(getpid()),
            @"helper_session": _session,
            @"request_id": key,
            @"connected": @(_peers.count),
            @"expected": @(live.count),
            @"acknowledged": @(results.count),
            @"results": results,
            @"errors": errors,
            @"missing_pids": missing,
            @"ring": [self ringState]
        } mutableCopy];
        if (!live)
            value[@"error"] = @"process_discovery_failed";
        else if (!ok)
            value[@"error"] = @"incomplete_or_stale_connections";
        oneReply(request.reply, ok ? request.operation : TCError, request.identifier, value);
        [_requests removeObjectForKey:key];
    }
}

- (kern_return_t)sendTo:(TCSubscriber *)subscriber
              operation:(TCOperation)operation
                  value:(id)value {
    return TCSendJSON(subscriber.send, operation, 0, value, 0);
}

- (void)pumpSubscribers {
    for (TCSubscriber *subscriber in _subscribers.allValues) {
        for (int budget = 0; budget < 8; budget++) {
            kern_return_t result = KERN_SUCCESS;
            if (!subscriber.began) {
                result = [self sendTo:subscriber
                            operation:TCReplayBegin
                                value:@{
                                    @"type": @"replay_begin",
                                    @"helper_session": _session,
                                    @"first_sequence": @(subscriber.cursor),
                                    @"snapshot_end": @(subscriber.boundary),
                                    @"ring": [self ringState]
                                }];
                if (!result)
                    subscriber.began = YES;
            } else if (!subscriber.replayEnded && subscriber.cursor > subscriber.boundary) {
                result = [self
                       sendTo:subscriber
                    operation:TCReplayEnd
                        value:@{@"type": @"replay_end", @"snapshot_end": @(subscriber.boundary)}];
                if (!result) {
                    subscriber.replayEnded = YES;
                    if (!subscriber.follow) {
                        [self removeSubscriber:subscriber];
                        break;
                    }
                }
            } else if (subscriber.cursor < _ring.firstSequence) {
                // A slow reader may outlive retention; report the gap explicitly.
                uint64_t end = _ring.firstSequence - 1;
                if (!subscriber.replayEnded)
                    end = MIN(end, subscriber.boundary);
                result = [self sendTo:subscriber
                            operation:TCGap
                                value:@{
                                    @"type": @"gap",
                                    @"from": @(subscriber.cursor),
                                    @"to": @(end),
                                    @"reason": @"ring_evicted"
                                }];
                if (!result)
                    subscriber.cursor = end + 1;
            } else {
                TCLogEntry *entry = [_ring entry:subscriber.cursor];
                if (!entry)
                    break;
                TCFrame frame;
                TCPrepare(&frame, TCBypassLog, entry.sequence, entry.data.bytes,
                          (uint32_t)entry.data.length);
                result = TCPost(&frame, subscriber.send, MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
                if (!result)
                    subscriber.cursor++;
            }
            if (result == MACH_SEND_INVALID_DEST) {
                [self removeSubscriber:subscriber];
                break;
            }
            if (result)
                break; // Keep the cursor when the reader's queue is full.
        }
    }
}

- (int)run:(NSArray<NSDictionary *> *)connections {
    _clients = TCReceivePort();
    _notifications = TCReceivePort();
    if (!_clients || !_notifications ||
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &_portSet))
        return 1;
    mach_port_move_member(mach_task_self(), _clients, _portSet);
    mach_port_move_member(mach_task_self(), _notifications, _portSet);
    mach_port_insert_right(mach_task_self(), _clients, _clients, MACH_MSG_TYPE_MAKE_SEND);
    kern_return_t registration = bootstrap_register(bootstrap_port, TC_SERVICE, _clients);
    mach_port_deallocate(mach_task_self(), _clients);
    if (registration) {
        os_log_error(_logger, "service registration failed: %d", registration);
        return 1;
    }
    for (NSDictionary *connection in connections) {
        NSString *error = [self addConnection:connection];
        if (error)
            os_log_error(_logger, "initial connection failed: %{public}s", error.UTF8String);
    }
    if (!_hadPeers)
        return 1;
    os_log(_logger, "helper ready pid=%d", getpid());
    while (_peers.count) {
        @autoreleasepool {
            TCMessage message;
            kern_return_t result = TCRead(&message, _portSet, _subscribers.count ? 10 : 100);
            if (!result) {
                mach_port_t dead = TCDeadName(&message);
                if (message.frame.header.msgh_local_port == _notifications && dead)
                    [self handleDeath:dead];
                else {
                    audit_token_t audit;
                    if (TCValidate(&message, &audit)) {
                        if (message.frame.header.msgh_local_port == _clients)
                            [self handleClient:&message audit:audit];
                        else {
                            TCPeer *peer = _receivers[@(message.frame.header.msgh_local_port)];
                            if (peer)
                                [self handlePeer:&message peer:peer audit:audit];
                        }
                    }
                    mach_msg_destroy(&message.frame.header);
                }
            } else if (result != MACH_RCV_TIMED_OUT)
                break;
            for (TCPeer *peer in _peers.allValues)
                if (!peer.ready && now() >= peer.helloDeadline)
                    [self removePeer:peer reason:@"handshake_timeout"];
            [self finishRequests];
            [self pumpSubscribers];
        }
    }
    // Death of the last injected tccd ends the resident helper, including log streams.
    for (TCRequest *request in _requests.allValues)
        oneReply(request.reply, TCError, request.identifier,
                 @{@"ok": @NO, @"error": @"all_tccd_disconnected"});
    for (TCSubscriber *subscriber in _subscribers.allValues) {
        [self sendTo:subscriber
            operation:TCStreamEnd
                value:@{@"type": @"end", @"reason": @"all_tccd_disconnected"}];
        [self removeSubscriber:subscriber];
    }
    for (TCPeer *peer in _peers.allValues)
        [self removePeer:peer reason:@"helper_stopped"];
    TCDestroyReceive(_clients);
    TCDestroyReceive(_notifications);
    mach_port_mod_refs(mach_task_self(), _portSet, MACH_PORT_RIGHT_PORT_SET, -1);
    os_log(_logger, "all tccd ports closed; helper exiting");
    return 0;
}

@end

int TCBrokerRun(NSArray<NSDictionary *> *connections, NSUInteger ringCapacity) {
    if (geteuid() != 0) {
        fprintf(stderr, "[!] root required\n");
        return 77;
    }
    return [[[TCBroker alloc] initWithCapacity:ringCapacity] run:connections];
}
