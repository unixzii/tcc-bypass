// CLI RPC and streaming live here; Python only forwards them.

#import "ControlHelper.h"
#import "ControlProtocol.h"
#include <errno.h>
#include <servers/bootstrap.h>
#include <time.h>
#include <unistd.h>

static void printJSON(id value) {
    NSData *data = TCEncode(value);
    if (data) {
        fwrite(data.bytes, 1, data.length, stdout);
        fputc('\n', stdout);
        fflush(stdout);
    }
}

static int clientError(NSString *error, int code) {
    printJSON(@{@"ok": @NO, @"error": error});
    return code;
}

static int exchange(TCOperation operation, NSDictionary *value, BOOL snapshot) {
    mach_port_t server = 0, receive = 0;
    if (bootstrap_look_up(bootstrap_port, TC_SERVICE, &server))
        return clientError(@"helper_unavailable", 69);

    receive = TCReceivePort();
    if (!receive) {
        mach_port_deallocate(mach_task_self(), server);
        return clientError(@"receive_port_failed", 70);
    }

    TCWatchDead(server, receive);
    NSData *data = TCEncode(value);
    if (!data || data.length > TCMaxBody) {
        TCDestroyReceive(receive);
        mach_port_deallocate(mach_task_self(), server);
        return clientError(@"request_too_large", 64);
    }

    BOOL streaming = operation == TCSubscribe;
    TCFrame frame;
    TCPrepare(&frame, operation, 1, data.bytes, (uint32_t)data.length);
    kern_return_t result =
        TCPost(&frame, server, MACH_MSG_TYPE_COPY_SEND, receive,
               streaming ? MACH_MSG_TYPE_MAKE_SEND : MACH_MSG_TYPE_MAKE_SEND_ONCE, 100);
    int exitCode = 0;
    if (result)
        exitCode = clientError(@"helper_send_failed", 69);

    while (!result) {
        @autoreleasepool {
            TCMessage message;
            result = TCRead(&message, receive, streaming ? 1000 : 4000);
            if (streaming && result == MACH_RCV_TIMED_OUT) {
                result = KERN_SUCCESS;
                continue;
            }
            if (result) {
                exitCode = clientError(@"helper_timeout", 70);
                break;
            }

            mach_port_t dead = TCDeadName(&message);
            if (dead == server) {
                mach_port_deallocate(mach_task_self(), dead);
                exitCode = clientError(@"helper_disconnected", 69);
                break;
            }

            audit_token_t audit;
            if (!TCValidate(&message, &audit) || audit_token_to_euid(audit) != 0) {
                mach_msg_destroy(&message.frame.header);
                exitCode = clientError(@"invalid_helper_reply", 70);
                break;
            }

            id reply = TCDecode(&message.frame);
            if (![reply isKindOfClass:NSDictionary.class]) {
                exitCode = clientError(@"invalid_reply_body", 70);
                break;
            }

            // Preserve original record casing and paths. Only human diagnostics are lowercase.
            printJSON(reply);
            if (!streaming) {
                exitCode = [reply[@"ok"] boolValue] ? 0 : 1;
                break;
            }
            if (message.frame.operation == TCStreamEnd ||
                (snapshot && message.frame.operation == TCReplayEnd)) {
                exitCode = reply[@"error"] ? 1 : 0;
                break;
            }
        }
    }

    TCWatchDead(server, 0);
    mach_port_deallocate(mach_task_self(), server);
    TCDestroyReceive(receive);
    return exitCode;
}

int TCControlCLI(int argc, const char **argv) {
    if (argc < 2) {
        fprintf(
            stderr,
            "usage: tccd_control_helper enable [minutes] | disable | status | logs [--snapshot]\n");
        return 64;
    }

    if (strcmp(argv[1], "enable") == 0 && (argc == 2 || argc == 3)) {
        char *end = NULL;
        errno = 0;
        unsigned long minutes = argc == 3 ? strtoul(argv[2], &end, 10) : 30;
        if (errno || (end && (*end || end == argv[2])) || minutes < 1 || minutes > 1440)
            return clientError(@"minutes_must_be_1_to_1440", 64);
        return exchange(TCEnable, @{@"expires_at": @((uint64_t)time(NULL) + minutes * 60)}, NO);
    }

    if (strcmp(argv[1], "disable") == 0 && argc == 2)
        return exchange(TCDisable, @{}, NO);

    if (strcmp(argv[1], "status") == 0 && argc == 2)
        return exchange(TCStatus, @{}, NO);

    if (strcmp(argv[1], "logs") == 0 &&
        (argc == 2 || (argc == 3 && strcmp(argv[2], "--snapshot") == 0)))
        return exchange(TCSubscribe, @{@"snapshot": @(argc == 3)}, argc == 3);

    if (strcmp(argv[1], "_attach") == 0 && argc == 3) {
        NSData *data = [@(argv[2]) dataUsingEncoding:NSUTF8StringEncoding];
        id connections = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
        if (![connections isKindOfClass:NSArray.class])
            return clientError(@"invalid_connections", 64);
        return exchange(TCAttach, @{@"connections": connections}, NO);
    }

    return clientError(@"invalid_command", 64);
}
