// CLI RPC and streaming live here; Python only forwards them.

#import "ControlHelper.h"
#import "ControlProtocol.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <servers/bootstrap.h>
#include <time.h>
#include <unistd.h>

static BOOL gJSONOutput;

static NSDictionary *dictionary(id value) {
    return [value isKindOfClass:NSDictionary.class] ? value : @{};
}

static NSString *text(id value) {
    if (![value isKindOfClass:NSString.class] || ![value length])
        return nil;
    return [[value componentsSeparatedByCharactersInSet:NSCharacterSet.controlCharacterSet]
        componentsJoinedByString:@"?"];
}

static NSNumber *number(id value) {
    return [value isKindOfClass:NSNumber.class] ? value : nil;
}

static NSString *numericText(id value) {
    return number(value).stringValue ?: @"?";
}

static NSString *paint(NSString *value, const char *color, FILE *stream) {
    const char *term = getenv("TERM");
    if (!isatty(fileno(stream)) || getenv("NO_COLOR") || (term && strcmp(term, "dumb") == 0))
        return value;
    return [NSString stringWithFormat:@"\033[%sm%@\033[0m", color, value];
}

static void printLine(FILE *stream, NSString *value) {
    fprintf(stream, "%s\n", value.UTF8String);
    fflush(stream);
}

static NSString *errorText(id value) {
    return [text(value) stringByReplacingOccurrencesOfString:@"_" withString:@" "]
               ?: @"unknown error";
}

static NSString *timestamp(id value) {
    NSNumber *seconds = number(value);
    if (!seconds || !isfinite(seconds.doubleValue) || seconds.doubleValue <= 0)
        return @"unknown time";

    static NSDateFormatter *formatter;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        formatter = [NSDateFormatter new];
        formatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
        formatter.timeZone = NSTimeZone.localTimeZone;
        formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS Z";
    });
    return [formatter stringFromDate:[NSDate dateWithTimeIntervalSince1970:seconds.doubleValue]];
}

static NSString *processLabel(NSDictionary *process) {
    NSString *identifier = text(process[@"identifier"]);
    NSString *path = text(process[@"binary_path"]) ?: text(process[@"responsible_path"]);
    NSString *name = identifier ?: path.lastPathComponent ?: @"unknown process";
    return [NSString stringWithFormat:@"%@ (PID %@)", name, numericText(process[@"pid"])];
}

static NSString *permissionLabel(id value) {
    NSString *service = text(value);
    static NSDictionary *names;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        names = @{
            @"kTCCServiceMicrophone": @"Microphone",
            @"kTCCServiceCamera": @"Camera",
            @"kTCCServiceScreenCapture": @"Screen Recording",
            @"kTCCServiceAccessibility": @"Accessibility",
            @"kTCCServiceListenEvent": @"Input Monitoring",
            @"kTCCServicePostEvent": @"Post Events",
            @"kTCCServiceAppleEvents": @"Automation",
            @"kTCCServiceSystemPolicyAllFiles": @"Full Disk Access",
            @"kTCCServiceSystemPolicyDesktopFolder": @"Desktop Folder",
            @"kTCCServiceSystemPolicyDocumentsFolder": @"Documents Folder",
            @"kTCCServiceSystemPolicyDownloadsFolder": @"Downloads Folder",
            @"kTCCServiceAddressBook": @"Contacts",
            @"kTCCServiceCalendar": @"Calendars",
            @"kTCCServiceReminders": @"Reminders",
            @"kTCCServicePhotos": @"Photos",
            @"kTCCServiceLocation": @"Location"
        };
    });
    NSString *name = names[service ?: @""];
    return name ? [NSString stringWithFormat:@"%@ [%@]", name, service] : service ?: @"unknown permission";
}

static void printRecord(NSDictionary *reply) {
    NSDictionary *record = dictionary(reply[@"record"]);
    NSDictionary *accessing = dictionary(record[@"accessing"]);
    NSDictionary *checked = dictionary(record[@"checked_process"]);
    NSDictionary *actor = [number(accessing[@"available"]) boolValue] ? accessing : checked;
    NSString *actorLabel = processLabel(actor);
    NSNumber *original = number(record[@"original_entitlement_result"]);
    NSString *action = original && !original.boolValue ? @"BYPASS" : @"CHECK";

    printLine(
        stdout,
        [NSString stringWithFormat:@"%@  %@  %@ → %@",
                                   paint(timestamp(record[@"timestamp"]), "2", stdout),
                                   paint(action, original && !original.boolValue ? "1;32" : "1;33",
                                         stdout),
                                   paint(actorLabel, "1;36", stdout),
                                   paint(permissionLabel(record[@"service"]), "1;35", stdout)]);

    NSString *path = text(actor[@"binary_path"]);
    if (path)
        printLine(stdout, [NSString stringWithFormat:@"    binary: %@", path]);

    for (NSString *role in @[@"requesting", @"responsible", @"checked_process"]) {
        NSDictionary *process = dictionary(record[role]);
        if (![number(process[@"available"]) boolValue] || [process isEqual:actor])
            continue;
        NSString *label = [role isEqualToString:@"checked_process"] ? @"checked" : role;
        printLine(stdout, [NSString stringWithFormat:@"    %@: %@", label, processLabel(process)]);
    }

    NSMutableArray *details = [NSMutableArray new];
    [details addObject:[NSString stringWithFormat:@"TCC allow entitlement: %@",
                                                  original ? (original.boolValue
                                                                  ? @"already present"
                                                                  : @"supplied (originally absent)")
                                                           : @"unknown"]];
    [details addObject:[NSString stringWithFormat:@"tccd PID %@",
                                                  numericText(record[@"tccd_pid"]
                                                                  ?: reply[@"source_pid"])]];
    if (text(record[@"request_id"]))
        [details addObject:[NSString stringWithFormat:@"request %@", text(record[@"request_id"])]];
    if ([number(record[@"preflight"]) boolValue])
        [details addObject:@"preflight"];
    printLine(stdout, [@"    " stringByAppendingString:[details componentsJoinedByString:@" · "]]);
}

static void printStatus(NSDictionary *reply, TCOperation operation) {
    BOOL ok = [number(reply[@"ok"]) boolValue];
    BOOL enabled = [number(reply[@"enabled"]) boolValue];
    NSString *title =
        ok ? (enabled ? @"Bypass enabled" : @"Bypass disabled") : @"Status incomplete";
    if (!ok && operation == TCEnable)
        title = @"Could not enable bypass on every tccd";
    else if (!ok && operation == TCDisable)
        title = @"Could not disable bypass on every tccd";

    printLine(stdout, paint(title, !ok ? "1;31" : enabled ? "1;32" : "1;33", stdout));
    if (number(reply[@"helper_pid"])) {
        printLine(stdout,
                  [NSString stringWithFormat:@"  Helper PID %@ · connected %@/%@ · acknowledged %@",
                                             numericText(reply[@"helper_pid"]),
                                             numericText(reply[@"connected"]),
                                             numericText(reply[@"expected"]),
                                             numericText(reply[@"acknowledged"])]);
    }

    for (NSDictionary *state in reply[@"results"]) {
        BOOL active = [number(state[@"enabled"]) boolValue];
        NSString *status = paint(active ? @"enabled" : @"disabled", active ? "32" : "33", stdout);
        NSString *expiry =
            active ? [NSString stringWithFormat:@" · expires %@", timestamp(state[@"expires_at"])]
                   : @"";
        printLine(stdout, [NSString stringWithFormat:@"  tccd PID %@ (UID %@) · %@%@",
                                                     numericText(state[@"pid"]),
                                                     numericText(state[@"uid"]), status, expiry]);
        printLine(
            stdout,
            [NSString
                stringWithFormat:@"    Logs: %@ generated · %@ sent · %@ dropped · %@ oversized",
                                 numericText(state[@"logs_generated"]),
                                 numericText(state[@"logs_sent"]),
                                 numericText(state[@"logs_dropped"]),
                                 numericText(state[@"logs_oversized"])]);
    }

    NSDictionary *ring = dictionary(reply[@"ring"]);
    if (ring.count) {
        printLine(
            stdout,
            [NSString
                stringWithFormat:@"  Log buffer: %@ records · %@ bytes · %@ evicted · %@ oversized",
                                 numericText(ring[@"records"]), numericText(ring[@"bytes"]),
                                 numericText(ring[@"evicted"]), numericText(ring[@"oversized"])]);
    }
    if (reply[@"error"])
        printLine(stderr, paint([@"Error: " stringByAppendingString:errorText(reply[@"error"])],
                                "31", stderr));
    for (NSDictionary *error in reply[@"errors"])
        printLine(stderr,
                  paint([NSString stringWithFormat:@"  tccd PID %@: %@", numericText(error[@"pid"]),
                                                   errorText(error[@"error"])],
                        "31", stderr));
    for (id pid in reply[@"missing_pids"])
        printLine(stderr, paint([NSString stringWithFormat:@"  tccd PID %@: not connected",
                                                           numericText(pid)],
                                "31", stderr));
}

static void printJSON(id value) {
    NSData *data = TCEncode(value);
    if (data) {
        fwrite(data.bytes, 1, data.length, stdout);
        fputc('\n', stdout);
        fflush(stdout);
    }
}

static void printReply(NSDictionary *reply, TCOperation operation, BOOL snapshot) {
    if (gJSONOutput) {
        printJSON(reply);
        return;
    }
    NSString *type = text(reply[@"type"]);
    if ([type isEqualToString:@"record"]) {
        printRecord(reply);
    } else if ([type isEqualToString:@"replay_begin"]) {
        NSDictionary *ring = dictionary(reply[@"ring"]);
        printLine(
            stdout,
            paint(
                [NSString
                    stringWithFormat:@"Replaying logs · %@ buffered · %@ evicted · times are local",
                                     numericText(ring[@"records"]), numericText(ring[@"evicted"])],
                "2", stdout));
    } else if ([type isEqualToString:@"replay_end"]) {
        printLine(stdout, paint(snapshot ? @"End of snapshot"
                                         : @"Following live permission checks… (Ctrl-C to stop)",
                                "2", stdout));
    } else if ([type isEqualToString:@"gap"]) {
        printLine(
            stdout,
            paint([NSString stringWithFormat:@"Log gap: records %@–%@ unavailable (%@)",
                                             numericText(reply[@"from"]), numericText(reply[@"to"]),
                                             errorText(reply[@"reason"])],
                  "33", stdout));
    } else if ([type isEqualToString:@"end"]) {
        FILE *stream = reply[@"error"] ? stderr : stdout;
        printLine(stream,
                  paint([NSString stringWithFormat:@"Log stream ended: %@",
                                                   errorText(reply[@"error"] ?: reply[@"reason"])],
                        reply[@"error"] ? "31" : "33", stream));
    } else {
        printStatus(reply, operation);
    }
}

static int clientError(NSString *error, int code) {
    if (gJSONOutput)
        printJSON(@{@"ok": @NO, @"error": error});
    else
        printLine(stderr,
                  paint([@"Error: " stringByAppendingString:errorText(error)], "1;31", stderr));
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

            printReply(reply, operation, snapshot);
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
    // Bootstrap uses JSON; interactive commands default to readable text.
    gJSONOutput = argc >= 2 && strcmp(argv[1], "_attach") == 0;
    if (argc >= 3 && strcmp(argv[argc - 1], "--json") == 0) {
        gJSONOutput = YES;
        argc--;
    }

    if (argc < 2) {
        fprintf(
            stderr,
            "usage: tccd_control_helper enable [minutes] | disable | status | logs [--snapshot] [--json]\n");
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
