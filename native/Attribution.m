// Immutable request snapshots never retain TCC process objects.

#import "Attribution.h"
#import "ControlProtocol.h"
#import <objc/message.h>
#import <objc/runtime.h>

static char kAuditKey;
static char kChainKey;

static id objectValue(id object, const char *name) {
    SEL selector = sel_getUid(name);
    if (!object || ![object respondsToSelector:selector])
        return nil;

    NSMethodSignature *signature = [object methodSignatureForSelector:selector];
    if (!signature || signature.methodReturnType[0] != '@')
        return nil;
    return ((id(*)(id, SEL))objc_msgSend)(object, selector);
}

static id textValue(id object, const char *name) {
    id value = objectValue(object, name);
    return [value isKindOfClass:NSString.class] ? [value copy] : NSNull.null;
}

static id boolValue(id object, const char *name) {
    SEL selector = sel_getUid(name);
    if (!object || ![object respondsToSelector:selector])
        return NSNull.null;

    NSMethodSignature *signature = [object methodSignatureForSelector:selector];
    if (!signature)
        return NSNull.null;
    const char *type = signature.methodReturnType;
    if (strcmp(type, @encode(BOOL)) != 0)
        return NSNull.null;
    return @(((BOOL(*)(id, SEL))objc_msgSend)(object, selector));
}

static NSDictionary *processSnapshot(id process) {
    if (!process)
        return @{@"available": @NO};

    NSMutableDictionary *snapshot = [@{
        @"available": @YES,
        @"identifier": textValue(process, "identifier"),
        @"binary_path": textValue(process, "binaryPath"),
        @"responsible_path": textValue(process, "responsiblePath")
    } mutableCopy];

    SEL selector = sel_getUid("auditToken");
    NSMethodSignature *signature = [process methodSignatureForSelector:selector];
    if ([process respondsToSelector:selector] && signature &&
        signature.methodReturnType[0] == '{' &&
        signature.methodReturnLength == sizeof(audit_token_t)) {
        audit_token_t token = ((audit_token_t(*)(id, SEL))objc_msgSend)(process, selector);
        snapshot[@"pid"] = @(audit_token_to_pid(token));
        snapshot[@"pid_version"] = @(audit_token_to_pidversion(token));
        snapshot[@"euid"] = @(audit_token_to_euid(token));
        snapshot[@"auid"] = @(audit_token_to_auid(token));
        snapshot[@"audit_token"] =
            [[NSData dataWithBytes:&token length:sizeof(token)] base64EncodedStringWithOptions:0];
    }
    return [snapshot copy];
}

static void bindChain(id chain, NSDictionary *metadata) {
    if (!chain)
        return;

    id accessing = objectValue(chain, "accessingProcess");
    id requesting = objectValue(chain, "requestingProcess");
    id responsible = objectValue(chain, "responsibleProcess");
    NSDictionary *previous = objc_getAssociatedObject(chain, &kChainKey);
    NSMutableDictionary *snapshot = [@{
        @"request_id": previous[@"request_id"] ?: NSUUID.UUID.UUIDString,
        @"responsible_valid": boolValue(chain, "responsibleProcessIsValid"),
        @"responsible_distinct": boolValue(chain, "responsibleProcessIsDistinct"),
        @"accessing": processSnapshot(accessing),
        @"requesting": processSnapshot(requesting),
        @"responsible": processSnapshot(responsible)
    } mutableCopy];
    [snapshot addEntriesFromDictionary:metadata];
    objc_setAssociatedObject(chain, &kChainKey, [snapshot copy], OBJC_ASSOCIATION_RETAIN);

    // No snapshot retains a process, chain, or context.
    for (id process in
         @[accessing ?: NSNull.null, requesting ?: NSNull.null, responsible ?: NSNull.null]) {
        if (process != NSNull.null) {
            NSMutableDictionary *binding = [snapshot mutableCopy];
            binding[@"checked_is_accessing"] = @(process == accessing);
            binding[@"checked_is_requesting"] = @(process == requesting);
            binding[@"checked_is_responsible"] = @(process == responsible);
            objc_setAssociatedObject(process, &kAuditKey, [binding copy], OBJC_ASSOCIATION_RETAIN);
        }
    }
}

void TCCaptureChain(id chain, xpc_object_t message) {
    const char *identifier = NULL, *function = NULL;
    id preflight = NSNull.null;
    if (message && xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
        identifier = xpc_dictionary_get_string(message, "TCCD_MSG_ID");
        function = xpc_dictionary_get_string(message, "function");
        xpc_object_t value = xpc_dictionary_get_value(message, "preflight");
        if (value && xpc_get_type(value) == XPC_TYPE_BOOL)
            preflight = @(xpc_bool_get_value(value));
    }

    bindChain(
        chain, @{
            @"attribution": @"attribution_chain",
            @"message_id": identifier ? @(identifier) : @"?",
            @"function": function ? @(function) : NSNull.null,
            @"preflight": preflight
        });
}

void TCCaptureAttribution(id context) {
    bindChain(objectValue(context, "attributionChain"), @{
        @"attribution": @"request_context",
        @"message_id": textValue(context, "messageIdentifier"),
        @"function": textValue(context, "functionName"),
        @"preflight": boolValue(context, "isPreflight")
    });
}

NSDictionary *TCBypassRecord(id process, id service, unsigned long long options,
                             BOOL originalResult, uint64_t expiry) {
    NSDictionary *binding = objc_getAssociatedObject(process, &kAuditKey);
    NSMutableDictionary *event = binding ? [binding mutableCopy] : [NSMutableDictionary new];
    event[@"event"] = @"bypass_check";
    event[@"attribution"] = binding ? binding[@"attribution"] : @"unavailable";
    event[@"tccd_pid"] = @(getpid());
    event[@"tccd_uid"] = @(geteuid());
    event[@"checked_process"] = processSnapshot(process);
    event[@"service"] = textValue(service, "name");
    event[@"options"] = @(options);
    event[@"original_entitlement_result"] = @(originalResult);
    event[@"expires_at"] = @(expiry);
    event[@"timestamp"] = @(NSDate.date.timeIntervalSince1970);
    return [event copy];
}
