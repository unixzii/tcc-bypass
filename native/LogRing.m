#import "LogRing.h"
#import "ControlProtocol.h"

@implementation TCLogEntry
@end

@implementation TCLogRing {
    NSMutableArray *_slots;
    NSUInteger _head, _used, _byteCount, _limit;
    uint64_t _next, _evictions;
}

- (instancetype)initWithCapacity:(NSUInteger)capacity byteLimit:(NSUInteger)byteLimit {
    if ((self = [super init])) {
        _slots = [NSMutableArray arrayWithCapacity:capacity];
        for (NSUInteger i = 0; i < capacity; i++)
            [_slots addObject:NSNull.null];
        _limit = byteLimit;
        _next = 1;
    }
    return self;
}

- (NSUInteger)count {
    return _used;
}

- (NSUInteger)bytes {
    return _byteCount;
}

- (uint64_t)firstSequence {
    return _used ? ((TCLogEntry *)_slots[_head]).sequence : _next;
}

- (uint64_t)lastSequence {
    return _next - 1;
}

- (uint64_t)evicted {
    return _evictions;
}

- (TCLogEntry *)append:(NSDictionary *)record {
    NSMutableDictionary *value = [record mutableCopy];
    value[@"sequence"] = @(_next);
    NSData *data = TCEncode(value);
    if (!data || data.length > TCMaxBody || data.length > _limit || !_slots.count)
        return nil;

    while (_used && (_used == _slots.count || _byteCount + data.length > _limit)) {
        _byteCount -= ((TCLogEntry *)_slots[_head]).data.length;
        _slots[_head] = NSNull.null;
        _head = (_head + 1) % _slots.count;
        _used--;
        _evictions++;
    }

    TCLogEntry *entry = [TCLogEntry new];
    entry.sequence = _next++;
    entry.data = data;
    _slots[(_head + _used) % _slots.count] = entry;
    _used++;
    _byteCount += data.length;
    return entry;
}

- (TCLogEntry *)entry:(uint64_t)sequence {
    if (!_used || sequence < self.firstSequence || sequence >= _next)
        return nil;
    return _slots[(_head + (NSUInteger)(sequence - self.firstSequence)) % _slots.count];
}

@end
