// Bounded helper-owned log storage; never used inside tccd.

#import <Foundation/Foundation.h>

@interface TCLogEntry : NSObject
@property uint64_t sequence;
@property(strong) NSData *data;
@end

@interface TCLogRing : NSObject
@property(readonly) NSUInteger count;
@property(readonly) NSUInteger bytes;
@property(readonly) uint64_t firstSequence;
@property(readonly) uint64_t lastSequence;
@property(readonly) uint64_t evicted;

- (instancetype)initWithCapacity:(NSUInteger)capacity byteLimit:(NSUInteger)byteLimit;
- (TCLogEntry *)append:(NSDictionary *)record;
- (TCLogEntry *)entry:(uint64_t)sequence;
@end
