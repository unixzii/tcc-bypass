#import <Foundation/Foundation.h>
#import <xpc/xpc.h>

void TCCaptureChain(id chain, xpc_object_t message);
void TCCaptureAttribution(id context);
NSDictionary *TCBypassRecord(id process, id service, unsigned long long options,
                             BOOL originalResult, uint64_t expiry);
