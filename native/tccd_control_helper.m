#import "ControlHelper.h"

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc >= 3 && strcmp(argv[1], "_serve") == 0) {
            NSUInteger capacity = 1024;
            if (argc == 5 && strcmp(argv[3], "--capacity") == 0) {
                char *end = NULL;
                capacity = strtoul(argv[4], &end, 10);
                if (*end || capacity < 1 || capacity > 65536)
                    return 64;
            } else if (argc != 3)
                return 64;

            id connections = [NSJSONSerialization
                JSONObjectWithData:[@(argv[2]) dataUsingEncoding:NSUTF8StringEncoding]
                           options:0
                             error:NULL];
            if (![connections isKindOfClass:NSArray.class])
                return 64;
            return TCBrokerRun(connections, capacity);
        }

        return TCControlCLI(argc, argv);
    }
}
