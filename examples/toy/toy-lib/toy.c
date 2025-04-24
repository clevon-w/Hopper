#include <stdio.h>
#include <stdlib.h>
#include "toy.h"

Resource* init_resource() {
    Resource* res = (Resource*)malloc(sizeof(Resource));
    if (res) {
        res->state = 1;
    }
    return res;
}

int modify_resource(Resource* resource) {
    resource->state = 10;  // Modified state
    return 1;
}

int use_resource(Resource* resource, int input) {
    int result = 0;
    
    if (resource->state == 1) {
        result = input + 1;
    } else if (resource->state == 10) {
        result = input + 1;
        if (input > 0) {
            result *= 2;
        }
        if (input > 5) {
            result += 10;
        }
        if (input > 10) {
            result *= input;
        }
    }
    
    return result;
}

void free_resource(Resource* resource) {
    free(resource);
}