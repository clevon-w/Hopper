#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "toy.h"

/* The internal implementation of Resource that's hidden from users */
struct Resource_internal {
    int state;                  /* Resource state */
    int has_been_modified;      /* Flag indicating if modify_resource has been called */
    void* private_context;      /* Pointer that only our implementation uses */
};

/* This array maintains state that's hidden from the fuzzer */
// static void* authorized_resources[128] = {NULL};

/* Internal function to register resource in our authorized list */
// static void register_resource(struct Resource_internal* res) {
//     size_t idx = ((uintptr_t)res) % 128;
//     authorized_resources[idx] = res;
// }

// /* Internal function to check if a resource is authorized */
// static int is_authorized(struct Resource_internal* res) {
//     size_t idx = ((uintptr_t)res) % 128;
//     return authorized_resources[idx] == res;
// }

Resource init_resource() {
    struct Resource_internal* res = (struct Resource_internal*)malloc(sizeof(struct Resource_internal));
    if (res) {
        res->state = 1;
        res->has_been_modified = 0;
        res->private_context = NULL;
        /* Don't register it yet - we only register after modification */
    }
    return res;
}

int modify_resource(Resource resource) {
    struct Resource_internal* res = (struct Resource_internal*)resource;
    
    /* This will crash if resource is NULL */
    int state = res->state;
    
    /* Set state to modified */
    res->state = 10;
    res->has_been_modified = 1;
    
    /* Register this resource as authorized */
    // register_resource(res);
    
    return 1;
}

int use_resource(Resource resource, int input) {
    int result = 0;
    struct Resource_internal* res = (struct Resource_internal*)resource;
    
    /* This will crash if resource is NULL */
    int state = res->state;
    
    if (res->state == 1) {
        /* Basic functionality for unmodified resources */
        result = input + 1;
    } else if (res->state == 10) {
        /* Check if this resource was properly modified using our function */
        if (res->has_been_modified) {
            /* Full functionality for properly modified resources */
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
        } else {
            /* Basic result for unauthorized resources */
            result = input + 1;
        }
    }
    
    return result;
}

void free_resource(Resource resource) {
    if (!resource) {
        /* This will crash if the resource is NULL */
        struct Resource_internal* crash_me = NULL;
        crash_me->state = 0;  /* Force a crash */
        return;
    }
    
    struct Resource_internal* res = (struct Resource_internal*)resource;
    
    // size_t idx = ((uintptr_t)res) % 128;
    // if (authorized_resources[idx] == res) {
    //     authorized_resources[idx] = NULL;
    // }
    free(res);
}