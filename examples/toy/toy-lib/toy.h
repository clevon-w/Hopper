#ifndef TOY_H
#define TOY_H

/* Opaque handle to the resource - the fuzzer can't see inside this */
typedef struct Resource_internal* Resource;

/* Create a new resource */
Resource init_resource();

/* Modify the resource - this must be called before using it for full functionality */
int modify_resource(Resource resource);

/* Use the resource with an input value */
int use_resource(Resource resource, int input);

/* Free the resource */
void free_resource(Resource resource);

#endif /* TOY_H */