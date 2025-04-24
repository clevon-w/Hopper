#ifndef TOY_H
#define TOY_H

typedef struct {
    int state;  // 0 = uninitialized, 1 = initialized, 10 = modified
} Resource;

Resource* init_resource();

int modify_resource(Resource* resource);

int use_resource(Resource* resource, int input);

void free_resource(Resource* resource);

#endif /* TOY_H */