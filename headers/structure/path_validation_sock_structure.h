//
// Created by 张贺凡 on 2024/12/9.
//

#ifndef PATH_VALIDATION_MODULE_PATH_VALIDATION_SOCK_STRUCTURE_H
#define PATH_VALIDATION_MODULE_PATH_VALIDATION_SOCK_STRUCTURE_H
#include <net/ip.h>
#include "structure/header/opt_header.h"
struct PathValidationSockStructure{
    bool sent_first_packet;
    struct SessionID session_id;
};

struct PathValidationSockStructure* init_pvss(void);
void free_pvss(struct PathValidationSockStructure* pvss);
#endif //PATH_VALIDATION_MODULE_PATH_VALIDATION_SOCK_STRUCTURE_H