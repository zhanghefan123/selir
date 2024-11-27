//
// Created by zhf on 2024/11/21.
//

#ifndef SELIR_NAMESPACE_H
#define SELIR_NAMESPACE_H

#include "structure/path_validation_structure.h"

void set_pvs_in_ns(struct net *ns, struct PathValidationStructure *pvs);

struct PathValidationStructure* get_pvs_from_ns(struct net* ns);

#endif //SELIR_NAMESPACE_H
