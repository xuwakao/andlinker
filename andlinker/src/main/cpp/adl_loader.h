//
// Created by P7XXTM1-G on 6/8/2021.
//

#ifndef ANDLINKER_ADL_LOADER_H
#define ANDLINKER_ADL_LOADER_H

#include <sys/cdefs.h>

__BEGIN_DECLS

void *adl_load(const char *filename);

void adl_loader_lock(void);

void adl_loader_unlock(void);

__END_DECLS


#endif //ANDLINKER_ADL_LOADER_H
