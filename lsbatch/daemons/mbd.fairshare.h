/*
 * Copyright (C) 2021-2025 Bytedance Ltd. and/or its affiliates
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef FAIRSHARE_H
#define FAIRSHARE_H

#include "mbd.h"

#define FS_MAX_CANDHOST 20

/*Organize jobs by user*/
struct fsQueueJobSet {
    struct fairsharePolicy * policy;
    hTab   usersTab; /*key=userName, value=jobFSRef's list*/
    int    nJobs;    /*job counter in current job set*/
#define M_STAGE_FS_INIT 0
#define M_STAGE_FS_PROCESS 1
    int    status;

    int (*add)(struct fsQueueJobSet *jobSet, void *data);
    void *(*get)(struct fsQueueJobSet *jobSet, void *data, hEnt **ent);
    int (*del)(struct fsQueueJobSet *jobSet, struct shareAcct *, void *data, void *param);
};

struct jobFSRef {
    struct jobFSRef *frow;
    struct jobFSRef *back;
    struct jData    *job;
    int             idx;
};

typedef enum sAcctUpdType {
    SHARE_ACCT_UPD_CPUTIME,
    SHARE_ACCT_UPD_DECAYED_CPUTIME,
    SHARE_ACCT_UPD_RUNTIME,
    SHARE_ACCT_UPD_DECAYTIMES,
    SHARE_ACCT_UPD_NUMSTARTJOBS
} SHARE_ACCT_UPD_TYPE_T;

struct shareAcctUpd {
    SHARE_ACCT_UPD_TYPE_T type;
    union {
        float newUsedCpuTime;
        float decayedCpuTime;
        int runTime;
        int decayTimes;
        int   numStartJobs;
    }update;
};

#define SACCT_CPUTIME_UPDATE(cpuTime, sAcct, caller) \
{\
    struct shareAcctUpd __update__;\
    memset((void *) &__update__, 0, sizeof(struct shareAcctUpd));\
    __update__.type =  SHARE_ACCT_UPD_CPUTIME;\
    __update__.update.newUsedCpuTime = (cpuTime);\
    updShareAcctStats((sAcct), &__update__, (caller));\
}

#define SACCT_DECAYED_CPUTIME_UPDATE(cpuTime, sAcct,caller) \
{\
    struct shareAcctUpd __update__;\
    memset((void *) &__update__, 0, sizeof(struct shareAcctUpd));\
    __update__.type =  SHARE_ACCT_UPD_DECAYED_CPUTIME;\
    __update__.update.decayedCpuTime = (cpuTime);\
    updShareAcctStats((sAcct), &__update__, (caller));\
}

#define SACCT_RUNTIME_UPDATE(time, sAcct, caller) \
{\
    struct shareAcctUpd __update__;\
    memset((void *) &__update__, 0, sizeof(struct shareAcctUpd));\
    __update__.type =  SHARE_ACCT_UPD_RUNTIME;\
    __update__.update.runTime = (time);\
    updShareAcctStats((sAcct), &__update__, (caller));\
}

#define SACCT_DECAYTIMES_UPDATE(times, sAcct, caller) \
{\
    struct shareAcctUpd __update__;\
    memset((void *) &__update__, 0, sizeof(struct shareAcctUpd));\
    __update__.type =  SHARE_ACCT_UPD_DECAYTIMES;\
    __update__.update.decayTimes = (times);\
    updShareAcctStats((sAcct), &__update__, (caller));\
}

#define SACCT_NUMSTARTJOBS_UPDATE(nJobs, sAcct, caller) \
{\
    struct shareAcctUpd __update__;\
    memset((void *) &__update__, 0, sizeof(struct shareAcctUpd));\
    __update__.type =  SHARE_ACCT_UPD_NUMSTARTJOBS;\
    __update__.update.numStartJobs = (nJobs);\
    updShareAcctStats((sAcct), &__update__, (caller));\
}


#define FS_IS_LEAF_NODE(n) (! n->sharePolicy || \
                            ! n->sharePolicy->sAcctList || \
                            n->sharePolicy->sAcctList->numEnts <= 0)

#define FS_NUM_CHILD(n) (n->sharePolicy->sAcctList->numEnts)

extern void addFSPolicy(struct qData *);
extern void freeFSPolicy(struct fairsharePolicy *);
extern void dumpFSPolicy(struct fairsharePolicy *, const char *, int);
extern void dumpFSPolicies(const char *caller, int level);
extern struct fsQueueJobSet * sch_fs_newJobSet(struct fairsharePolicy *);
extern void sch_fs_freeJobSet(struct fsQueueJobSet *);
extern void sch_fs_init(struct fairsharePolicy *);
extern struct jData * sch_fs_electJob(struct fsQueueJobSet *, struct shareAcct **);
extern struct shareAcct * getSAcctForJob(struct fairsharePolicy *, struct jData *, int);
extern void attachJob2FSTree(struct fairsharePolicy *, struct jData *, struct shareAcct *, char *);
extern void detachedJobFromFSTree(struct jData *jPtr, char *);
extern void updAliveUserInFSTree(struct qData *qPtr, char *userName);
extern void updShareAcctStats(struct shareAcct *, struct shareAcctUpd *, const char *);  /*update workload statistics*/
extern void updSAcctPriorityByPath(struct shareAcct *); /*update priority and order of shareAccts*/
extern void updAllSAcctForDecay(time_t);
extern void accumHistCpuTime(struct jData *);
#endif
