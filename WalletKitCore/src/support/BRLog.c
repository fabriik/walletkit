/*
 * BRLog.c
 *
 *  Created on: Nov. 12, 2021
 *      Author: bryangoring
 */
#include "BRLog.h"
#include "BROSCompat.h"
#include "BRArray.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>

#define MAX_LEVEL_DESC_LEN  (4)
static const char* levelDescriptions[MAX_LEVELS] = 
{
    "FATL",
    "ERRR",
    "WARN",
    "INFO",
    "DEBG",
    "DBG2"
};

#define MAX_LOG_LEN     (1024) // Or as deemed suitable

struct BRModuleInfoStruct {
    struct BRLogModuleStruct    base;
    
    struct BRModuleInfoStruct   *parent;
    char                        tag[MAX_LOG_MOD_NAME_LEN+1];
    uint32_t                    numModules;
    struct BRModuleInfoStruct   **modules;
};

struct BRBaseLogModuleStruct {
    pthread_mutex_t             log_lock;
    struct BRModuleInfoStruct   all;
};

static struct BRBaseLogModuleStruct systemLogInfo;
BRLogModule SYSTEM_LOG = (BRLogModule)&systemLogInfo.all;

static void initLog() {
    pthread_mutex_init_brd(&systemLogInfo.log_lock, PTHREAD_MUTEX_RECURSIVE);
    systemLogInfo.all.numModules = 0;
    systemLogInfo.all.modules = NULL;
    systemLogInfo.all.parent = NULL;
    systemLogInfo.all.base.level = DEFAULT_LOG_LEVEL;
    strcpy(systemLogInfo.all.base.name, "SYSTEM");
    strcpy(systemLogInfo.all.tag, "SYSTEM");
}

static pthread_once_t logInitOnlyOnce = PTHREAD_ONCE_INIT;
void initLogSystem() {
    pthread_once (&logInitOnlyOnce, initLog);
}

void registerLogModule(
    const char      *moduleName,
    BRLogModule     *ownerModule,
    BRLogModule     *module  ) {
    
    assert (NULL != ownerModule && NULL != *ownerModule);
    assert (NULL != module);
    assert (MAX_LOG_MOD_NAME_LEN >= strlen(moduleName));
    
    struct BRModuleInfoStruct **ownerModuleInfo = (struct BRModuleInfoStruct**)ownerModule;
    struct BRModuleInfoStruct **moduleInfo = (struct BRModuleInfoStruct**)module;
    
    pthread_mutex_lock(&systemLogInfo.log_lock);
    
    if (NULL == *moduleInfo) {
        *moduleInfo = (struct BRModuleInfoStruct*) calloc (1, sizeof (struct BRModuleInfoStruct));
        assert (NULL != *moduleInfo);
        (*moduleInfo)->base.level = DEFAULT_LOG_LEVEL;
        (*moduleInfo)->parent = *ownerModuleInfo;
    }
    
    // Resize, if needed
    struct BRModuleInfoStruct **tmp = (*ownerModuleInfo)->modules;
    (*ownerModuleInfo)->modules = (struct BRModuleInfoStruct**) calloc ((*ownerModuleInfo)->numModules + 1, 
                                                                        sizeof (struct BRModuleInfoStruct*));
    if (NULL != tmp) {
        for (int i=0; i < (*ownerModuleInfo)->numModules; i++) {
            (*ownerModuleInfo)->modules[i] = tmp[i];
        }
    }
    (*ownerModuleInfo)->modules[(*ownerModuleInfo)->numModules++] = *moduleInfo;
    strncpy((*moduleInfo)->tag, moduleName, MAX_LOG_MOD_NAME_LEN);
    
    // Formulate the external name of the log
    char* nm = (*moduleInfo)->base.name;
    if ((*ownerModule) != SYSTEM_LOG) {
        size_t sz = sprintf (nm, "%s_", (*ownerModuleInfo)->tag);
        nm += sz;
    }
    sprintf (nm, "%s", (*moduleInfo)->tag);
    
    if (NULL != tmp)
        free (tmp);
    
    pthread_mutex_unlock(&systemLogInfo.log_lock);
}

// '[hh:mm:ss.SSS][LVL][MOD-MAX_LOG_MOD_NAME_LEN][SUBMOD-MAX_LOG_MOD_NAME_LEN]: '
#define MAX_OCCURS_ON_LEN   ((2+1+2+1+2+1+3)+2)                             // [hh:mm:ss.SSS]
#define MAX_LVL_LOG_LEN     (MAX_LEVEL_DESC_LEN + 2)                        // [lvl]
#define MAX_MOD_LOG_LEN     (MAX_LOG_MOD_NAME_LEN + 2)                      // [submod]
#define MAX_HDR_LEN         ((MAX_OCCURS_ON_LEN + MAX_LVL_LOG_LEN + MAX_MOD_LOG_LEN * 2) + 2) // +2 for ': '
void doLog(
    BRLogLevel      lvl, 
    BRLogModule     mod, 
    const char*     fmt, ... ) {
    
    assert (NULL != mod);
    
    struct BRModuleInfoStruct *modInfo = (struct BRModuleInfoStruct*)mod;
    struct BRModuleInfoStruct *submodInfo = NULL;
    if (modInfo->parent != (struct BRModuleInfoStruct*)SYSTEM_LOG) {
        // A submodule is passed
        submodInfo = modInfo;
        modInfo = submodInfo->parent;
    }
    
    char smod[MAX_MOD_LOG_LEN + 1];
    char occursOn[MAX_OCCURS_ON_LEN + 1];
    char logMsg[MAX_LOG_LEN + 1];
    time_t t; 
    struct tm local;
    struct timeval tv;
    
    t = time(NULL);
    local = *localtime(&t);
    gettimeofday (&tv, NULL);
    snprintf(occursOn, 
             MAX_OCCURS_ON_LEN + 1, 
             "[%02d:%02d:%02d.%03d]",
             local.tm_hour,
             local.tm_min,
             local.tm_sec,
             (tv.tv_usec / 1000));
    
    if ( NULL != submodInfo)
        snprintf (smod, MAX_MOD_LOG_LEN + 1, "[%*s]", MAX_LOG_MOD_NAME_LEN, submodInfo->tag);
    else {
        memset (smod, ' ', MAX_MOD_LOG_LEN);
        smod[MAX_MOD_LOG_LEN] = 0;
    }
    snprintf (logMsg, 
              MAX_HDR_LEN + 1,
              "%s[%s][%*s]%s: ", 
              occursOn, 
              levelDescriptions[lvl],
              MAX_LOG_MOD_NAME_LEN,
              modInfo->tag,
              smod);

    char *p = logMsg + MAX_HDR_LEN;
    
    va_list args;
    va_start (args, fmt);
    int len = vsnprintf (p, MAX_LOG_LEN - MAX_HDR_LEN, fmt, args);
    va_end (args);
    
    if (len > (MAX_LOG_LEN - MAX_HDR_LEN)) {
        // log too large for static buffer, ignore OR heap to help
        // p = malloc ...
        // etc
    } else {
        *(p + len) = 0;
    }
    
    // Per system target type...
    printf("%s\n", logMsg);
}

void setLogLevel(
    BRLogLevel  newLevel,
    const char  *modName,
    const char  *submodName )
{
    // TODO...
}

static BRLogModule logModuleFromInfo(struct BRModuleInfoStruct *info) {
    BRLogModule mod = calloc (1, sizeof (struct BRLogModuleStruct));
    mod->level = info->base.level;
    strcpy (mod->name, info->base.name);
    return mod;
}

// General for any depth of module records, w/o recursion; however
// in practice due to the structure of log module macros & registration there
// is only ever a maximum depth of 2 (SYSTEM, first order mod, and submods)
size_t getAllLogLevelsList(BRLogModule **moduleList) {
    
    struct BRModuleInfoStruct *mod = (struct BRModuleInfoStruct*)SYSTEM_LOG;
    
    // For tracking recursion
    uint32_t *indexes = 0;
    uint32_t depth = 0;
    struct BRModuleInfoStruct **parents = NULL;
    
    array_new (indexes, 1);
    array_add (indexes, 0);
    
    array_new (*moduleList, 1);
    array_new (parents, 1);
    
    array_add (*moduleList, logModuleFromInfo (mod));
    indexes[depth] = 0;
    while (NULL != mod && indexes[depth] < mod->numModules) {
        
        struct BRModuleInfoStruct *submod = mod->modules[indexes[depth]];
        if (submod->numModules > 0 && *(submod->modules) != NULL) {

            // push
            indexes[depth]++;
            
            array_add (*moduleList, logModuleFromInfo (submod));
            array_add (indexes, 0);
            array_add (parents, mod);
            mod = submod;
            depth++;
            
        } else {
            
            // describe
            array_add (*moduleList, logModuleFromInfo (mod->modules[indexes[depth]]));
            indexes[depth]++;

        }
        
        if (indexes[depth] == mod->numModules) {
            
            // pop
            depth--;
            if (depth >= 0) {
                
                mod = parents[depth];
                array_rm_last (parents);
                array_rm_last (indexes);
                
            } else {
                
                // end
                mod = NULL;
                
            }
        }
    }
    
    array_free (indexes);
    array_free (parents);
    
    return array_count (*moduleList);
}

void releaseAllLogLevelsList(BRLogModule *list) {
    for (size_t i; i < array_count (list); i++) {
        free (list[i]);
    }
    array_free (list);
}