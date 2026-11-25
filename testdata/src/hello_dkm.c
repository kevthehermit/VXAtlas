#include <vxWorks.h>
#include <stdio.h>
#include <string.h>
#include <taskLib.h>
#include <semLib.h>

static SEM_ID helloSem;
int helloCount = 7;

int helloWorker(long arg)
{
    printf("hello from a DKM task, arg=%ld\n", arg);
    return (int)strlen("worker") + helloCount;
}

int helloStart(void)
{
    helloSem = semBCreate(SEM_Q_FIFO, SEM_EMPTY);
    return (int)(long)taskSpawn("tHello", 100, 0, 0x4000, (FUNCPTR)helloWorker, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}
