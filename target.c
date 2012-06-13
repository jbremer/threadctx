#include <stdio.h>
#include <windows.h>

int main(void)
{
    // use this threadid as argument on the commandline to poc.exe
    printf("threadid: %d\n", GetCurrentThreadId());
    while (1) {
        Sleep(100);
        // the tick count is just to show difference between two lines
        // so it's easier to see if the program is running etc.
        printf("alive.. %d\n", GetTickCount());
    }
}
