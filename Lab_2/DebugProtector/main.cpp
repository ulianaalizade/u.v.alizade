#include <Windows.h>
#include <QDebug>


int main(int argc, char *argv[])
{
    // Получить из аргументов PID процесса, который надо защищать
       DWORD pid = (DWORD) atoi(argv[1]);

       bool isAttached = DebugActiveProcess(pid); // Подключаемся к нему как отладчик

       if(!isAttached) { // Проверяем, удалось ли подключиться
           DWORD lastError = GetLastError();
           qDebug() << "GetLastError()" << lastError;
           return lastError;
       }

       DEBUG_EVENT DbgEvent;

       while(1) { //
           WaitForDebugEvent(&DbgEvent, INFINITE);
           ContinueDebugEvent(DbgEvent.dwProcessId, DbgEvent.dwThreadId, DBG_CONTINUE);
       }
}
