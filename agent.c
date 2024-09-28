#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include "scanner.h"
#include "malware_detector.h"

void collect_windows_event_log(const char *log_file) {
    HANDLE hEventLog = OpenEventLog(NULL, "System");
    if (hEventLog == NULL) {
        printf("Failed to open event log: %lu\n", GetLastError());
        return;
    }

    char log_message[1024];
    DWORD bytesRead, minNumberOfBytesNeeded;
    EVENTLOGRECORD *pRecord = (EVENTLOGRECORD *)malloc(0x10000);

    while (ReadEventLog(hEventLog, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ,
                        0, pRecord, 0x10000, &bytesRead, &minNumberOfBytesNeeded)) {
        snprintf(log_message, sizeof(log_message), "Event ID: %lu, Event Type: %u, Source: %s\n",
                 pRecord->EventID, pRecord->EventType, (char *)((LPBYTE)pRecord + sizeof(EVENTLOGRECORD)));
        real_time_scan(log_message);
    }

    CloseEventLog(hEventLog);
    free(pRecord);
}

DWORD WINAPI monitor_log_file(LPVOID lpParam) {
    const char *log_file = (const char *)lpParam;
    HANDLE hDir = CreateFile(".", FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (hDir == INVALID_HANDLE_VALUE) {
        printf("Failed to open directory: %lu\n", GetLastError());
        return 1;
    }

    char buffer[1024];
    FILE_NOTIFY_INFORMATION *fni;
    DWORD bytesReturned;

    while (ReadDirectoryChangesW(hDir, buffer, sizeof(buffer), FALSE, FILE_NOTIFY_CHANGE_LAST_WRITE,
                                 &bytesReturned, NULL, NULL)) {
        fni = (FILE_NOTIFY_INFORMATION *)buffer;
        if (fni->Action == FILE_ACTION_MODIFIED) {
            printf("Log file modified. Scanning...\n");
            scan_logs(log_file);
            detect_malware(log_file);  // Call malware detection after scanning
        }
    }

    CloseHandle(hDir);
    return 0;
}

#endif // _WIN32

#ifdef __linux__
//#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#include "scanner.h"
#include "malware_detector.h"

void collect_linux_system_logs(const char *log_file) {
    FILE *fp = fopen("/var/log/syslog", "r");
    if (fp == NULL) {
        perror("Failed to open system log file");
        return;
    }

    char log_message[1024];
    while (fgets(log_message, sizeof(log_message), fp) != NULL) {
        real_time_scan(log_message);
    }

    fclose(fp);
}

void monitor_log_file(const char *log_file) {
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }

    int wd = inotify_add_watch(inotify_fd, log_file, IN_MODIFY);
    if (wd < 0) {
        perror("inotify_add_watch");
        close(inotify_fd);
        exit(EXIT_FAILURE);
    }

    char buffer[1024];
    while (1) {
        ssize_t length = read(inotify_fd, buffer, sizeof(buffer));
        if (length < 0) {
            perror("read");
            break;
        }

        for (char *ptr = buffer; ptr < buffer + length; ) {
            struct inotify_event *event = (struct inotify_event *)ptr;
            if (event->mask & IN_MODIFY) {
                printf("Log file modified. Scanning...\n");
                scan_logs(log_file);
                detect_malware(log_file);  // Call malware detection after scanning
            }
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }

    inotify_rm_watch(inotify_fd, wd);
    close(inotify_fd);
}

#endif // __linux__

void collect_logs(const char *log_file) {
#ifdef _WIN32
    HANDLE hThread = CreateThread(NULL, 0, monitor_log_file, (LPVOID)log_file, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create thread: %lu\n", GetLastError());
        return;
    }

    collect_windows_event_log(log_file);

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
#elif __linux__
    collect_linux_system_logs(log_file);
    monitor_log_file(log_file);
#endif
}

int main() {
    const char *log_file = "logs.txt";
    collect_logs(log_file);
    return 0;
}
