#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scanner.h"

#ifdef _WIN32
#include <windows.h>

void scan_logs(const char *log_file) {
    FILE *file = fopen(log_file, "r");
    if (file == NULL) {
        perror("Failed to open log file");
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        real_time_scan(line);
    }

    if (fclose(file) != 0) {
        perror("Failed to close log file");
    }
}

void real_time_scan(const char *log_message) {
    printf("Scanning log message: %s\n", log_message);

    // Define vulnerability patterns and corresponding messages
    const char *vulnerability_patterns[][2] = {
        // Unauthorized access patterns
        {"Unauthorized access", "Unauthorized access detected"},
        {"Access denied", "Access denied detected"},
        {"Failed authentication", "Failed authentication detected"},
        {"Access not permitted", "Access not permitted detected"},

        // Failed login attempt patterns
        {"Failed login attempt", "Failed login attempt detected"},
        {"Invalid username", "Invalid username detected"},
        {"Invalid password", "Invalid password detected"},
        {"Login failed", "Login failed detected"},

        // Buffer overflow patterns
        {"AAAA", "Buffer overflow detected"},
        {"BBBB", "Buffer overflow detected"},
        {"C0C0C0C0", "Buffer overflow detected"},
        {"0x41414141", "Buffer overflow detected"},
        {"0x42424242", "Buffer overflow detected"},
        {"0x43434343", "Buffer overflow detected"},

        // Cross-site scripting patterns
        {"<script>", "Cross-site scripting detected"},
        {"</script>", "Cross-site scripting detected"},
        {"javascript:", "Cross-site scripting detected"},
        {"onerror=", "Cross-site scripting detected"},
        {"onload=", "Cross-site scripting detected"},
        {"onmouseover=", "Cross-site scripting detected"},
        {"alert(", "Cross-site scripting detected"},
        {"document.cookie", "Cross-site scripting detected"},
        {"eval(", "Cross-site scripting detected"},
        {"window.location", "Cross-site scripting detected"},
        {"iframe", "Cross-site scripting detected"},

        // Privilege escalation patterns
        {"Privilege escalation", "Privilege escalation detected"},
        {"Escalation attempt", "Escalation attempt detected"},
        {"Admin access", "Admin access detected"},
        {"Root access", "Root access detected"},
        {"Sudo attempt", "Sudo attempt detected"},

        // Exploit patterns
        {"Exploit", "Exploit detected"},
        {"Exploit attempt", "Exploit attempt detected"},
        {"Shellcode", "Shellcode detected"},
        {"Exploit payload", "Exploit payload detected"},

        // SQL injection patterns
        {"SQL injection", "SQL injection detected"},
        {"SELECT * FROM", "SQL injection detected"},
        {"DROP TABLE", "SQL injection detected"},
        {"' OR '1'='1", "SQL injection detected"},
        {"' OR 'a'='a", "SQL injection detected"}
    };

    int pattern_count = sizeof(vulnerability_patterns) / sizeof(vulnerability_patterns[0]);

    for (int i = 0; i < pattern_count; i++) {
        if (strstr(log_message, vulnerability_patterns[i][0]) != NULL) {
            printf("%s: %s\n", vulnerability_patterns[i][1], log_message);
            return;
        }
    }

    printf("No vulnerabilities detected: %s\n", log_message);
}

#elif defined(__linux__)

void scan_logs(const char *log_file) {
    FILE *file = fopen(log_file, "r");
    if (file == NULL) {
        perror("Failed to open log file");
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        real_time_scan(line);
    }

    if (fclose(file) != 0) {
        perror("Failed to close log file");
    }
}

void real_time_scan(const char *log_message) {
    printf("Scanning log message: %s\n", log_message);

    // Define vulnerability patterns and corresponding messages
    const char *vulnerability_patterns[][2] = {
        // Unauthorized access patterns
        {"Unauthorized access", "Unauthorized access detected"},
        {"Access denied", "Access denied detected"},
        {"Failed authentication", "Failed authentication detected"},
        {"Access not permitted", "Access not permitted detected"},

        // Failed login attempt patterns
        {"Failed login attempt", "Failed login attempt detected"},
        {"Invalid username", "Invalid username detected"},
        {"Invalid password", "Invalid password detected"},
        {"Login failed", "Login failed detected"},

        // Buffer overflow patterns
        {"AAAA", "Buffer overflow detected"},
        {"BBBB", "Buffer overflow detected"},
        {"C0C0C0C0", "Buffer overflow detected"},
        {"0x41414141", "Buffer overflow detected"},
        {"0x42424242", "Buffer overflow detected"},
        {"0x43434343", "Buffer overflow detected"},

        // Cross-site scripting patterns
        {"<script>", "Cross-site scripting detected"},
        {"</script>", "Cross-site scripting detected"},
        {"javascript:", "Cross-site scripting detected"},
        {"onerror=", "Cross-site scripting detected"},
        {"onload=", "Cross-site scripting detected"},
        {"onmouseover=", "Cross-site scripting detected"},
        {"alert(", "Cross-site scripting detected"},
        {"document.cookie", "Cross-site scripting detected"},
        {"eval(", "Cross-site scripting detected"},
        {"window.location", "Cross-site scripting detected"},
        {"iframe", "Cross-site scripting detected"},

        // Privilege escalation patterns
        {"Privilege escalation", "Privilege escalation detected"},
        {"Escalation attempt", "Escalation attempt detected"},
        {"Admin access", "Admin access detected"},
        {"Root access", "Root access detected"},
        {"Sudo attempt", "Sudo attempt detected"},

        // Exploit patterns
        {"Exploit", "Exploit detected"},
        {"Exploit attempt", "Exploit attempt detected"},
        {"Shellcode", "Shellcode detected"},
        {"Exploit payload", "Exploit payload detected"},

        // SQL injection patterns
        {"SQL injection", "SQL injection detected"},
        {"SELECT * FROM", "SQL injection detected"},
        {"DROP TABLE", "SQL injection detected"},
        {"' OR '1'='1", "SQL injection detected"},
        {"' OR 'a'='a", "SQL injection detected"}
    };

    int pattern_count = sizeof(vulnerability_patterns) / sizeof(vulnerability_patterns[0]);

    for (int i = 0; i < pattern_count; i++) {
        if (strstr(log_message, vulnerability_patterns[i][0]) != NULL) {
            printf("%s: %s\n", vulnerability_patterns[i][1], log_message);
            return;
        }
    }

    printf("No vulnerabilities detected: %s\n", log_message);
}

#endif
