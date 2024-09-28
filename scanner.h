#ifndef SCANNER_H
#define SCANNER_H

/**
 * @brief Scans a log file for vulnerabilities.
 * 
 * This function reads the specified log file line by line, scanning each log
 * message for known vulnerability patterns.
 * 
 * @param log_file The path to the log file to be scanned for vulnerabilities.
 */
void scan_logs(const char *log_file);

/**
 * @brief Scans a log message for vulnerabilities in real-time.
 * 
 * This function analyzes the given log message for known vulnerability patterns
 * and prints a detection result if any vulnerabilities are found.
 * 
 * @param log_message The log message to be analyzed for vulnerabilities.
 */
void real_time_scan(const char *log_message);

#endif // SCANNER_H
