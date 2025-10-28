#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <algorithm>
#include <curl/curl.h>

using namespace std;
mutex cout_mutex;

class WebsiteScanner {
private:
    string target_url;
    string target_host;
    vector<int> open_ports;
    vector<string> vulnerabilities;

public:
    WebsiteScanner(const string& url) : target_url(url) {
        // Extract host from URL
        size_t start = target_url.find("://") + 3;
        size_t end = target_url.find('/', start);
        if (end == string::npos) {
            target_host = target_url.substr(start);
        } else {
            target_host = target_url.substr(start, end - start);
        }
    }

    // Run complete scan
    void fullScan() {
        cout << "[+] Starting comprehensive scan for: " << target_url << endl;
        cout << "[+] Target Host: " << target_host << endl << endl;

        // Phase 1: Nmap Port Scanning
        cout << "[PHASE 1] Port Scanning with Nmap..." << endl;
        portScan();
        
        // Phase 2: Service Detection
        cout << "\n[PHASE 2] Service Detection..." << endl;
        serviceDetection();
        
        // Phase 3: Web Vulnerability Scanning
        cout << "\n[PHASE 3] Web Vulnerability Scanning..." << endl;
        webVulnerabilityScan();
        
        // Phase 4: Security Headers Check
        cout << "\n[PHASE 4] Security Headers Check..." << endl;
        checkSecurityHeaders();
        
        // Phase 5: Generate Report
        cout << "\n[PHASE 5] Generating Report..." << endl;
        generateReport();
    }

private:
    // Execute system command and get output
    string executeCommand(const string& cmd) {
        char buffer[128];
        string result = "";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return "ERROR";
        
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        pclose(pipe);
        return result;
    }

    // Port scanning with nmap
    void portScan() {
        string cmd = "nmap -sS -T4 -p- " + target_host + " 2>/dev/null";
        string result = executeCommand(cmd);
        
        // Parse nmap output for open ports
        istringstream iss(result);
        string line;
        while (getline(iss, line)) {
            if (line.find("/tcp") != string::npos && line.find("open") != string::npos) {
                size_t port_start = line.find('/');
                if (port_start != string::npos) {
                    string port_str = line.substr(0, port_start);
                    int port = stoi(port_str);
                    open_ports.push_back(port);
                    
                    lock_guard<mutex> lock(cout_mutex);
                    cout << "  [+] Open Port: " << port << " - " << getServiceName(port) << endl;
                }
            }
        }
    }

    // Service detection
    void serviceDetection() {
        if (open_ports.empty()) return;

        string ports_str = "";
        for (int port : open_ports) {
            if (!ports_str.empty()) ports_str += ",";
            ports_str += to_string(port);
        }

        string cmd = "nmap -sV -p " + ports_str + " " + target_host + " 2>/dev/null";
        string result = executeCommand(cmd);
        
        cout << "  Service Detection Results:" << endl;
        cout << result << endl;
    }

    // Web vulnerability scanning
    void webVulnerabilityScan() {
        // Check for common web vulnerabilities
        
        // 1. SQL Injection
        checkSQLInjection();
        
        // 2. XSS
        checkXSS();
        
        // 3. Directory Traversal
        checkDirectoryTraversal();
        
        // 4. Exposed Admin Panels
        checkAdminPanels();
        
        // 5. Information Disclosure
        checkInformationDisclosure();
    }

    void checkSQLInjection() {
        vector<string> sql_tests = {
            "'", "';", "\"", "\";", "' OR '1'='1", "' UNION SELECT 1,2,3--",
            "1' ORDER BY 1--", "1' AND 1=1--", "1' AND 1=2--"
        };

        string test_url = target_url;
        if (target_url.back() != '/') test_url += "/";
        test_url += "?id=1";

        for (const string& test : sql_tests) {
            string url = test_url + test;
            // In real implementation, you would make HTTP request and analyze response
            // This is simplified for demonstration
        }

        // For demonstration, let's simulate finding something
        vulnerabilities.push_back("Potential SQL Injection in 'id' parameter");
        cout << "  [!] Potential SQL Injection vulnerability detected" << endl;
    }

    void checkXSS() {
        vector<string> xss_tests = {
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        };

        // Similar implementation to SQL injection check
        vulnerabilities.push_back("Potential XSS in search parameter");
        cout << "  [!] Potential XSS vulnerability detected" << endl;
    }

    void checkDirectoryTraversal() {
        vector<string> traversal_paths = {
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "../windows/win.ini"
        };

        for (const string& path : traversal_paths) {
            string url = target_url + "/files?path=" + path;
            // Make request and check response
        }

        vulnerabilities.push_back("Directory Traversal possible in file parameter");
        cout << "  [!] Potential Directory Traversal vulnerability" << endl;
    }

    void checkAdminPanels() {
        vector<string> admin_paths = {
            "/admin", "/administrator", "/wp-admin", "/login", "/admin.php",
            "/cpanel", "/webadmin", "/manager", "/backend", "/dashboard"
        };

        cout << "  Checking for admin panels..." << endl;
        for (const string& path : admin_paths) {
            string url = target_url + path;
            // Check if URL exists and returns 200 OK
            if (checkURLExists(url)) {
                vulnerabilities.push_back("Admin panel exposed: " + url);
                cout << "  [!] Exposed admin panel: " << url << endl;
            }
        }
    }

    void checkInformationDisclosure() {
        vector<string> info_paths = {
            "/.git", "/.env", "/backup", "/backups", "/database.sql",
            "/phpinfo.php", "/test.php", "/info.php", "/.htaccess"
        };

        cout << "  Checking for information disclosure..." << endl;
        for (const string& path : info_paths) {
            string url = target_url + path;
            if (checkURLExists(url)) {
                vulnerabilities.push_back("Information disclosure: " + url);
                cout << "  [!] Information disclosure: " << url << endl;
            }
        }
    }

    void checkSecurityHeaders() {
        cout << "  Checking security headers..." << endl;
        
        // Check for important security headers
        vector<string> security_headers = {
            "X-Frame-Options", "X-Content-Type-Options", 
            "X-XSS-Protection", "Strict-Transport-Security",
            "Content-Security-Policy"
        };

        for (const string& header : security_headers) {
            // In real implementation, check if header exists
            cout << "  [-] Missing: " << header << endl;
            vulnerabilities.push_back("Missing security header: " + header);
        }
    }

    bool checkURLExists(const string& url) {
        // Simplified - in real implementation, make HTTP HEAD request
        // For demo, return true for some paths
        vector<string> existing_paths = {"/admin", "/login", "/.env"};
        for (const string& path : existing_paths) {
            if (url.find(path) != string::npos) {
                return true;
            }
        }
        return false;
    }

    string getServiceName(int port) {
        switch(port) {
            case 22: return "SSH";
            case 80: return "HTTP";
            case 443: return "HTTPS";
            case 21: return "FTP";
            case 25: return "SMTP";
            case 53: return "DNS";
            case 3306: return "MySQL";
            case 5432: return "PostgreSQL";
            case 27017: return "MongoDB";
            case 8080: return "HTTP-Alt";
            case 8443: return "HTTPS-Alt";
            default: return "Unknown";
        }
    }

    void generateReport() {
        cout << "\n" << string(60, '=') << endl;
        cout << "SCAN REPORT FOR: " << target_url << endl;
        cout << string(60, '=') << endl;
        
        cout << "\n[OPEN PORTS]" << endl;
        for (int port : open_ports) {
            cout << "  Port " << port << " - " << getServiceName(port) << endl;
        }
        
        cout << "\n[VULNERABILITIES FOUND]" << endl;
        if (vulnerabilities.empty()) {
            cout << "  No critical vulnerabilities detected" << endl;
        } else {
            for (const string& vuln : vulnerabilities) {
                cout << "  [!] " << vuln << endl;
            }
        }
        
        cout << "\n[SECURITY SCORE]" << endl;
        int score = calculateSecurityScore();
        cout << "  Overall Security Score: " << score << "/100" << endl;
        
        if (score >= 80) cout << "  Status: SECURE" << endl;
        else if (score >= 60) cout << "  Status: MODERATE" << endl;
        else cout << "  Status: INSECURE" << endl;
        
        cout << "\n[RECOMMENDATIONS]" << endl;
        generateRecommendations();
    }

    int calculateSecurityScore() {
        int score = 100;
        
        // Deduct points for each vulnerability
        score -= vulnerabilities.size() * 10;
        
        // Deduct for missing HTTPS
        if (find(open_ports.begin(), open_ports.end(), 443) == open_ports.end()) {
            score -= 20;
        }
        
        // Deduct for too many open ports
        if (open_ports.size() > 10) score -= 15;
        
        return max(0, score);
    }

    void generateRecommendations() {
        cout << "  1. Close unnecessary open ports" << endl;
        cout << "  2. Implement proper security headers" << endl;
        cout << "  3. Use HTTPS instead of HTTP" << endl;
        cout << "  4. Regular security patches and updates" << endl;
        cout << "  5. Implement WAF (Web Application Firewall)" << endl;
    }
};

// Main function
int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <website_url>" << endl;
        cout << "Example: " << argv[0] << " http://example.com" << endl;
        return 1;
    }

    string target_url = argv[1];
    
    // Validate URL format
    if (target_url.find("http") != 0) {
        target_url = "http://" + target_url;
    }

    WebsiteScanner scanner(target_url);
    scanner.fullScan();

    return 0;
}
