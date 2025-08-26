# Inactive-Operator-Scanner-Remover



**Inactive Operator Remover** is a full-featured Python automation suite designed to manage operator records, identify inactive operators, update external systems, and streamline reporting. It integrates with the FA DataLoader to update databases, generates professional HTML reports, and provides a dedicated **Manager Console** for secure and simple configuration management.  

This project was originally developed to handle sensitive operational data. For security and compliance reasons, **all sensitive information (such as server addresses, local fallback paths, authentication credentials, and internal system details) has been removed** from the published source code. What remains is the core logic, reporting, and automation framework.

---

## Features  

### 1. Inactive Operator Processing  
- Parses operator records and detects inactive operators based on customizable rules.  
- Generates both **summary reports** and **individual operator reports**, highlighting all detected changes.  
- Retains recent reports while automatically cleaning up older ones based on configurable retention settings.  

### 2. Automated Database Updates (FA DataLoader Integration)  
- After generating daily XML operator files, the program prepares and triggers FA DataLoader to update the database.  
- Automates the creation and execution of batch scripts (`.bat`) for seamless FA DataLoader integration.  
- Appends FA DataLoader log outputs into the program’s consolidated log file for full visibility.  

### 3. Email Notifications  
- Automatically generates **email-ready HTML reports** summarizing inactive operator changes.  
- Creates individual HTML email files for each operator with relevant changes, suitable for direct distribution.  
- Email and report retention is configurable through the Manager Console and `config.ini`.  

### 4. Manager Console (GUI)  
A user-friendly management application that centralizes all control functions:  
- **Configuration Management**: Edit and save `config.ini` settings (paths, retention, email options, etc.) without manual file editing.  
- **Email/Database Settings**: Adjust report destinations, email parameters, and FA DataLoader behaviors.  
- **Backup Handling**: Automatically backs up input files with date-stamped copies before clearing the input directory.  
- **Maintenance Tools**: Simplifies log access, report cleanup, and configuration resets.  
- **Security**: Excludes direct system-level scheduling (delegated to IT/administrators), ensuring safe use.  

### 5. Configurable Settings (`config.ini`)  
All runtime parameters are centralized in the configuration file:  
- Report and email output directories  
- File retention periods  
- FA DataLoader options  
- Logging preferences  
- Backup and input handling rules  

This separation of logic from configuration improves **security, maintainability, and portability**.  

### 6. Logging & Error Handling  
- Maintains a single consolidated log file with appended entries for each run.  
- Includes execution summaries: number of operators processed, number updated in FA DataLoader, failures, and errors.  
- Automatically incorporates FA DataLoader logs for a complete picture of system activity.  
- Prevents crashes from wiping input/output data.  

---

## Project Structure  

```
InactiveOperatorRemover/
│
├── inactive_operator_remover.py     # Core automation script  
├── manager_console.py               # GUI management console  
├── config.ini                       # Centralized configuration file  
├── /input                           # Raw operator files (parsed and processed)  
├── /input backups                   # Automatic date-stamped backups of input files  
├── /output                          # Generated reports and XML files  
├── /emails                          # Generated email-ready HTML reports  
├── /logs                            # Consolidated execution and DataLoader logs  
└── requirements.txt                 # Python dependencies  
```

---

## Installation & Usage  

### Requirements  
- Python 3.10+  
- Dependencies listed in `requirements.txt`  


## Maintenance & Extensibility  
- Modular structure allows easy extension (e.g., adding new reporting rules or database connectors).  
- `config.ini` makes updates safe and environment-specific.  
- Designed to support long-term operational use, including auditability through logs and backups.  

---

## Security Notes  
- Sensitive environment data (server paths, credentials, fallback addresses) has been removed from this repository.  
- Users must configure their own secure environment in `config.ini`.  
- The provided code focuses only on logic, workflow, and reporting.  

---

## Disclaimer  
This is a **sanitized version** of the original project.  
- All private details (e.g., server locations, credentials) have been excluded.  
- Only the functional framework and automation logic remain.  
- Users must adapt the configuration and environment for production use.  
