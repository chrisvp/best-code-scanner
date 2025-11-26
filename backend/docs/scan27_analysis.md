# Scan #27 Analysis - Model Performance Benchmark

## Test Case
- **Files**: 4 C++ firmware files (firmware_updater.cpp, logger_service.cpp, memory_pool.cpp, network_client.cpp)
- **Planted Vulnerabilities**:
  - Command Injection (line 330-331 in firmware_updater.cpp)
  - Buffer Overflow (lines 328-331 in network_client.cpp)
  - Use-After-Free (lines 409-413 in memory_pool.cpp)
  - Format String (line 311 in logger_service.cpp)

## Results Summary
- **Total Drafts**: 47
- **Verified**: 26
- **Rejected**: 21

## Manual Review Classification

### True Positives (Real Vulnerabilities) - 10 findings
| ID | Finding | File | Line |
|----|---------|------|------|
| 155 | Command Injection via system() | firmware_updater.cpp | 331 |
| 156 | Use-After-Free | memory_pool.cpp | 409 |
| 158 | Format String printf(user_message) | logger_service.cpp | 311 |
| 159-161, 166 | Buffer Overflow strcpy/strcat | network_client.cpp | 328-331 |
| 162, 165 | UAF/Double-Free (duplicate of 156) | memory_pool.cpp | 410-411 |
| 164 | Format String vsnprintf | logger_service.cpp | 192 |

### Debatable/Context-Dependent - 4 findings
| ID | Finding | Issue |
|----|---------|-------|
| 157 | Path Traversal (log_path) | Depends on input source |
| 163 | Buffer Overflow sprintf | Borderline size calculation |
| 168 | Path Traversal (hook_name) | Depends on call site |
| 170 | Path Traversal (mkdir) | Depends on input source |

### False Positives - 12 findings
| ID | Finding | Why It's Wrong |
|----|---------|----------------|
| 169 | Integer Overflow (line 176) | This IS a bounds check, not a vuln |
| 171 | Integer Overflow (line 225) | Requires ~4GB allocations - theoretical |
| 172 | Integer Overflow (line 121) | Requires >42M bytes - unlikely |
| 173 | Buffer Overflow (line 294) | strncpy with explicit len limit is safe |
| 174 | Insecure Permissions (0644) | Debatable, not a security vuln |
| 175 | Buffer Overflow (line 192) | vsnprintf PREVENTS overflow |
| 176 | Buffer Overflow (line 105) | strncpy with sizeof is safe |
| 177 | Buffer Overflow (line 197) | snprintf with size calc is correct |
| 178 | Missing Error Handling | Code quality, not security |
| 179, 167 | Integer Overflow align_size | Requires size > SIZE_MAX-7 - impossible |
| 180 | Missing Input Validation | Duplicate of 159-161 |

## Model Performance (Based on Manual Classification)

| Model | TP | Debatable | FP | Total | FP Rate |
|-------|----|-----------|----|-------|---------|
| **gemma-3-27b-it** | 7 | 0 | 1 | 8 | **12.5%** |
| llama3.3-70b-instruct | 3 | 2 | 2 | 7 | 28.6% |
| gpt-oss-120b | 8 | 2 | 5 | 15 | 33.3% |
| **mistral-small** | 6 | 2 | 8 | 16 | **50.0%** |
| static | 1 | 0 | 0 | 1 | 0.0% |

## False Positive Patterns

### 1. Integer Overflow Fear
Models flag arithmetic like `size + 7` or `bytes * 100` as overflow risks even when:
- The values would need to be impossibly large (>4GB for 32-bit)
- The code is checking bounds, not causing overflow

### 2. Safe Function Confusion
Models incorrectly flag:
- `snprintf(buf, sizeof(buf) - offset, ...)` as unsafe
- `strncpy(dst, src, sizeof(dst))` as buffer overflow
- `vsnprintf` as vulnerable (it's designed to prevent overflow)

### 3. Bounds Check Inversion
Models mark defensive code like `if (x > MAX)` as the vulnerability instead of recognizing it as protection.

## Recommendations

### For Reducing FPs:
1. Give `gemma-3-27b-it` higher voting weight (best signal-to-noise)
2. Add verifier rules to reject theoretical integer overflows
3. Whitelist safe patterns: snprintf with sizeof, strncpy with sizeof

### For Finding More TPs:
1. `gpt-oss-120b` found the Command Injection others missed
2. `llama3.3-70b-instruct` found the Buffer Overflow others missed
3. Keep multi-model voting but weight by accuracy

### Model Strengths:
- **gemma-3-27b-it**: Lowest FP rate, precise
- **gpt-oss-120b**: Found command injection, good at injection vulns
- **llama3.3-70b-instruct**: Found buffer overflow, good at memory vulns
- **mistral-small**: High volume but noisy - consider lower weight
