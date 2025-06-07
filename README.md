# Y-Leak-Scanner.go

**Y-Leak-Scanner.go** is a high-performance, multi-threaded scanner written in Go that detects sensitive information leaks in HTTP responses using custom regex-based signatures.

## 🚀 Features

* ✅ Scans a list of URLs for leaked secrets or sensitive data
* 🔍 Uses regex patterns to match common token formats (e.g., `private_token`, `mapbox`, `app_token`)
* 🟢 Severity levels with color-coded alerts
* ⚡ Fast concurrent execution with configurable thread count
* 💾 Supports saving results to a file
* 📊 Real-time scanning progress display

## 📦 Installation

### Clone and Build

```bash
git clone https://github.com/Ahmex000/Y-Leak-Scanner.go.git
cd Y-Leak-Scanner.go
go build -o Y-Leak-Scanner.go Y-Leak-Scanner.go.go
```

Or run it directly:

```bash
go run Y-Leak-Scanner.go.go -f urls.txt -t 10 -o output.txt
```

![image](https://github.com/user-attachments/assets/f706d850-6ccd-4495-b060-a3ee1af47390)

> Ensure you have Go installed (version 1.16+ recommended)

## 🧪 Usage

### Basic Syntax

```bash
./Y-Leak-Scanner.go -f urls.txt -t 10 -o results.txt
```

### Parameters

| Flag | Description                                     |
| ---- | ----------------------------------------------- |
| `-f` | Path to file containing list of URLs (required) |
| `-t` | Number of concurrent threads (default: 10)      |
| `-o` | Path to output file for results (optional)      |

### Example `urls.txt` Format

```
https://example.com
https://testsite.com/page
```

## 🧠 How It Works

1. Reads URLs from a file.
2. Sends an HTTP GET request to each URL.
3. Scans the HTTP response body for matches using a built-in set of regular expressions.
4. Reports matches along with severity and the regex pattern used.
5. Displays real-time progress and optionally writes results to a file.

## 🛡️ Regex Keywords

The scanner uses a customizable list of regular expressions to detect common secret leaks:

```go
var KEYWORDS = map[string]string{
    `affirm[-_]?private\s*[:="'\s]*\s*([a-zA-Z0-9_\-]{8,}[^'":;\s,]*)`: "High",
    `app[-_]?token\s*[:="'\s]*\s*([a-zA-Z0-9_\-]{8,}[^'":;\s,]*)`:      "High",
    `map[-_]?box\s*[:="'\s]*\s*([a-zA-Z0-9_\-]{8,}[^'":;\s,]*) `:       "High",
    `private[-_]?token\s*[:="'\s]*\s*([a-zA-Z0-9_\-]{8,}[^'":;\s,]*)`:  "High",
}
```

> **Note:** The effectiveness of Y-Leak-Scanner.go depends heavily on the quality and variety of the regex patterns. **To improve detection coverage and get more results, you should expand the `KEYWORDS` list with additional patterns** tailored to your use case (e.g., API keys, secrets, credentials, etc.).

## 🧑‍💻 Author

**Ahmex000**

* 📖 [Medium](https://medium.com/@Ahmex000)
* 🐦 [X (Twitter)](https://x.com/Ahmex000)
* 💼 [LinkedIn](https://linkedin.com/in/Ahmex000)

