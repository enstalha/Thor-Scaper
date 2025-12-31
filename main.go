package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

const (
	torProxyAddress = "socks5://127.0.0.1:9150"
	inputFile       = "targets.yaml"
	baseOutputDir   = "data"
	userAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
)

type GlobalScanReport struct {
	ScanID       string          `json:"scan_id"`
	StartTime    string          `json:"start_time"`
	EndTime      string          `json:"end_time"`
	TotalTargets int             `json:"total_targets"`
	SuccessCount int             `json:"success_count"`
	FailureCount int             `json:"failure_count"`
	Targets      []TargetSummary `json:"targets"`
}

type TargetSummary struct {
	URL         string `json:"url"`
	Status      string `json:"status"`
	StatusCode  int64  `json:"status_code"`
	Duration    string `json:"duration"`
	EvidenceDir string `json:"evidence_dir"`
}

type MetaData struct {
	TargetURL  string     `json:"target_url"`
	ScanTime   string     `json:"scan_time"`
	StatusCode int64      `json:"status_code"`
	PageTitle  string     `json:"page_title"`
	Hashes     FileHashes `json:"hashes"`
	Notes      string     `json:"notes"`
}

type FileHashes struct {
	HTMLSha256       string `json:"html_sha256"`
	ScreenshotSha256 string `json:"screenshot_sha256"`
}

func main() {
	setupDirectories()

	scanID := fmt.Sprintf("SCAN-%s", time.Now().Format("20060102-150405"))
	fmt.Printf("🛡️  Thor Scraper [Gold Master] | ID: %s\n", scanID)

	fmt.Print("🌍 Tor Bağlantısı ve IP Gizliliği Kontrol Ediliyor... ")
	if !verifyTorConnection() {
		fmt.Println("\n❌ KRİTİK HATA: Tor Proxy (127.0.0.1:9150) yanıt vermiyor veya bağlantı güvenli değil.")
		fmt.Println("   Lütfen Tor Browser'ın açık olduğundan emin olun.")
		os.Exit(1)
	}
	fmt.Println("✅ GÜVENLİ (Bağlantı Doğrulandı)")

	targets, err := readTargets(inputFile)
	if err != nil {
		log.Fatalf("Hedef dosyası hatası: %v", err)
	}

	report := GlobalScanReport{
		ScanID:       scanID,
		StartTime:    time.Now().Format(time.RFC3339),
		TotalTargets: len(targets),
		Targets:      []TargetSummary{},
	}
	fmt.Printf("📋 Hedef Sayısı: %d\n", len(targets))

	for i, targetURL := range targets {
		fmt.Printf("\n[%d/%d] Analiz: %s\n", i+1, len(targets), targetURL)

		summary := processTarget(targetURL)

		report.Targets = append(report.Targets, summary)
		if summary.Status == "SUCCESS" {
			report.SuccessCount++
		} else {
			report.FailureCount++
		}

		time.Sleep(3 * time.Second)
	}

	report.EndTime = time.Now().Format(time.RFC3339)
	saveGlobalReport(report)

	fmt.Println("\nOperasyon Tamamlandı.")
	fmt.Printf("Sonuç: %d Başarılı | %d Hatalı\n", report.SuccessCount, report.FailureCount)
	fmt.Println("Özet: data/scan_summary.json")
}

func verifyTorConnection() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ProxyServer(torProxyAddress),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()

	chromeCtx, cancelChrome := chromedp.NewContext(allocCtx)
	defer cancelChrome()

	var title string
	err := chromedp.Run(chromeCtx,
		chromedp.Navigate("https://check.torproject.org"),
		chromedp.Evaluate(`document.title`, &title),
	)

	if err == nil && strings.Contains(strings.ToLower(title), "tor") {
		return true
	}
	return false
}

func processTarget(targetURL string) TargetSummary {
	startTime := time.Now()

	domain := extractDomain(targetURL)
	timeTag := time.Now().Format("2006-01-02_15-04")
	baseDir := filepath.Join(baseOutputDir, domain, timeTag)

	summary := TargetSummary{
		URL:         targetURL,
		EvidenceDir: filepath.Join(domain, timeTag),
	}

	logsDir := filepath.Join(baseDir, "logs")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		summary.Status = "FS_ERROR"
		return summary
	}

	netLogFile, _ := os.Create(filepath.Join(logsDir, "network.log"))
	consoleLogFile, _ := os.Create(filepath.Join(logsDir, "console.log"))
	defer netLogFile.Close()
	defer consoleLogFile.Close()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ProxyServer(torProxyAddress),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.IgnoreCertErrors,
		chromedp.UserAgent(userAgent),
		chromedp.Flag("disable-webrtc", true),
		chromedp.Flag("disable-quic", true),
		chromedp.Flag("dns-prefetch-disable", true),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	ctx, cancel := context.WithTimeout(allocCtx, 90*time.Second)
	defer cancel()
	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	var htmlSrc string
	var imgData []byte
	var pageTitle string
	var responseStatus int64 = 0

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			netLogFile.WriteString(fmt.Sprintf("[%s] REQ: %s %s\n", time.Now().Format("15:04:05"), e.Request.Method, e.Request.URL))
		case *network.EventResponseReceived:
			if e.Type == network.ResourceTypeDocument {
				responseStatus = e.Response.Status
			}
			netLogFile.WriteString(fmt.Sprintf("[%s] RES: [%d] %s (%s)\n", time.Now().Format("15:04:05"), e.Response.Status, e.Response.URL, e.Response.MimeType))
		case *runtime.EventConsoleAPICalled:
			var args []string
			for _, arg := range e.Args {
				args = append(args, string(arg.Value))
			}
			consoleLogFile.WriteString(fmt.Sprintf("[%s] [%s] %s\n", time.Now().Format("15:04:05"), e.Type, strings.Join(args, " ")))
		}
	})

	fmt.Print("   ↳ Veri toplanıyor (Snapshot + HTML)... ")

	err := chromedp.Run(ctx,
		network.Enable(),
		runtime.Enable(),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(10*time.Second),
		chromedp.Evaluate(`document.title`, &pageTitle),
		chromedp.OuterHTML("html", &htmlSrc),
		chromedp.FullScreenshot(&imgData, 70),
	)

	duration := fmt.Sprintf("%.2fs", time.Since(startTime).Seconds())
	summary.Duration = duration
	summary.StatusCode = responseStatus

	if err != nil {
		fmt.Println("❌ BAŞARISIZ")
		logError(baseDir, err)
		saveMeta(baseDir, targetURL, 0, "", duration, "", "", "FAILED: "+err.Error())
		summary.Status = "FAILED"
		return summary
	}

	os.WriteFile(filepath.Join(baseDir, "full_page.png"), imgData, 0644)
	os.WriteFile(filepath.Join(baseDir, "source.html"), []byte(htmlSrc), 0644)

	imgHash := calculateHash(imgData)
	htmlHash := calculateHash([]byte(htmlSrc))

	saveMeta(baseDir, targetURL, responseStatus, pageTitle, duration, htmlHash, imgHash, "Scan Completed Successfully")

	fmt.Printf("✅ (%s)\n", duration)
	summary.Status = "SUCCESS"

	return summary
}

func saveGlobalReport(report GlobalScanReport) {
	data, _ := json.MarshalIndent(report, "", "  ")
	filename := filepath.Join(baseOutputDir, "scan_summary.json")
	os.WriteFile(filename, data, 0644)
}

func saveMeta(dir, url string, status int64, title, dur, htmlHash, imgHash, notes string) {
	meta := MetaData{
		TargetURL:  url,
		ScanTime:   time.Now().Format(time.RFC3339),
		StatusCode: status,
		PageTitle:  title,
		Notes:      notes,
	}
	meta.Hashes.HTMLSha256 = htmlHash
	meta.Hashes.ScreenshotSha256 = imgHash
	data, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(filepath.Join(dir, "meta.json"), data, 0644)
}

func calculateHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func setupDirectories() {
	if _, err := os.Stat(baseOutputDir); os.IsNotExist(err) {
		os.Mkdir(baseOutputDir, 0755)
	}
}

func readTargets(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, "http") {
				line = "http://" + line
			}
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func extractDomain(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "unknown_host"
	}
	return u.Hostname()
}

func logError(dir string, err error) {
	f, _ := os.Create(filepath.Join(dir, "error.log"))
	defer f.Close()
	f.WriteString(fmt.Sprintf("ERROR: %v\nTime: %s", err, time.Now().Format(time.RFC3339)))
}
