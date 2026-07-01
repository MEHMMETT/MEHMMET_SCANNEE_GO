package main

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"image/color"
)

// ─── رنج‌های رسمی کلودفلر ───────────────────────────────────────────────────
var cfSubnets = []string{
	"103.21.244", "103.22.200", "103.22.201", "103.31.4", "103.31.5",
	"104.16", "104.17", "104.18", "104.19", "104.20",
	"104.21", "104.22", "104.24", "104.25", "104.26", "104.27", "104.28",
	"172.64", "172.65", "172.66", "172.67", "172.68", "172.69", "172.70", "172.71",
	"108.162.192", "108.162.193", "108.162.194", "108.162.195",
	"108.162.196", "108.162.197", "108.162.198", "108.162.199",
	"162.158.0", "162.158.1", "162.158.2", "162.158.78",
	"162.158.100", "162.158.150", "162.158.200",
	"190.93.240", "190.93.241", "190.93.242", "190.93.243", "190.93.244",
	"188.114.96", "188.114.97", "188.114.98", "188.114.99",
	"197.234.240", "197.234.241", "197.234.242", "197.234.243",
	"198.41.128", "198.41.144", "198.41.192", "198.41.208",
	"141.101.64", "141.101.65", "141.101.66", "141.101.67",
	"131.0.72", "131.0.73", "131.0.74", "131.0.75",
	"173.245.48", "173.245.49", "173.245.50", "173.245.51",
}

type ScanResult struct {
	IP     string
	Port   int
	PingMs int64
}

// ─── تست TCP خام (بدون TLS) ─────────────────────────────────────────────────
// این دقیقاً همون چیزیه که از فیلترینگ SNI/DPI روی 443 رد میشه:
// فقط SYN → SYN/ACK → ACK، بدون هیچ داده‌ای که بشه بازرسیش کرد.
func pingTCP(ip string, port int, timeout time.Duration) (int64, bool) {
	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return 0, false
	}
	conn.Close()
	ms := time.Since(t0).Milliseconds()
	if ms < 5 {
		return 0, false // جواب فوری = fail واقعی
	}
	return ms, true
}

// ─── تولید IP از CIDR ────────────────────────────────────────────────────────
func genFromCIDR(cidr string) []string {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return nil
	}
	bits, err := strconv.Atoi(parts[1])
	if err != nil || bits < 8 || bits > 32 {
		return nil
	}
	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return nil
	}
	var nums [4]int
	for i, o := range octets {
		n, e := strconv.Atoi(o)
		if e != nil {
			return nil
		}
		nums[i] = n
	}
	ipNum := (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
	hostBits := 32 - bits
	mask := ^((1 << hostBits) - 1)
	network := ipNum & mask
	total := 1 << hostBits
	max := total
	if max > 65536 {
		max = 65536
	}
	out := make([]string, 0, max)
	for h := 1; h < total && len(out) < max; h++ {
		full := network + h
		d := full & 255
		if d == 0 || d == 255 {
			continue
		}
		out = append(out, fmt.Sprintf("%d.%d.%d.%d",
			(full>>24)&255, (full>>16)&255, (full>>8)&255, d))
	}
	return out
}

// ─── تولید IP رندوم از ساب‌نت‌های کلودفلر ────────────────────────────────────
func genRandom(n int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, n)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	guard := 0
	for len(out) < n && guard < n*8 {
		guard++
		sub := cfSubnets[rng.Intn(len(cfSubnets))]
		parts := strings.Split(sub, ".")
		d := rng.Intn(254) + 1
		var ip string
		if len(parts) == 3 {
			ip = fmt.Sprintf("%s.%d", sub, d)
		} else {
			c := rng.Intn(254) + 1
			ip = fmt.Sprintf("%s.%d.%d", sub, c, d)
		}
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

// ─── تم تیره سفارشی ─────────────────────────────────────────────────────────
type darkTheme struct{}

func (darkTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	switch n {
	case theme.ColorNameBackground:
		return color.NRGBA{3, 0, 5, 255}
	case theme.ColorNameButton:
		return color.NRGBA{21, 16, 31, 255}
	case theme.ColorNamePrimary:
		return color.NRGBA{139, 63, 255, 255}
	case theme.ColorNameForeground:
		return color.NRGBA{207, 198, 232, 255}
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{138, 128, 168, 255}
	case theme.ColorNameInputBackground:
		return color.NRGBA{21, 16, 31, 255}
	case theme.ColorNameSeparator:
		return color.NRGBA{45, 45, 69, 255}
	}
	return theme.DefaultTheme().Color(n, v)
}
func (darkTheme) Font(s fyne.TextStyle) fyne.Resource  { return theme.DefaultTheme().Font(s) }
func (darkTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (darkTheme) Size(n fyne.ThemeSizeName) float32    { return theme.DefaultTheme().Size(n) }

// ─── main ─────────────────────────────────────────────────────────────────────
func main() {
	a := app.New()
	a.Settings().SetTheme(darkTheme{})
	w := a.NewWindow("MHMTSCANNER")
	w.Resize(fyne.NewSize(400, 700))

	// ── Header ──
	title := canvas.NewText("MHMTSCANNER", color.NRGBA{139, 63, 255, 255})
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.TextSize = 20
	title.Alignment = fyne.TextAlignCenter

	sub := canvas.NewText("CF CLEAN IP SCANNER — RAW TCP", color.NRGBA{138, 128, 168, 255})
	sub.TextSize = 10
	sub.Alignment = fyne.TextAlignCenter

	// ── Inputs ──
	cidrEntry := widget.NewEntry()
	cidrEntry.SetPlaceHolder("رنج CIDR — مثال: 104.16.0.0/24  (خالی = رندوم)")

	portEntry := widget.NewEntry()
	portEntry.SetText("80")

	countEntry := widget.NewEntry()
	countEntry.SetText("100")
	countLabel := widget.NewLabel("تعداد IP (حالت رندوم):")

	// ── Stats ──
	statsLabel := widget.NewLabel("SCANNED: 0   OPEN: 0   BEST: —")
	statsLabel.Alignment = fyne.TextAlignCenter
	progress := widget.NewProgressBar()
	progress.Min = 0
	progress.Max = 1

	// ── Results ──
	resultList := widget.NewList(
		func() int { return 0 },
		func() fyne.CanvasObject {
			ip := widget.NewLabel("0.0.0.0:443")
			ip.TextStyle = fyne.TextStyle{Monospace: true}
			ping := canvas.NewText("0ms", color.NRGBA{0, 255, 163, 255})
			ping.TextStyle = fyne.TextStyle{Bold: true}
			return container.NewBorder(nil, nil, nil, ping, ip)
		},
		func(id widget.ListItemID, o fyne.CanvasObject) {},
	)

	var results []ScanResult
	var mu sync.Mutex
	var stopCh chan struct{}
	var scanning bool

	updateList := func() {
		mu.Lock()
		local := make([]ScanResult, len(results))
		copy(local, results)
		mu.Unlock()

		resultList.Length = func() int { return len(local) }
		resultList.UpdateItem = func(id widget.ListItemID, o fyne.CanvasObject) {
			r := local[id]
			box := o.(*fyne.Container)
			ip := box.Objects[0].(*widget.Label)
			ping := box.Objects[1].(*canvas.Text)
			ip.SetText(fmt.Sprintf("%s:%d", r.IP, r.Port))
			ping.Text = fmt.Sprintf("%dms", r.PingMs)
			ping.Refresh()
		}
		resultList.Refresh()
	}

	// ── Copy All Button ──
	copyBtn := widget.NewButton("کپی همه IP", func() {
		mu.Lock()
		lines := make([]string, len(results))
		for i, r := range results {
			lines[i] = r.IP
		}
		mu.Unlock()
		w.Clipboard().SetContent(strings.Join(lines, "\n"))
	})
	copyBtn.Hide()

	// ── Scan Button ──
	scanBtn := widget.NewButton("SCAN", nil)
	scanBtn.Importance = widget.HighImportance

	scanBtn.OnTapped = func() {
		if scanning {
			// Stop
			if stopCh != nil {
				close(stopCh)
			}
			return
		}

		// پارس پورت‌ها
		ports := []int{}
		for _, p := range strings.Split(portEntry.Text, ",") {
			p = strings.TrimSpace(p)
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
				ports = append(ports, n)
			}
		}
		if len(ports) == 0 {
			ports = []int{80}
		}

		// تولید IP‌ها
		var ips []string
		cidr := strings.TrimSpace(cidrEntry.Text)
		if cidr != "" {
			ips = genFromCIDR(cidr)
			if len(ips) == 0 {
				statsLabel.SetText("رنج CIDR معتبر نیست")
				return
			}
		} else {
			n, _ := strconv.Atoi(countEntry.Text)
			if n <= 0 {
				n = 100
			}
			ips = genRandom(n)
		}

		// ریست
		mu.Lock()
		results = nil
		mu.Unlock()
		updateList()
		copyBtn.Hide()
		progress.SetValue(0)
		statsLabel.SetText("در حال اسکن...")

		scanning = true
		stopCh = make(chan struct{})
		scanBtn.SetText("STOP")

		go func() {
			total := len(ips)
			done := 0
			openCount := 0
			var bestMs int64 = -1

			sem := make(chan struct{}, 60) // 60 کانکشن هم‌زمان
			var wg sync.WaitGroup

			for _, ip := range ips {
				select {
				case <-stopCh:
					goto done
				default:
				}

				for _, port := range ports {
					wg.Add(1)
					sem <- struct{}{}
					go func(ip string, port int) {
						defer wg.Done()
						defer func() { <-sem }()

						timeout := 2500 * time.Millisecond

						ms, ok := pingTCP(ip, port, timeout)
						if ok {
							r := ScanResult{IP: ip, Port: port, PingMs: ms}
							mu.Lock()
							results = append(results, r)
							openCount++
							if bestMs < 0 || ms < bestMs {
								bestMs = ms
							}
							mu.Unlock()
						}
					}(ip, port)
				}

				// بعد از هر IP، progress و UI رو آپدیت کن
				done++
				pct := float64(done) / float64(total)
				progress.SetValue(pct)

				mu.Lock()
				o := openCount
				b := bestMs
				mu.Unlock()

				best := "—"
				if b >= 0 {
					best = fmt.Sprintf("%dms", b)
				}
				statsLabel.SetText(fmt.Sprintf("SCANNED: %d/%d   OPEN: %d   BEST: %s", done, total, o, best))
				updateList()
			}

			wg.Wait()
		done:
			updateList()
			mu.Lock()
			o := openCount
			mu.Unlock()
			if o > 0 {
				copyBtn.Show()
			}
			scanBtn.SetText("SCAN")
			scanning = false
			statsLabel.SetText(fmt.Sprintf("تموم شد — SCANNED: %d   OPEN: %d   BEST: %s", total, o, func() string {
				if bestMs < 0 {
					return "—"
				}
				return fmt.Sprintf("%dms", bestMs)
			}()))
		}()
	}

	// ── Layout ──
	content := container.NewVBox(
		container.NewCenter(title),
		container.NewCenter(sub),
		widget.NewSeparator(),
		widget.NewLabel("رنج / CIDR:"),
		cidrEntry,
		widget.NewLabel("پورت‌ها (با کاما):"),
		portEntry,
		countLabel,
		countEntry,
		scanBtn,
		progress,
		statsLabel,
		copyBtn,
		widget.NewSeparator(),
		layout.NewSpacer(),
	)

	w.SetContent(container.NewBorder(
		content, nil, nil, nil,
		container.NewVScroll(resultList),
	))

	w.ShowAndRun()
}
