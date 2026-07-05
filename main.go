package main

import (
	_ "embed"
	"fmt"
	"image/color"
	"math/rand"
	"net"
	"regexp"
	"sort"
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
)

// ─── رنج‌های رسمی کلودفلر ───────────────────────────────────────────────────
// عکس پس‌زمینه از قبل رندر شده — به‌جای گرادیانت زنده که هر رفرش
// دوباره محاسبه می‌شد و باعث لگ موقع تایپ می‌شد.
//
//go:embed background.png
var bgPNGBytes []byte

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

// ─── پالت رنگی ────────────────────────────────────────────────────────────────
var (
	colBg      = color.NRGBA{8, 6, 14, 255}
	colGlow    = color.NRGBA{46, 20, 82, 255}   // نور بنفش محو پشت صفحه
	colCard    = color.NRGBA{28, 22, 46, 150}   // نیمه‌شفاف برای حس شیشه‌ای
	colBorder  = color.NRGBA{150, 130, 200, 90} // لبه‌ی روشن‌تر برای حس شیشه
	colAccent  = color.NRGBA{139, 63, 255, 255}
	colAccent2 = color.NRGBA{0, 224, 190, 255}
	colFg      = color.NRGBA{225, 219, 245, 255}
	colFgDim   = color.NRGBA{148, 138, 176, 255}
	colGood    = color.NRGBA{0, 224, 150, 255}  // پینگ خوب
	colMid     = color.NRGBA{255, 196, 0, 255}  // پینگ متوسط
	colBad     = color.NRGBA{255, 76, 76, 255}  // پینگ بد
)

type ScanResult struct {
	IP     string
	Port   int
	PingMs int64
}

type ConfigItem struct {
	IP     string
	Port   int
	Config string
}

// الگویی برای پیدا کردن یه IP:PORT واقعی که کاربر مستقیم توی قالب پیست کرده،
// برای وقتی که به‌جای {ip}/{port} از یه کانفیگ واقعی استفاده می‌کنه.
var ipPortRe = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\b`)

// کیبوردهای فارسی گاهی رقم‌های ۰-۹ یا ٠-٩ رو به‌جای 0-9 وارد می‌کنن؛
// این تابع همه رو به رقم انگلیسی معمولی تبدیل می‌کنه تا تشخیص IP خراب نشه.
func normalizeDigits(s string) string {
	r := []rune(s)
	for i, c := range r {
		switch {
		case c >= '۰' && c <= '۹': // فارسی
			r[i] = '0' + (c - '۰')
		case c >= '٠' && c <= '٩': // عربی
			r[i] = '0' + (c - '٠')
		}
	}
	return string(r)
}

// ─── تست TCP خام (بدون TLS) ─────────────────────────────────────────────────
// رنگ‌بندی سه‌سطحی بر اساس پینگ: سریع=سبز، متوسط=زرد، کند=قرمز
func pingColor(ms int64) color.Color {
	switch {
	case ms <= 150:
		return colGood
	case ms <= 500:
		return colMid
	default:
		return colBad
	}
}

func pingTCP(ip string, port int, timeout time.Duration) (int64, bool) {
	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return 0, false
	}
	conn.Close()
	ms := time.Since(t0).Milliseconds()
	if ms < 5 {
		return 0, false
	}
	return ms, true
}

// ─── تولید IP از CIDR ────────────────────────────────────────────────────────
func genFromOneCIDR(cidr string) []string {
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

// چند تا رنج CIDR که با کاما از هم جدا شدن رو با هم می‌سازه (بدون تکراری)
func genFromCIDR(cidrList string) []string {
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(cidrList, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		for _, ip := range genFromOneCIDR(part) {
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	return out
}

// ─── تولید IP رندوم از ساب‌نت‌های کلودفلر ────────────────────────────────────
// لیست IP دلخواه کاربر رو پارس می‌کنه — با خط جدید، کاما یا فاصله جدا شده باشن مهم نیست
func parseIPList(text string) []string {
	text = normalizeDigits(text)
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' ' || r == ';'
	})
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		octets := strings.Split(f, ".")
		if len(octets) != 4 {
			continue
		}
		valid := true
		for _, o := range octets {
			n, err := strconv.Atoi(o)
			if err != nil || n < 0 || n > 255 {
				valid = false
				break
			}
		}
		if valid && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

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
		return colBg
	case theme.ColorNameButton:
		return colCard
	case theme.ColorNamePrimary:
		return colAccent
	case theme.ColorNameForeground:
		return colFg
	case theme.ColorNamePlaceHolder:
		return colFgDim
	case theme.ColorNameInputBackground:
		return colCard
	case theme.ColorNameSeparator:
		return colBorder
	}
	return theme.DefaultTheme().Color(n, v)
}
func (darkTheme) Font(s fyne.TextStyle) fyne.Resource     { return theme.DefaultTheme().Font(s) }
func (darkTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (darkTheme) Size(n fyne.ThemeSizeName) float32       { return theme.DefaultTheme().Size(n) }

// section یک بلوک با عنوان و کادر دور، برای مرتب‌سازی بصری.
func section(titleText string, items ...fyne.CanvasObject) fyne.CanvasObject {
	body := container.NewVBox(items...)
	if titleText != "" {
		lbl := canvas.NewText(titleText, colFgDim)
		lbl.TextSize = 12
		lbl.TextStyle = fyne.TextStyle{Bold: true}
		lbl.Alignment = fyne.TextAlignTrailing // راست‌چین برای فارسی
		body = container.NewVBox(append([]fyne.CanvasObject{lbl}, items...)...)
	}

	bg := canvas.NewRectangle(colCard)
	bg.CornerRadius = 12
	bg.StrokeColor = colBorder
	bg.StrokeWidth = 1

	inner := container.New(layout.NewCustomPaddedLayout(8, 8, 12, 12), body)
	return container.New(layout.NewCustomPaddedLayout(4, 4, 6, 6), container.NewStack(bg, inner))
}

func main() {
	a := app.New()
	a.Settings().SetTheme(darkTheme{})
	w := a.NewWindow("MHMTSCANNER")
	w.Resize(fyne.NewSize(430, 780))

	// ── Header ──
	title := canvas.NewText("MHMTSCANNER", colAccent)
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.TextSize = 19
	title.Alignment = fyne.TextAlignCenter

	sub := canvas.NewText("CF CLEAN IP SCANNER  •  RAW TCP", colFgDim)
	sub.TextSize = 9
	sub.Alignment = fyne.TextAlignCenter

	accentBar := canvas.NewRectangle(colAccent)
	accentBar.SetMinSize(fyne.NewSize(0, 2))
	accentBar2 := canvas.NewRectangle(colAccent2)
	accentBar2.SetMinSize(fyne.NewSize(0, 2))

	header := container.NewVBox(
		container.New(layout.NewCustomPaddedLayout(4, 2, 6, 6), container.NewVBox(
			container.NewCenter(title),
			container.NewCenter(sub),
		)),
		container.NewGridWithColumns(2, accentBar, accentBar2),
	)

	// ── Inputs ──
	cidrEntry := widget.NewEntry()
	cidrEntry.SetPlaceHolder("مثال: 104.16.0.0/24, 172.64.0.0/24  —  خالی یعنی رندوم")

	// رنج‌های رسمی کلودفلر (طبق cloudflare.com/ips) — قابل انتخاب چندتایی
	officialCFRanges := []string{
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
	}
	rangeChecks := make([]*widget.Check, 0, len(officialCFRanges))
	rangeList := container.NewVBox()
	for _, rng := range officialCFRanges {
		chk := widget.NewCheck(rng, nil)
		rangeChecks = append(rangeChecks, chk)
		rangeList.Add(chk)
	}
	addSelectedRangesBtn := widget.NewButton("اضافه کردن انتخاب‌شده‌ها به کادر رنج", func() {
		cur := strings.TrimSpace(cidrEntry.Text)
		existing := map[string]bool{}
		for _, p := range strings.Split(cur, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				existing[p] = true
			}
		}
		var toAdd []string
		for i, chk := range rangeChecks {
			if chk.Checked {
				rng := officialCFRanges[i]
				if !existing[rng] {
					toAdd = append(toAdd, rng)
					existing[rng] = true
				}
				chk.SetChecked(false) // برای استفاده‌ی دوباره خالی بشه
			}
		}
		if len(toAdd) == 0 {
			return
		}
		if cur == "" {
			cidrEntry.SetText(strings.Join(toAdd, ", "))
		} else {
			cidrEntry.SetText(cur + ", " + strings.Join(toAdd, ", "))
		}
		// جلوگیری از باز موندن فوکوس روی کادر متنی، تا نوار Cut/Copy/Paste
		// اندروید خودکار باز نمونه (که خودش می‌تونه باعث افت فریم بشه).
		w.Canvas().Unfocus()
	})
	addSelectedRangesBtn.Importance = widget.LowImportance

	// جعبه‌ی جدا و جمع‌شونده برای رنج‌های پیشنهادی — پیش‌فرض بسته‌ست
	// تا هم شلوغ نباشه هم موقع بسته بودن سربار رندر نداشته باشه.
	// خود لیست چک‌باکس‌ها یه اسکرول کوچیک و مستقل داره (ارتفاع ثابت)
	// تا وقتی باز میشه، کل صفحه بلند نشه و بقیه‌ی بخش‌ها (دکمه‌ی اسکن،
	// تب‌ها) همیشه در دسترس بمونن.
	rangeScroll := container.NewVScroll(rangeList)
	rangeScroll.SetMinSize(fyne.NewSize(0, 260))

	rangeBody := container.NewVBox(widget.NewSeparator(), rangeScroll, addSelectedRangesBtn)
	rangeBody.Hide()

	var toggleRangeBtn *widget.Button
	toggleRangeBtn = widget.NewButton("نمایش رنج‌های پیشنهادی ▼", func() {
		if rangeBody.Visible() {
			rangeBody.Hide()
			toggleRangeBtn.SetText("نمایش رنج‌های پیشنهادی ▼")
		} else {
			rangeBody.Show()
			toggleRangeBtn.SetText("جمع کردن رنج‌های پیشنهادی ▲")
		}
	})
	toggleRangeBtn.Importance = widget.LowImportance
	rangeSettingsBox := container.NewVBox(toggleRangeBtn, rangeBody)

	// ── لیست IP دلخواه ── وقتی پر باشه، به‌جای CIDR/رندوم همین‌ها تست میشن
	// (این بخش یه تب کامل و جدا برای خودش داره، پایین‌تر تعریف میشه)
	customIPHelp := widget.NewLabel("هر آی‌پی رو توی یه خط جدا، یا با کاما از هم جدا کن. اگه اینجا چیزی بنویسی، اسکنر به‌جای رنج یا حالت رندوم، دقیقاً همین آی‌پی‌ها رو تست می‌کنه.")
	customIPHelp.Wrapping = fyne.TextWrapWord
	customIPHelp.Alignment = fyne.TextAlignTrailing

	customIPEntry := widget.NewMultiLineEntry()
	customIPEntry.SetPlaceHolder("مثال:\n104.16.0.5\n104.16.0.9, 172.64.0.3")
	customIPEntry.Wrapping = fyne.TextWrapWord
	customIPEntry.SetMinRowsVisible(10)

	clearCustomIPBtn := widget.NewButtonWithIcon("پاک کردن لیست", theme.DeleteIcon(), func() {
		customIPEntry.SetText("")
	})
	clearCustomIPBtn.Importance = widget.LowImportance

	customIPCard := section("لیست آی‌پی دلخواه", customIPHelp, customIPEntry, clearCustomIPBtn)

	portEntry := widget.NewEntry()
	portEntry.SetText("443")

	countEntry := widget.NewEntry()
	countEntry.SetText("100")

	// ── Stats ──
	statsLabel := widget.NewLabelWithStyle("SCANNED: 0   OPEN: 0   BEST: —", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	progress := widget.NewProgressBar()
	progress.Min = 0
	progress.Max = 1

	scanBtn := widget.NewButtonWithIcon("SCAN", theme.MediaPlayIcon(), nil)
	scanBtn.Importance = widget.HighImportance

	settingsBody := container.NewVBox(
		widget.NewLabelWithStyle("تنظیمات رنج", fyne.TextAlignTrailing, fyne.TextStyle{}),
		rangeSettingsBox,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("رنج CIDR – با کاما چند رنج جدا کن", fyne.TextAlignTrailing, fyne.TextStyle{}),
		cidrEntry,
		container.NewGridWithColumns(2,
			container.NewVBox(
				widget.NewLabelWithStyle("پورت‌ها – با کاما جدا کن", fyne.TextAlignTrailing, fyne.TextStyle{}),
				portEntry,
			),
			container.NewVBox(
				widget.NewLabelWithStyle("تعداد – حالت رندوم", fyne.TextAlignTrailing, fyne.TextStyle{}),
				countEntry,
			),
		),
		widget.NewSeparator(),
		scanBtn,
		progress,
		statsLabel,
	)

	settingsTitle := canvas.NewText("تنظیمات اسکن", colFgDim)
	settingsTitle.TextSize = 12
	settingsTitle.TextStyle = fyne.TextStyle{Bold: true}
	settingsTitle.Alignment = fyne.TextAlignTrailing

	// دکمه‌ی جمع/باز کردن کارت تنظیمات، برای اینکه بشه فضای بیشتری
	// به لیست نتایج/کانفیگ داد.
	var toggleSettingsBtn *widget.Button
	toggleSettingsBtn = widget.NewButton("جمع کن ▲", func() {
		if settingsBody.Visible() {
			settingsBody.Hide()
			toggleSettingsBtn.SetText("باز کن ▼")
		} else {
			settingsBody.Show()
			toggleSettingsBtn.SetText("جمع کن ▲")
		}
	})
	toggleSettingsBtn.Importance = widget.LowImportance

	titleRow := container.NewBorder(nil, nil, toggleSettingsBtn, nil, settingsTitle)

	settingsBg := canvas.NewRectangle(colCard)
	settingsBg.CornerRadius = 12
	settingsBg.StrokeColor = colBorder
	settingsBg.StrokeWidth = 1
	settingsInner := container.New(layout.NewCustomPaddedLayout(8, 8, 12, 12), container.NewVBox(titleRow, settingsBody))
	settingsCard := container.New(layout.NewCustomPaddedLayout(4, 4, 6, 6), container.NewStack(settingsBg, settingsInner))

	top := container.NewVBox(header, settingsCard)

	// ── Shared state ──
	var (
		results  []ScanResult
		configs  []ConfigItem
		mu       sync.Mutex
		stopCh   chan struct{}
		scanning bool
	)

	// ═══════════════════ تب نتایج IP ═══════════════════

	resultList := widget.NewList(
		func() int { return 0 },
		func() fyne.CanvasObject {
			ip := widget.NewLabel("0.0.0.0:443")
			ip.TextStyle = fyne.TextStyle{Monospace: true}
			ping := canvas.NewText("0ms", colGood)
			ping.TextStyle = fyne.TextStyle{Bold: true}
			copyIcon := widget.NewIcon(theme.ContentCopyIcon())
			right := container.NewHBox(ping, copyIcon)
			return container.NewHBox(ip, layout.NewSpacer(), right)
		},
		func(id widget.ListItemID, o fyne.CanvasObject) {},
	)

	copyAllBtn := widget.NewButtonWithIcon("کپی همه آی‌پی", theme.ContentCopyIcon(), func() {
		mu.Lock()
		lines := make([]string, len(results))
		for i, r := range results {
			lines[i] = r.IP
		}
		mu.Unlock()
		w.Clipboard().SetContent(strings.Join(lines, "\n"))
	})
	copyAllBtn.Hide()

	updateList := func() {
		mu.Lock()
		local := make([]ScanResult, len(results))
		copy(local, results)
		mu.Unlock()

		// آیپی‌های با پینگ کمتر (بهتر) اول لیست بیان
		sort.Slice(local, func(i, j int) bool { return local[i].PingMs < local[j].PingMs })

		resultList.Length = func() int { return len(local) }
		resultList.UpdateItem = func(id widget.ListItemID, o fyne.CanvasObject) {
			r := local[id]
			box := o.(*fyne.Container)
			ip := box.Objects[0].(*widget.Label)
			right := box.Objects[2].(*fyne.Container)
			ping := right.Objects[0].(*canvas.Text)

			ip.SetText(fmt.Sprintf("%s:%d", r.IP, r.Port))
			ping.Text = fmt.Sprintf("%dms", r.PingMs)
			ping.Color = pingColor(r.PingMs)
			ping.Refresh()
		}
		// با لمس هر ردیف، فقط همون IP کپی میشه — سبک‌تر از یک دکمه‌ی
		// جداگانه روی هر ردیف، برای اسکرول روون‌تر با لیست‌های بزرگ.
		resultList.OnSelected = func(id widget.ListItemID) {
			if id >= 0 && id < len(local) {
				r := local[id]
				w.Clipboard().SetContent(fmt.Sprintf("%s:%d", r.IP, r.Port))
			}
			resultList.UnselectAll()
		}
		resultList.Refresh()
	}

	resultsBg := canvas.NewRectangle(colCard)
	resultsBg.CornerRadius = 12
	resultsWrap := container.NewPadded(container.NewStack(resultsBg, container.NewPadded(
		container.NewBorder(container.NewPadded(copyAllBtn), nil, nil, nil, resultList),
	)))

	// ═══════════════════ تب کانفیگ ═══════════════════

	configHelp := widget.NewLabel("همون کانفیگ واقعی خودت رو پیست کن — آی‌پی و پورتش رو خودش پیدا و جایگزین می‌کنه.")
	configHelp.Wrapping = fyne.TextWrapWord
	configHelp.Alignment = fyne.TextAlignTrailing

	templateEntry := widget.NewMultiLineEntry()
	templateEntry.SetPlaceHolder("مثال: trojan://pass@1.2.3.4:443?sni=example.com#MHMT")
	templateEntry.Wrapping = fyne.TextWrapWord
	templateEntry.SetMinRowsVisible(3)

	configMsg := widget.NewLabel("")
	configMsg.Alignment = fyne.TextAlignTrailing

	configList := widget.NewList(
		func() int { return 0 },
		func() fyne.CanvasObject {
			lbl := widget.NewLabel("0.0.0.0:443")
			lbl.TextStyle = fyne.TextStyle{Monospace: true}
			copyIcon := widget.NewIcon(theme.ContentCopyIcon())
			return container.NewHBox(lbl, layout.NewSpacer(), copyIcon)
		},
		func(id widget.ListItemID, o fyne.CanvasObject) {},
	)

	copyAllConfigsBtn := widget.NewButtonWithIcon("کپی همه کانفیگ‌ها", theme.ContentCopyIcon(), func() {
		mu.Lock()
		lines := make([]string, len(configs))
		for i, c := range configs {
			lines[i] = c.Config
		}
		mu.Unlock()
		w.Clipboard().SetContent(strings.Join(lines, "\n\n"))
	})
	copyAllConfigsBtn.Hide()

	updateConfigList := func() {
		mu.Lock()
		local := make([]ConfigItem, len(configs))
		copy(local, configs)
		mu.Unlock()

		configList.Length = func() int { return len(local) }
		configList.UpdateItem = func(id widget.ListItemID, o fyne.CanvasObject) {
			c := local[id]
			box := o.(*fyne.Container)
			lbl := box.Objects[0].(*widget.Label)
			lbl.SetText(fmt.Sprintf("%s:%d", c.IP, c.Port))
		}
		configList.OnSelected = func(id widget.ListItemID) {
			if id >= 0 && id < len(local) {
				w.Clipboard().SetContent(local[id].Config)
			}
			configList.UnselectAll()
		}
		configList.Refresh()
	}

	genBtn := widget.NewButtonWithIcon("ساخت کانفیگ از نتایج", theme.ViewRefreshIcon(), func() {
		tpl := normalizeDigits(templateEntry.Text)
		if strings.TrimSpace(tpl) == "" {
			configMsg.SetText("اول یه قالب کانفیگ وارد کن")
			return
		}

		hasToken := strings.Contains(tpl, "{ip}")
		match := ipPortRe.FindString(tpl) // مثلاً "104.16.0.5:443"
		if !hasToken && match == "" {
			preview := tpl
			if len(preview) > 40 {
				preview = preview[:40] + "…"
			}
			configMsg.SetText(fmt.Sprintf("\u200fنه {ip} نه آدرس آی‌پی:پورت واقعی پیدا نشد. شروع قالب: %s", preview))
			return
		}

		mu.Lock()
		src := make([]ScanResult, len(results))
		copy(src, results)
		mu.Unlock()
		sort.Slice(src, func(i, j int) bool { return src[i].PingMs < src[j].PingMs })

		if len(src) == 0 {
			configMsg.SetText("هنوز نتیجه‌ای نیست — اول اسکن بزن")
			return
		}

		built := make([]ConfigItem, 0, len(src))
		for _, r := range src {
			cfg := tpl
			if hasToken {
				cfg = strings.ReplaceAll(cfg, "{ip}", r.IP)
				cfg = strings.ReplaceAll(cfg, "{port}", strconv.Itoa(r.Port))
			} else {
				// جایگزینی خودکار همون IP:PORT واقعی که توی قالب پیدا شد
				cfg = strings.Replace(cfg, match, fmt.Sprintf("%s:%d", r.IP, r.Port), 1)
			}
			built = append(built, ConfigItem{IP: r.IP, Port: r.Port, Config: cfg})
		}

		mu.Lock()
		configs = built
		mu.Unlock()

		configMsg.SetText(fmt.Sprintf("%d کانفیگ ساخته شد", len(built)))
		updateConfigList()
		copyAllConfigsBtn.Show()
	})
	genBtn.Importance = widget.HighImportance

	configCard := section("قالب کانفیگ", configHelp, templateEntry, genBtn, configMsg)

	configBg := canvas.NewRectangle(colCard)
	configBg.CornerRadius = 12
	configListWrap := container.NewPadded(container.NewStack(configBg, container.NewPadded(
		container.NewBorder(container.NewPadded(copyAllConfigsBtn), nil, nil, nil, configList),
	)))

	configTab := container.NewBorder(configCard, nil, nil, nil, configListWrap)

	// ═══════════════════ تب‌ها ═══════════════════

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("نتایج", theme.SearchIcon(), resultsWrap),
		container.NewTabItemWithIcon("کانفیگ", theme.SettingsIcon(), configTab),
		container.NewTabItemWithIcon("آی‌پی دلخواه", theme.ContentAddIcon(), customIPCard),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	// ═══════════════════ منطق اسکن ═══════════════════

	scanBtn.OnTapped = func() {
		if scanning {
			if stopCh != nil {
				close(stopCh)
			}
			return
		}

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

		var ips []string
		customIPs := parseIPList(customIPEntry.Text)
		cidr := strings.TrimSpace(cidrEntry.Text)
		switch {
		case len(customIPs) > 0:
			ips = customIPs
		case cidr != "":
			ips = genFromCIDR(cidr)
			if len(ips) == 0 {
				statsLabel.SetText("رنج CIDR معتبر نیست")
				return
			}
		default:
			n, _ := strconv.Atoi(countEntry.Text)
			if n <= 0 {
				n = 100
			}
			ips = genRandom(n)
		}

		mu.Lock()
		results = nil
		configs = nil
		mu.Unlock()
		updateList()
		updateConfigList()
		copyAllBtn.Hide()
		copyAllConfigsBtn.Hide()
		configMsg.SetText("")
		progress.SetValue(0)
		statsLabel.SetText("در حال اسکن...")

		scanning = true
		stopCh = make(chan struct{})
		scanBtn.SetText("STOP")
		scanBtn.SetIcon(theme.MediaStopIcon())

		go func() {
			total := len(ips)
			done := 0
			openCount := 0
			var bestMs int64 = -1

			sem := make(chan struct{}, 60)
			var wg sync.WaitGroup

			// آپدیت UI فقط با فاصله‌ی زمانی مشخص انجام میشه، نه برای هر IP —
			// این چیزیه که باعث لگ و گیر کردن گوشی می‌شد.
			lastUI := time.Now()
			const uiInterval = 200 * time.Millisecond

			pushUI := func(force bool) {
				if !force && time.Since(lastUI) < uiInterval {
					return
				}
				lastUI = time.Now()

				mu.Lock()
				o := openCount
				b := bestMs
				d := done
				mu.Unlock()

				best := "—"
				if b >= 0 {
					best = fmt.Sprintf("%dms", b)
				}
				pct := float64(d) / float64(total)

				// نکته‌ی اصلی رفع لگ همینه: این آپدیت فقط هر uiInterval یک‌بار
				// اجرا میشه، نه برای هر IP — قبلاً همین باعث گیر کردن UI می‌شد.
				progress.SetValue(pct)
				statsLabel.SetText(fmt.Sprintf("SCANNED: %d/%d   OPEN: %d   BEST: %s", d, total, o, best))
				updateList()
			}

		loop:
			for _, ip := range ips {
				select {
				case <-stopCh:
					break loop
				default:
				}

				for _, port := range ports {
					wg.Add(1)
					sem <- struct{}{}
					go func(ip string, port int) {
						defer wg.Done()
						defer func() { <-sem }()

						ms, ok := pingTCP(ip, port, 2500*time.Millisecond)
						if ok {
							mu.Lock()
							results = append(results, ScanResult{IP: ip, Port: port, PingMs: ms})
							openCount++
							if bestMs < 0 || ms < bestMs {
								bestMs = ms
							}
							mu.Unlock()
						}
					}(ip, port)
				}

				mu.Lock()
				done++
				mu.Unlock()
				pushUI(false)
			}

			wg.Wait()
			pushUI(true)

			mu.Lock()
			o := openCount
			b := bestMs
			mu.Unlock()

			if o > 0 {
				copyAllBtn.Show()
			}
			scanBtn.SetText("SCAN")
			scanBtn.SetIcon(theme.MediaPlayIcon())
			scanning = false
			best := "—"
			if b >= 0 {
				best = fmt.Sprintf("%dms", b)
			}
			statsLabel.SetText(fmt.Sprintf("تموم شد — SCANNED: %d   OPEN: %d   BEST: %s", total, o, best))
		}()
	}

	// عکس پس‌زمینه‌ی از‌قبل‌رندرشده به‌جای گرادیانت زنده — سبک‌تره و
	// دیگه هر تایپ یا چشمک مکان‌نما باعث محاسبه‌ی دوباره‌ش نمی‌شه.
	bgRes := fyne.NewStaticResource("background.png", bgPNGBytes)
	bgImage := canvas.NewImageFromResource(bgRes)
	bgImage.FillMode = canvas.ImageFillStretch

	w.SetContent(container.NewStack(bgImage, container.NewBorder(top, nil, nil, nil, tabs)))
	w.ShowAndRun()
}
