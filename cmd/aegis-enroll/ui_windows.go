//go:build windows

package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32 = windows.NewLazySystemDLL("user32.dll")
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")

	pRegisterClassExW              = user32.NewProc("RegisterClassExW")
	pCreateWindowExW               = user32.NewProc("CreateWindowExW")
	pDefWindowProcW                = user32.NewProc("DefWindowProcW")
	pDestroyWindow                 = user32.NewProc("DestroyWindow")
	pShowWindow                    = user32.NewProc("ShowWindow")
	pUpdateWindow                  = user32.NewProc("UpdateWindow")
	pGetMessageW                   = user32.NewProc("GetMessageW")
	pTranslateMessage              = user32.NewProc("TranslateMessage")
	pDispatchMessageW              = user32.NewProc("DispatchMessageW")
	pIsDialogMessageW              = user32.NewProc("IsDialogMessageW")
	pPostQuitMessage               = user32.NewProc("PostQuitMessage")
	pPostMessageW                  = user32.NewProc("PostMessageW")
	pSendMessageW                  = user32.NewProc("SendMessageW")
	pBeginPaint                    = user32.NewProc("BeginPaint")
	pEndPaint                      = user32.NewProc("EndPaint")
	pGetClientRect                 = user32.NewProc("GetClientRect")
	pDrawTextW                     = user32.NewProc("DrawTextW")
	pFillRect                      = user32.NewProc("FillRect")
	pSetWindowPos                  = user32.NewProc("SetWindowPos")
	pGetSystemMetrics              = user32.NewProc("GetSystemMetrics")
	pGetDpiForWindow               = user32.NewProc("GetDpiForWindow")
	pSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	pLoadCursorW                   = user32.NewProc("LoadCursorW")
	pGetWindowTextLengthW          = user32.NewProc("GetWindowTextLengthW")
	pGetWindowTextW                = user32.NewProc("GetWindowTextW")
	pEnableWindow                  = user32.NewProc("EnableWindow")
	pSetFocus                      = user32.NewProc("SetFocus")
	pInvalidateRect                = user32.NewProc("InvalidateRect")

	pCreateFontW            = gdi32.NewProc("CreateFontW")
	pCreateSolidBrush       = gdi32.NewProc("CreateSolidBrush")
	pCreatePen              = gdi32.NewProc("CreatePen")
	pSelectObject           = gdi32.NewProc("SelectObject")
	pDeleteObject           = gdi32.NewProc("DeleteObject")
	pSetTextColor           = gdi32.NewProc("SetTextColor")
	pSetBkMode              = gdi32.NewProc("SetBkMode")
	pSetBkColor             = gdi32.NewProc("SetBkColor")
	pRoundRect              = gdi32.NewProc("RoundRect")
	pCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	pCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	pBitBlt                 = gdi32.NewProc("BitBlt")
	pDeleteDC               = gdi32.NewProc("DeleteDC")
)

const (
	wsOverlapped    = 0x00000000
	wsCaption       = 0x00C00000
	wsSysMenu       = 0x00080000
	wsVisible       = 0x10000000
	wsChild         = 0x40000000
	wsTabStop       = 0x00010000
	wsExClientEdge  = 0x00000200
	esAutoHScroll   = 0x0080
	bsPushButton    = 0x00000000
	bsDefPushButton = 0x00000001
	swShowNormal    = 1

	wmDestroy       = 0x0002
	wmPaint         = 0x000F
	wmClose         = 0x0010
	wmCommand       = 0x0111
	wmCtlColorEdit  = 0x0133
	wmSetFont       = 0x0030
	wmEnrollDone    = 0x8001 // WM_APP + 1

	idBtnActivate = 1 // IDOK
	idBtnCancel   = 2 // IDCANCEL
	idEditURL     = 101
	idEditCode    = 102

	dtLeft       = 0x00000000
	dtWordBreak  = 0x00000010
	dtSingleLine = 0x00000020
	srccopy      = 0x00CC0020
	transparent  = 1
	colorWindow  = 5
)

type rect struct {
	Left, Top, Right, Bottom int32
}

type paintStruct struct {
	Hdc         uintptr
	FErase      int32
	RcPaint     rect
	FRestore    int32
	FIncUpdate  int32
	RgbReserved [32]byte
}

type wndMsg struct {
	Hwnd    uintptr
	Message uint32
	Wparam  uintptr
	Lparam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

type wndClassExW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type enrollAsyncResult struct {
	out enrollOutput
	err error
}

type enrollDialog struct {
	params     enrollDialogParams
	onSubmit   enrollSubmitFn
	parentCtx  context.Context
	cancelCall context.CancelFunc

	scale      float64
	hwnd       uintptr
	hEditURL   uintptr
	hEditCode  uintptr
	hBtnActive uintptr
	hBtnCancel uintptr

	fontTitle    uintptr
	fontSubtitle uintptr
	fontLabel    uintptr
	fontInput    uintptr
	fontStatus   uintptr
	fontButton   uintptr

	brushBg      uintptr
	brushCard    uintptr
	penCard      uintptr
	brushEditBg  uintptr

	busy          bool
	statusText    string
	statusIsError bool
	done          bool
	finalOut      enrollOutput
	finalErr      error

	mu          sync.Mutex
	asyncResult *enrollAsyncResult
}

var (
	enrollClassOnce sync.Once
	activeEnrollDlg *enrollDialog
)

func showEnrollDialog(ctx context.Context, params enrollDialogParams, onSubmit enrollSubmitFn) (enrollOutput, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if pSetProcessDpiAwarenessContext.Find() == nil {
		_, _, _ = pSetProcessDpiAwarenessContext.Call(uintptr(0xfffffffffffffffc))
	}

	d := &enrollDialog{
		params:    params,
		onSubmit:  onSubmit,
		parentCtx: ctx,
		scale:     1.0,
		finalErr:  errCancelled,
	}
	activeEnrollDlg = d
	defer func() {
		if d.cancelCall != nil {
			d.cancelCall()
		}
		activeEnrollDlg = nil
	}()

	className, err := windows.UTF16PtrFromString("AegisProtocolEnrollDialog")
	if err != nil {
		return enrollOutput{}, err
	}

	enrollClassOnce.Do(func() {
		cursor, _, _ := pLoadCursorW.Call(0, 32512)
		wc := wndClassExW{
			CbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
			Style:         0x0003,
			LpfnWndProc:   windows.NewCallback(enrollWndProc),
			HCursor:       cursor,
			HbrBackground: uintptr(colorWindow + 1),
			LpszClassName: className,
		}
		pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	})

	titleText := fmt.Sprintf("Activar %s · Aegis RD", params.ProductName)
	titlePtr, _ := windows.UTF16PtrFromString(titleText)

	hwnd, _, _ := pCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(wsOverlapped|wsCaption|wsSysMenu),
		uintptr(0x80000000),
		uintptr(0x80000000),
		460,
		340,
		0, 0, 0, 0,
	)
	if hwnd == 0 {
		return enrollOutput{}, fmt.Errorf("no se pudo crear la ventana de enrolamiento")
	}
	d.hwnd = hwnd

	if pGetDpiForWindow.Find() == nil {
		if dpi, _, _ := pGetDpiForWindow.Call(hwnd); dpi > 0 {
			d.scale = float64(dpi) / 96.0
		}
	}
	if d.scale < 1.0 {
		d.scale = 1.0
	}

	d.initResources()
	defer d.cleanup()

	winW := d.dp(460)
	winH := d.dp(376)
	screenW, _, _ := pGetSystemMetrics.Call(0)
	screenH, _, _ := pGetSystemMetrics.Call(1)
	posX := max(0, (int(screenW)-winW)/2)
	posY := max(0, (int(screenH)-winH)/2)
	pSetWindowPos.Call(hwnd, 0, uintptr(posX), uintptr(posY), uintptr(winW), uintptr(winH), 0x0040)

	var cr rect
	pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&cr)))
	d.createControls(int(cr.Right-cr.Left), int(cr.Bottom-cr.Top))
	pShowWindow.Call(hwnd, swShowNormal)
	pUpdateWindow.Call(hwnd)
	pSetFocus.Call(d.hEditCode)

	var m wndMsg
	for {
		ret, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		handled, _, _ := pIsDialogMessageW.Call(hwnd, uintptr(unsafe.Pointer(&m)))
		if handled != 0 {
			continue
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}

	if d.done {
		return d.finalOut, d.finalErr
	}
	return enrollOutput{}, errCancelled
}

func (d *enrollDialog) dp(v int) int {
	return int(float64(v) * d.scale)
}

func rgb(r, g, b byte) uint32 {
	return uint32(r) | (uint32(g) << 8) | (uint32(b) << 16)
}

func (d *enrollDialog) initResources() {
	segoe, _ := windows.UTF16PtrFromString("Segoe UI")
	segoeSemi, _ := windows.UTF16PtrFromString("Segoe UI Semibold")
	mkFont := func(pt, weight int, face *uint16) uintptr {
		h, _, _ := pCreateFontW.Call(uintptr(-d.dp(pt)), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(face)))
		return h
	}
	d.fontTitle = mkFont(15, 700, segoeSemi)
	d.fontSubtitle = mkFont(10, 400, segoe)
	d.fontLabel = mkFont(9, 600, segoeSemi)
	d.fontInput = mkFont(10, 400, segoe)
	d.fontStatus = mkFont(9, 400, segoe)
	d.fontButton = mkFont(10, 600, segoeSemi)

	d.brushBg, _, _ = pCreateSolidBrush.Call(uintptr(rgb(255, 255, 255)))
	d.brushCard, _, _ = pCreateSolidBrush.Call(uintptr(rgb(248, 250, 252)))
	d.penCard, _, _ = pCreatePen.Call(0, 1, uintptr(rgb(226, 232, 240)))
	d.brushEditBg, _, _ = pCreateSolidBrush.Call(uintptr(rgb(255, 255, 255)))
}

func (d *enrollDialog) cleanup() {
	for _, h := range []uintptr{
		d.fontTitle, d.fontSubtitle, d.fontLabel, d.fontInput, d.fontStatus, d.fontButton,
		d.brushBg, d.brushCard, d.penCard, d.brushEditBg,
	} {
		if h != 0 {
			pDeleteObject.Call(h)
		}
	}
}

func (d *enrollDialog) createControls(clientW, clientH int) {
	margin := d.dp(24)
	contentW := clientW - margin*2
	editClass, _ := windows.UTF16PtrFromString("EDIT")
	btnClass, _ := windows.UTF16PtrFromString("BUTTON")

	urlPtr, _ := windows.UTF16PtrFromString(d.params.InitialURL)
	d.hEditURL, _, _ = pCreateWindowExW.Call(
		wsExClientEdge,
		uintptr(unsafe.Pointer(editClass)),
		uintptr(unsafe.Pointer(urlPtr)),
		uintptr(wsChild|wsVisible|wsTabStop|esAutoHScroll),
		uintptr(margin),
		uintptr(d.dp(146)),
		uintptr(contentW),
		uintptr(d.dp(26)),
		d.hwnd,
		idEditURL,
		0, 0,
	)
	pSendMessageW.Call(d.hEditURL, wmSetFont, d.fontInput, 1)

	emptyPtr, _ := windows.UTF16PtrFromString("")
	d.hEditCode, _, _ = pCreateWindowExW.Call(
		wsExClientEdge,
		uintptr(unsafe.Pointer(editClass)),
		uintptr(unsafe.Pointer(emptyPtr)),
		uintptr(wsChild|wsVisible|wsTabStop|esAutoHScroll),
		uintptr(margin),
		uintptr(d.dp(202)),
		uintptr(contentW),
		uintptr(d.dp(26)),
		d.hwnd,
		idEditCode,
		0, 0,
	)
	pSendMessageW.Call(d.hEditCode, wmSetFont, d.fontInput, 1)

	btnW := d.dp(106)
	btnH := d.dp(30)
	btnY := clientH - d.dp(20) - btnH
	cancelX := clientW - margin - btnW
	actX := cancelX - btnW - d.dp(10)

	actPtr, _ := windows.UTF16PtrFromString("Activar")
	d.hBtnActive, _, _ = pCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(btnClass)),
		uintptr(unsafe.Pointer(actPtr)),
		uintptr(wsChild|wsVisible|wsTabStop|bsDefPushButton),
		uintptr(actX),
		uintptr(btnY),
		uintptr(btnW),
		uintptr(btnH),
		d.hwnd,
		idBtnActivate,
		0, 0,
	)
	pSendMessageW.Call(d.hBtnActive, wmSetFont, d.fontButton, 1)

	cancelPtr, _ := windows.UTF16PtrFromString("Cancelar")
	d.hBtnCancel, _, _ = pCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(btnClass)),
		uintptr(unsafe.Pointer(cancelPtr)),
		uintptr(wsChild|wsVisible|wsTabStop|bsPushButton),
		uintptr(cancelX),
		uintptr(btnY),
		uintptr(btnW),
		uintptr(btnH),
		d.hwnd,
		idBtnCancel,
		0, 0,
	)
	pSendMessageW.Call(d.hBtnCancel, wmSetFont, d.fontButton, 1)
}

func enrollWndProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	d := activeEnrollDlg
	if d == nil {
		r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wparam, lparam)
		return r
	}

	switch msg {
	case wmPaint:
		d.onPaint(hwnd)
		return 0

	case wmCtlColorEdit:
		pSetBkColor.Call(wparam, uintptr(rgb(255, 255, 255)))
		pSetTextColor.Call(wparam, uintptr(rgb(15, 23, 42)))
		return d.brushEditBg

	case wmCommand:
		cmdID := uint16(wparam & 0xFFFF)
		switch cmdID {
		case idBtnActivate:
			d.submit()
			return 0
		case idBtnCancel:
			d.cancelAndClose()
			return 0
		}

	case wmEnrollDone:
		d.handleAsyncDone()
		return 0

	case wmClose:
		d.cancelAndClose()
		return 0

	case wmDestroy:
		pPostQuitMessage.Call(0)
		return 0
	}

	r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wparam, lparam)
	return r
}

func (d *enrollDialog) submit() {
	if d.busy {
		return
	}
	rdURL := strings.TrimSpace(getWindowText(d.hEditURL))
	code := strings.TrimSpace(getWindowText(d.hEditCode))
	if code == "" {
		d.setStatus("Ingresá el código de enrolamiento generado en Aegis RD.", true)
		pSetFocus.Call(d.hEditCode)
		return
	}

	d.setBusy(true)
	d.setStatus("Verificando código con Aegis RD...", false)

	if d.cancelCall != nil {
		d.cancelCall()
	}
	callCtx, cancel := context.WithCancel(d.parentCtx)
	d.cancelCall = cancel

	go func() {
		out, err := d.onSubmit(callCtx, rdURL, code)
		d.mu.Lock()
		d.asyncResult = &enrollAsyncResult{out: out, err: err}
		d.mu.Unlock()
		pPostMessageW.Call(d.hwnd, wmEnrollDone, 0, 0)
	}()
}

func (d *enrollDialog) handleAsyncDone() {
	d.mu.Lock()
	res := d.asyncResult
	d.asyncResult = nil
	d.mu.Unlock()

	if res == nil {
		return
	}
	if res.err == nil {
		d.done = true
		d.finalOut = res.out
		d.finalErr = nil
		pDestroyWindow.Call(d.hwnd)
		return
	}
	d.setBusy(false)
	d.setStatus(formatFriendlyError(res.err), true)
	pSetFocus.Call(d.hEditCode)
}

func (d *enrollDialog) cancelAndClose() {
	if d.cancelCall != nil {
		d.cancelCall()
	}
	d.done = true
	d.finalOut = enrollOutput{}
	d.finalErr = errCancelled
	pDestroyWindow.Call(d.hwnd)
}

func (d *enrollDialog) setBusy(busy bool) {
	d.busy = busy
	enable := uintptr(1)
	if busy {
		enable = 0
	}
	pEnableWindow.Call(d.hEditURL, enable)
	pEnableWindow.Call(d.hEditCode, enable)
	pEnableWindow.Call(d.hBtnActive, enable)
}

func (d *enrollDialog) setStatus(text string, isErr bool) {
	d.statusText = text
	d.statusIsError = isErr
	pInvalidateRect.Call(d.hwnd, 0, 0)
}

func (d *enrollDialog) onPaint(hwnd uintptr) {
	var ps paintStruct
	hdc, _, _ := pBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	defer pEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))

	var cr rect
	pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&cr)))
	w := int(cr.Right - cr.Left)
	h := int(cr.Bottom - cr.Top)
	if w <= 0 || h <= 0 {
		return
	}

	memHDC, _, _ := pCreateCompatibleDC.Call(hdc)
	memBmp, _, _ := pCreateCompatibleBitmap.Call(hdc, uintptr(w), uintptr(h))
	oldBmp, _, _ := pSelectObject.Call(memHDC, memBmp)

	pFillRect.Call(memHDC, uintptr(unsafe.Pointer(&cr)), d.brushBg)
	pSetBkMode.Call(memHDC, transparent)

	margin := d.dp(24)
	contentW := w - margin*2

	pSelectObject.Call(memHDC, d.fontTitle)
	pSetTextColor.Call(memHDC, uintptr(rgb(15, 23, 42)))
	drawText(memHDC, "Activar equipo en Aegis RD", margin, d.dp(18), contentW, d.dp(24), dtLeft|dtSingleLine)

	pSelectObject.Call(memHDC, d.fontSubtitle)
	pSetTextColor.Call(memHDC, uintptr(rgb(100, 116, 139)))
	drawText(memHDC, "Ingresá el código de un solo uso generado en Equipos y flota.", margin, d.dp(42), contentW, d.dp(18), dtLeft|dtSingleLine)

	cardTop := d.dp(68)
	cardH := d.dp(46)
	oldBrush, _, _ := pSelectObject.Call(memHDC, d.brushCard)
	oldPen, _, _ := pSelectObject.Call(memHDC, d.penCard)
	pRoundRect.Call(memHDC, uintptr(margin), uintptr(cardTop), uintptr(margin+contentW), uintptr(cardTop+cardH), uintptr(d.dp(6)), uintptr(d.dp(6)))
	pSelectObject.Call(memHDC, oldBrush)
	pSelectObject.Call(memHDC, oldPen)

	pSelectObject.Call(memHDC, d.fontLabel)
	pSetTextColor.Call(memHDC, uintptr(rgb(30, 41, 59)))
	drawText(memHDC, fmt.Sprintf("Producto: %s (%s)", d.params.ProductName, d.params.ProductID), margin+d.dp(10), cardTop+d.dp(6), contentW-d.dp(20), d.dp(16), dtLeft|dtSingleLine)

	pSelectObject.Call(memHDC, d.fontStatus)
	pSetTextColor.Call(memHDC, uintptr(rgb(71, 85, 105)))
	drawText(memHDC, fmt.Sprintf("Equipo: %s", d.params.Hostname), margin+d.dp(10), cardTop+d.dp(24), contentW-d.dp(20), d.dp(16), dtLeft|dtSingleLine)

	pSelectObject.Call(memHDC, d.fontLabel)
	pSetTextColor.Call(memHDC, uintptr(rgb(51, 65, 85)))
	drawText(memHDC, "Servidor Aegis RD", margin, d.dp(126), contentW, d.dp(16), dtLeft|dtSingleLine)
	drawText(memHDC, "Código de enrolamiento", margin, d.dp(182), contentW, d.dp(16), dtLeft|dtSingleLine)

	if d.statusText != "" {
		pSelectObject.Call(memHDC, d.fontStatus)
		if d.statusIsError {
			pSetTextColor.Call(memHDC, uintptr(rgb(220, 38, 38)))
		} else {
			pSetTextColor.Call(memHDC, uintptr(rgb(37, 99, 235)))
		}
		drawText(memHDC, d.statusText, margin, d.dp(236), contentW, d.dp(34), dtLeft|dtWordBreak)
	}

	pBitBlt.Call(hdc, 0, 0, uintptr(w), uintptr(h), memHDC, 0, 0, srccopy)
	pSelectObject.Call(memHDC, oldBmp)
	pDeleteObject.Call(memBmp)
	pDeleteDC.Call(memHDC)
}

func drawText(hdc uintptr, text string, x, y, w, h int, flags uint32) {
	if text == "" {
		return
	}
	ptr, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	r := rect{Left: int32(x), Top: int32(y), Right: int32(x + w), Bottom: int32(y + h)}
	pDrawTextW.Call(hdc, uintptr(unsafe.Pointer(ptr)), uintptr(len([]rune(text))), uintptr(unsafe.Pointer(&r)), uintptr(flags))
}

func getWindowText(hwnd uintptr) string {
	n, _, _ := pGetWindowTextLengthW.Call(hwnd)
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	pGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), n+1)
	return windows.UTF16ToString(buf)
}
