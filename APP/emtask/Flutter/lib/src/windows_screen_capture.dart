import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:image/image.dart' as img;
import 'package:win32/win32.dart' as win32;

class WindowsScreenCaptureResult {
  const WindowsScreenCaptureResult({
    required this.pngBytes,
    required this.width,
    required this.height,
  });

  final Uint8List pngBytes;
  final int width;
  final int height;
}

class WindowsScreenRect {
  const WindowsScreenRect({
    required this.left,
    required this.top,
    required this.width,
    required this.height,
  });

  final int left;
  final int top;
  final int width;
  final int height;
}

class WindowsWindowSnapshot {
  const WindowsWindowSnapshot({
    required this.windowHandle,
    required this.style,
    required this.exStyle,
    required this.placementFlags,
    required this.showCmd,
    required this.minX,
    required this.minY,
    required this.maxX,
    required this.maxY,
    required this.normalLeft,
    required this.normalTop,
    required this.normalRight,
    required this.normalBottom,
  });

  final int windowHandle;
  final int style;
  final int exStyle;
  final int placementFlags;
  final int showCmd;
  final int minX;
  final int minY;
  final int maxX;
  final int maxY;
  final int normalLeft;
  final int normalTop;
  final int normalRight;
  final int normalBottom;
}

WindowsScreenRect getWindowsVirtualScreenRect() {
  if (!Platform.isWindows) {
    throw UnsupportedError(
        'Windows virtual screen metrics are only available on Windows.');
  }
  final left = win32.GetSystemMetrics(win32.SM_XVIRTUALSCREEN);
  final top = win32.GetSystemMetrics(win32.SM_YVIRTUALSCREEN);
  final width = win32.GetSystemMetrics(win32.SM_CXVIRTUALSCREEN);
  final height = win32.GetSystemMetrics(win32.SM_CYVIRTUALSCREEN);
  if (width <= 0 || height <= 0) {
    throw StateError('无法获取 Windows 虚拟屏幕尺寸。');
  }
  return WindowsScreenRect(left: left, top: top, width: width, height: height);
}

WindowsWindowSnapshot snapshotForegroundWindow() {
  if (!Platform.isWindows) {
    throw UnsupportedError(
        'Windows window control is only available on Windows.');
  }
  final hwnd = win32.GetForegroundWindow();
  if (hwnd == 0) {
    throw StateError('无法获取当前窗口句柄。');
  }

  final placement = calloc<win32.WINDOWPLACEMENT>();
  try {
    placement.ref.length = sizeOf<win32.WINDOWPLACEMENT>();
    if (win32.GetWindowPlacement(hwnd, placement) == 0) {
      throw StateError('无法保存当前窗口状态。');
    }
    return WindowsWindowSnapshot(
      windowHandle: hwnd,
      style: win32.GetWindowLongPtr(hwnd, win32.GWL_STYLE),
      exStyle: win32.GetWindowLongPtr(hwnd, win32.GWL_EXSTYLE),
      placementFlags: placement.ref.flags,
      showCmd: placement.ref.showCmd,
      minX: placement.ref.ptMinPosition.x,
      minY: placement.ref.ptMinPosition.y,
      maxX: placement.ref.ptMaxPosition.x,
      maxY: placement.ref.ptMaxPosition.y,
      normalLeft: placement.ref.rcNormalPosition.left,
      normalTop: placement.ref.rcNormalPosition.top,
      normalRight: placement.ref.rcNormalPosition.right,
      normalBottom: placement.ref.rcNormalPosition.bottom,
    );
  } finally {
    calloc.free(placement);
  }
}

void hideWindowsWindow(int windowHandle) {
  if (!Platform.isWindows || windowHandle == 0) {
    return;
  }
  win32.ShowWindow(windowHandle, win32.SW_HIDE);
}

void showWindowsFullscreenOverlay(WindowsWindowSnapshot snapshot) {
  if (!Platform.isWindows) {
    return;
  }
  final screen = getWindowsVirtualScreenRect();
  final hwnd = snapshot.windowHandle;
  win32.SetWindowLongPtr(
    hwnd,
    win32.GWL_STYLE,
    win32.WS_POPUP | win32.WS_VISIBLE,
  );
  win32.SetWindowLongPtr(hwnd, win32.GWL_EXSTYLE, 0);
  win32.SetWindowPos(
    hwnd,
    win32.HWND_TOPMOST,
    screen.left,
    screen.top,
    screen.width,
    screen.height,
    win32.SWP_FRAMECHANGED | win32.SWP_SHOWWINDOW,
  );
  win32.ShowWindow(hwnd, win32.SW_SHOW);
  win32.SetForegroundWindow(hwnd);
}

void restoreWindowsWindow(WindowsWindowSnapshot snapshot) {
  if (!Platform.isWindows) {
    return;
  }
  final hwnd = snapshot.windowHandle;
  win32.SetWindowLongPtr(hwnd, win32.GWL_STYLE, snapshot.style);
  win32.SetWindowLongPtr(hwnd, win32.GWL_EXSTYLE, snapshot.exStyle);
  final placement = calloc<win32.WINDOWPLACEMENT>();
  try {
    placement.ref
      ..length = sizeOf<win32.WINDOWPLACEMENT>()
      ..flags = snapshot.placementFlags
      ..showCmd = snapshot.showCmd
      ..ptMinPosition.x = snapshot.minX
      ..ptMinPosition.y = snapshot.minY
      ..ptMaxPosition.x = snapshot.maxX
      ..ptMaxPosition.y = snapshot.maxY
      ..rcNormalPosition.left = snapshot.normalLeft
      ..rcNormalPosition.top = snapshot.normalTop
      ..rcNormalPosition.right = snapshot.normalRight
      ..rcNormalPosition.bottom = snapshot.normalBottom;
    win32.SetWindowPlacement(hwnd, placement);
  } finally {
    calloc.free(placement);
  }
  win32.SetWindowPos(
    hwnd,
    win32.HWND_NOTOPMOST,
    0,
    0,
    0,
    0,
    win32.SWP_NOMOVE |
        win32.SWP_NOSIZE |
        win32.SWP_FRAMECHANGED |
        win32.SWP_SHOWWINDOW,
  );
  win32.ShowWindow(hwnd, snapshot.showCmd);
  win32.SetForegroundWindow(hwnd);
}

WindowsScreenCaptureResult captureWindowsVirtualScreen() {
  if (!Platform.isWindows) {
    throw UnsupportedError(
        'Windows GDI screen capture is only available on Windows.');
  }

  final screen = getWindowsVirtualScreenRect();

  final desktopWindow = win32.GetDesktopWindow();
  final screenDc = win32.GetDC(desktopWindow);
  if (screenDc == 0) {
    throw StateError('无法获取 Windows 屏幕 DC。');
  }

  var memoryDc = 0;
  var bitmap = 0;
  var oldBitmap = 0;
  final bitmapInfo = calloc<win32.BITMAPINFO>();
  final bits = calloc<Pointer>();

  try {
    memoryDc = win32.CreateCompatibleDC(screenDc);
    if (memoryDc == 0) {
      throw StateError('无法创建 Windows 内存 DC。');
    }

    bitmapInfo.ref.bmiHeader
      ..biSize = sizeOf<win32.BITMAPINFOHEADER>()
      ..biWidth = screen.width
      ..biHeight = -screen.height
      ..biPlanes = 1
      ..biBitCount = 32
      ..biCompression = win32.BI_RGB
      ..biSizeImage = screen.width * screen.height * 4
      ..biXPelsPerMeter = 0
      ..biYPelsPerMeter = 0
      ..biClrUsed = 0
      ..biClrImportant = 0;

    bitmap = win32.CreateDIBSection(
      screenDc,
      bitmapInfo,
      win32.DIB_RGB_COLORS,
      bits,
      0,
      0,
    );
    if (bitmap == 0 || bits.value == nullptr) {
      throw StateError('无法创建 Windows DIB 截图缓冲区。');
    }

    oldBitmap = win32.SelectObject(memoryDc, bitmap);
    final copied = win32.BitBlt(
      memoryDc,
      0,
      0,
      screen.width,
      screen.height,
      screenDc,
      screen.left,
      screen.top,
      win32.SRCCOPY | win32.CAPTUREBLT,
    );
    if (copied == 0) {
      throw StateError('Windows 屏幕截图复制失败。');
    }

    final rawBytes = Uint8List.fromList(
      bits.value.cast<Uint8>().asTypedList(screen.width * screen.height * 4),
    );
    final image = img.Image.fromBytes(
      width: screen.width,
      height: screen.height,
      bytes: rawBytes.buffer,
      numChannels: 4,
      order: img.ChannelOrder.bgra,
    );
    return WindowsScreenCaptureResult(
      pngBytes: Uint8List.fromList(img.encodePng(image)),
      width: screen.width,
      height: screen.height,
    );
  } finally {
    if (oldBitmap != 0 && memoryDc != 0) {
      win32.SelectObject(memoryDc, oldBitmap);
    }
    if (bitmap != 0) {
      win32.DeleteObject(bitmap);
    }
    if (memoryDc != 0) {
      win32.DeleteDC(memoryDc);
    }
    win32.ReleaseDC(desktopWindow, screenDc);
    calloc.free(bits);
    calloc.free(bitmapInfo);
  }
}
