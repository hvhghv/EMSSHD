import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:image/image.dart' as img;
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:xterm/xterm.dart';
import 'package:zxing2/qrcode.dart' as zxing;

import 'src/emtask_connection.dart';
import 'src/models.dart';
import 'src/panel_client.dart';
import 'src/panel_key_manager.dart';
import 'src/profile_store.dart';
import 'src/updater/updater.dart';
import 'src/windows_screen_capture.dart';

const _appDisplayName = 'emtask Client';
const _appVersion = '1.0.0+1';

Map<ShortcutActivator, Intent> _terminalShortcutsForPlatform(
  TargetPlatform platform,
) {
  switch (platform) {
    case TargetPlatform.iOS:
    case TargetPlatform.macOS:
      return <ShortcutActivator, Intent>{
        const SingleActivator(LogicalKeyboardKey.keyC, meta: true, shift: true):
            CopySelectionTextIntent.copy,
        const SingleActivator(LogicalKeyboardKey.keyV, meta: true, shift: true):
            const PasteTextIntent(SelectionChangedCause.keyboard),
      };
    case TargetPlatform.android:
    case TargetPlatform.fuchsia:
    case TargetPlatform.linux:
    case TargetPlatform.windows:
      return <ShortcutActivator, Intent>{
        const SingleActivator(LogicalKeyboardKey.keyC,
            control: true, shift: true): CopySelectionTextIntent.copy,
        const SingleActivator(LogicalKeyboardKey.keyV,
            control: true,
            shift: true): const PasteTextIntent(SelectionChangedCause.keyboard),
      };
  }
}

@visibleForTesting
Map<ShortcutActivator, Intent> terminalShortcutsForPlatformForTest(
  TargetPlatform platform,
) =>
    _terminalShortcutsForPlatform(platform);

void main() {
  runZonedGuarded(
    () {
      WidgetsFlutterBinding.ensureInitialized();
      FlutterError.onError = _handleFlutterError;
      ui.PlatformDispatcher.instance.onError = _handlePlatformError;
      runApp(const EmTaskClientApp());
    },
    _handleUnhandledError,
  );
}

void _handleFlutterError(FlutterErrorDetails details) {
  if (_isBenignSshCloseError(details.exception)) {
    debugPrint('忽略 SSH 关闭期异常：${details.exception}');
    return;
  }
  FlutterError.presentError(details);
}

bool _handlePlatformError(Object error, StackTrace stack) {
  _handleUnhandledError(error, stack);
  return _isBenignSshCloseError(error);
}

void _handleUnhandledError(Object error, StackTrace stack) {
  if (_isBenignSshCloseError(error)) {
    debugPrint('忽略 SSH 关闭期异常：$error');
    return;
  }
  debugPrint('未处理异常：$error');
  debugPrintStack(stackTrace: stack);
}

bool _isBenignSshCloseError(Object error) {
  final text = error.toString();
  return text.contains('SSHStateError') && text.contains('Transport is closed');
}

enum _ResponsiveLayout {
  compact,
  medium,
  expanded,
}

_ResponsiveLayout _layoutForWidth(double width) {
  if (width < 700) {
    return _ResponsiveLayout.compact;
  }
  if (width < 1120) {
    return _ResponsiveLayout.medium;
  }
  return _ResponsiveLayout.expanded;
}

extension _ResponsiveLayoutX on _ResponsiveLayout {
  EdgeInsets get pagePadding {
    switch (this) {
      case _ResponsiveLayout.compact:
        return const EdgeInsets.all(8);
      case _ResponsiveLayout.medium:
        return const EdgeInsets.all(12);
      case _ResponsiveLayout.expanded:
        return const EdgeInsets.all(14);
    }
  }

  bool get usesSessionGrid => this != _ResponsiveLayout.compact;
}

class EmTaskClientApp extends StatelessWidget {
  const EmTaskClientApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'emtask Client',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xff22c55e),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xff0f172a),
        cardTheme: CardTheme(
          color: const Color(0xff111827),
          elevation: 0,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(18),
            side: const BorderSide(color: Color(0xff1f2937)),
          ),
        ),
      ),
      home: const EmTaskHomePage(),
    );
  }
}

class EmTaskHomePage extends StatefulWidget {
  const EmTaskHomePage({super.key});

  @override
  State<EmTaskHomePage> createState() => _EmTaskHomePageState();
}

class _EmTaskHomePageState extends State<EmTaskHomePage> {
  final _store = EmTaskProfileStore();
  final _panelClient = const EmTaskPanelClient();
  final _panelKeyManager = const EmTaskPanelKeyManager();

  List<EmTaskConnection> _connections = <EmTaskConnection>[];
  List<EmTaskPanelProfile> _panels = <EmTaskPanelProfile>[];
  EmTaskClientSettings _settings = EmTaskClientSettings.defaults();
  final Set<String> _refreshingPanels = <String>{};
  Timer? _ticker;
  bool _loadingProfiles = true;

  @override
  void initState() {
    super.initState();
    _loadProfiles();
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) {
        setState(() {});
      }
    });
  }

  Future<void> _loadProfiles() async {
    final profiles = await _store.loadProfiles();
    final panels = await _store.loadPanels();
    final settings = await _store.loadSettings();
    if (!mounted) {
      return;
    }
    setState(() {
      _connections = profiles.map(EmTaskConnection.new).toList();
      _panels = panels;
      _settings = settings;
      _loadingProfiles = false;
    });
  }

  Future<void> _saveProfiles() async {
    await _store.saveProfiles(
      _connections.map((connection) => connection.profile).toList(),
    );
  }

  Future<void> _savePanels() async {
    await _store.savePanels(_panels);
  }

  void _applySettings(EmTaskClientSettings settings) {
    if (!mounted) {
      return;
    }
    setState(() => _settings = settings);
    unawaited(_store.saveSettings(settings));
  }

  Future<void> _openSettings() async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (context) => _SettingsPage(
          settings: _settings,
          onChanged: _applySettings,
        ),
      ),
    );
  }

  Future<void> _openUpdater() async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (context) => GitHubUpdatePage(
          config: GitHubUpdatePageConfig(
            initialRepository: 'owner/repo',
            defaultNamePattern: _defaultClientUpdatePattern(),
            appVersion: _appVersion,
          ),
        ),
      ),
    );
  }

  Future<void> _addOrEditProfile({EmTaskConnection? connection}) async {
    final panel =
        connection == null ? null : _panelForProfile(connection.profile);
    final profile = await showDialog<EmTaskSessionProfile>(
      context: context,
      builder: (context) => _ProfileDialog(
        profile: connection?.profile,
        isPanelSession: panel != null,
      ),
    );
    if (profile == null) {
      return;
    }

    if (connection != null && panel != null) {
      final request = _buildPanelUpdateRequest(connection.profile, profile);
      if (request != null) {
        try {
          if (connection.isConnected || connection.isConnecting) {
            await connection.disconnect(keepOutput: true);
          }
          await _panelClient.updateTask(
            panel,
            _panelTaskNameForProfile(connection.profile),
            request,
          );
        } catch (error) {
          if (mounted) {
            _showHomeSnackBar('同步服务端会话失败：${_formatError(error)}');
          }
          return;
        }
      }
    }

    final updatedPanel =
        panel == null ? null : _buildPanelCredentialUpdate(panel, profile);

    setState(() {
      if (updatedPanel != null) {
        _upsertPanel(updatedPanel);
      }
      if (connection == null) {
        _connections.add(EmTaskConnection(profile));
      } else {
        connection.profile = profile;
      }
    });
    if (updatedPanel != null) {
      await _savePanels();
    }
    await _saveProfiles();
    if (panel != null) {
      await _refreshPanel(updatedPanel ?? panel, showSnackBar: false);
    }
  }

  EmTaskPanelProfile? _buildPanelCredentialUpdate(
    EmTaskPanelProfile panel,
    EmTaskSessionProfile profile,
  ) {
    var changed = false;
    var next = panel;
    if (profile.panelTaskSyncCredentials &&
        (panel.username != profile.username ||
            panel.password != profile.password)) {
      next = next.copyWith(
        username: profile.username,
        password: profile.password,
      );
      changed = true;
    }
    if (profile.panelTaskSyncPrivateKey &&
        (panel.privateKeyPath != profile.privateKeyPath ||
            panel.privateKeyPassphrase != profile.privateKeyPassphrase)) {
      next = next.copyWith(
        privateKeyPath: profile.privateKeyPath,
        privateKeyPassphrase: profile.privateKeyPassphrase,
      );
      changed = true;
    }
    return changed ? next : null;
  }

  EmTaskPanelUpdateTaskRequest? _buildPanelUpdateRequest(
    EmTaskSessionProfile previous,
    EmTaskSessionProfile next,
  ) {
    String? listenAddress;
    int? port;
    String? command;
    String? workingDir;
    bool? useSftp;

    if (next.panelTaskSyncHost && next.host != previous.host) {
      listenAddress = next.host;
    }
    if (next.panelTaskSyncPort && next.port != previous.port) {
      port = next.port;
    }
    if (next.panelTaskSyncCommand &&
        next.panelTaskCommand != previous.panelTaskCommand) {
      command = next.panelTaskCommand;
    }
    if (next.panelTaskSyncWorkingDir &&
        next.panelTaskWorkingDir != previous.panelTaskWorkingDir) {
      workingDir = next.panelTaskWorkingDir;
    }
    if (next.panelTaskSyncSftp && next.supportsSftp != previous.supportsSftp) {
      useSftp = next.supportsSftp;
    }

    final request = EmTaskPanelUpdateTaskRequest(
      listenAddress: listenAddress,
      port: port,
      command: command,
      workingDir: workingDir,
      useSftp: useSftp,
    );
    return request.isEmpty ? null : request;
  }

  Future<void> _addPanel() async {
    final panel = await showDialog<EmTaskPanelProfile>(
      context: context,
      builder: (context) => const _PanelDialog(),
    );
    if (panel == null) {
      return;
    }

    var storedPanel = panel;
    setState(() => storedPanel = _upsertPanel(panel));
    await _savePanels();
    await _refreshPanel(storedPanel);
  }

  Future<void> _editPanel(EmTaskPanelProfile panel) async {
    final edited = await showDialog<EmTaskPanelProfile>(
      context: context,
      builder: (context) => _PanelDialog(panel: panel),
    );
    if (edited == null) {
      return;
    }

    final index = _panels.indexWhere((item) => item.id == panel.id);
    if (index < 0) {
      return;
    }
    final previous = _panels[index];
    final updated = edited.copyWith(id: previous.id);
    final panelConnections = _connections
        .where((connection) => _isPanelConnection(connection, previous))
        .toList(growable: false);
    final endpointChanged = previous.host != updated.host ||
        previous.username != updated.username ||
        previous.password != updated.password ||
        previous.privateKeyPath != updated.privateKeyPath ||
        previous.privateKeyPassphrase != updated.privateKeyPassphrase;
    if (endpointChanged) {
      for (final connection in panelConnections) {
        if (connection.isConnected || connection.isConnecting) {
          await connection.disconnect(keepOutput: true);
        }
      }
    }
    if (!mounted) {
      return;
    }

    setState(() {
      _panels[index] = updated;
      for (final connection in panelConnections) {
        connection.profile =
            _applyPanelCredentialDefaults(updated, connection.profile);
      }
    });
    await _savePanels();
    await _saveProfiles();
    await _refreshPanel(updated);
  }

  EmTaskSessionProfile _applyPanelCredentialDefaults(
    EmTaskPanelProfile panel,
    EmTaskSessionProfile profile,
  ) {
    return profile.copyWith(
      username:
          profile.panelTaskSyncCredentials ? panel.username : profile.username,
      password:
          profile.panelTaskSyncCredentials ? panel.password : profile.password,
      privateKeyPath: profile.panelTaskSyncPrivateKey
          ? panel.privateKeyPath
          : profile.privateKeyPath,
      privateKeyPassphrase: profile.panelTaskSyncPrivateKey
          ? panel.privateKeyPassphrase
          : profile.privateKeyPassphrase,
    );
  }

  Future<void> _removePanel(EmTaskPanelProfile panel) async {
    final panelConnections = _panelConnections(panel);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('删除面板'),
        content: Text(
          '确定删除 “${panel.name}” 吗？此面板下的 ${panelConnections.length} 个会话也会一起删除。',
        ),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('删除'),
          ),
        ],
      ),
    );
    if (confirmed != true) {
      return;
    }

    for (final connection in panelConnections) {
      await connection.disconnect(keepOutput: true);
    }
    if (!mounted) {
      return;
    }
    setState(() {
      _panels.removeWhere((item) => item.id == panel.id);
      _refreshingPanels.remove(panel.id);
      _connections.removeWhere(panelConnections.contains);
    });
    for (final connection in panelConnections) {
      connection.dispose();
    }
    await _savePanels();
    await _saveProfiles();
  }

  Future<void> _importPanelFromQrText(String text) async {
    try {
      final imported = parseEmTaskPanelQrText(text);
      var panel = imported.panel;
      setState(() {
        panel = _upsertPanel(panel);
        if (imported.firstSession != null) {
          _upsertPanelProfiles(panel, <EmTaskSessionProfile>[
            _normalizePanelSession(panel, imported.firstSession!),
          ]);
        }
      });
      await _savePanels();
      await _saveProfiles();
      _showHomeSnackBar('已通过二维码添加面板，正在注册本机 SSH 公钥。');
      final registeredPanel = await _registerPanelPublicKey(
        panel,
        showSuccess: false,
      );
      if (registeredPanel != null) {
        panel = registeredPanel;
        _showHomeSnackBar('已注册本机 SSH 公钥，正在获取所有会话。');
      }
      await _refreshPanel(panel);
    } catch (error) {
      _showHomeSnackBar('二维码导入失败：${_formatError(error)}');
    }
  }

  Future<EmTaskPanelProfile?> _registerPanelPublicKey(
    EmTaskPanelProfile panel, {
    bool showSuccess = true,
  }) async {
    try {
      final prepared = await _panelKeyManager.ensurePanelKey(panel);
      final registration = await _panelClient.registerAuthorizedKey(
        prepared.panel,
        publicKey: prepared.publicKeyLine,
      );
      if (!mounted) {
        return null;
      }

      var updatedPanel = prepared.panel;
      final serverUsername = registration.username.trim();
      if (serverUsername.isNotEmpty &&
          serverUsername != updatedPanel.username) {
        updatedPanel = updatedPanel.copyWith(username: serverUsername);
      }

      setState(() {
        updatedPanel = _upsertPanel(updatedPanel);
        for (final connection in _panelConnections(updatedPanel)) {
          final shouldUsePanelKey =
              connection.profile.panelTaskSyncPrivateKey ||
                  connection.profile.privateKeyPath.trim().isEmpty;
          connection.profile = connection.profile.copyWith(
            username: connection.profile.panelTaskSyncCredentials
                ? updatedPanel.username
                : connection.profile.username,
            password: connection.profile.panelTaskSyncCredentials
                ? updatedPanel.password
                : connection.profile.password,
            privateKeyPath: shouldUsePanelKey
                ? updatedPanel.privateKeyPath
                : connection.profile.privateKeyPath,
            privateKeyPassphrase: shouldUsePanelKey
                ? updatedPanel.privateKeyPassphrase
                : connection.profile.privateKeyPassphrase,
            panelTaskSyncPrivateKey:
                shouldUsePanelKey || connection.profile.panelTaskSyncPrivateKey,
          );
        }
      });
      await _savePanels();
      await _saveProfiles();
      if (showSuccess) {
        final verb = registration.alreadyPresent ? '已确认' : '已注册';
        final generated = prepared.generated ? '并已生成本地私钥' : '并复用本地私钥';
        _showHomeSnackBar('$verb本机 SSH 公钥，$generated。');
      }
      return updatedPanel;
    } catch (error) {
      if (mounted) {
        _showHomeSnackBar('注册 SSH 公钥失败：${_formatError(error)}');
      }
      return null;
    }
  }

  Future<bool> _refreshPanel(
    EmTaskPanelProfile panel, {
    bool showSnackBar = true,
  }) async {
    if (_refreshingPanels.contains(panel.id)) {
      return false;
    }
    setState(() => _refreshingPanels.add(panel.id));
    try {
      final sessions = await _panelClient.fetchSessions(panel);
      if (!mounted) {
        return false;
      }
      if (!_panels.any((item) => item.id == panel.id)) {
        return false;
      }
      setState(() => _upsertPanelProfiles(panel, sessions));
      await _saveProfiles();
      if (showSnackBar) {
        _showHomeSnackBar('已从 ${panel.name} 获取 ${sessions.length} 个会话。');
      }
      return true;
    } catch (error) {
      if (mounted && showSnackBar) {
        _showHomeSnackBar('刷新面板失败：${_formatError(error)}');
      }
      return false;
    } finally {
      if (mounted) {
        setState(() => _refreshingPanels.remove(panel.id));
      }
    }
  }

  Future<void> _addPanelTask(
    EmTaskPanelProfile panel, {
    EmTaskSessionProfile? template,
  }) async {
    final request = await showDialog<EmTaskPanelCreateTaskRequest>(
      context: context,
      builder: (context) => _PanelTaskDialog(
        panel: panel,
        template: template,
        existingTaskNames: _panelTaskNames(panel),
      ),
    );
    if (request == null) {
      return;
    }

    if (_panelTaskNameExists(panel, request.name)) {
      _showHomeSnackBar('子任务名称 “${request.name}” 已存在，请换一个名称。');
      return;
    }

    try {
      final session = await _panelClient.createTask(panel, request);
      if (!mounted || !_panels.any((item) => item.id == panel.id)) {
        return;
      }
      setState(() => _upsertPanelProfiles(panel, <EmTaskSessionProfile>[
            _normalizePanelSession(panel, session),
          ]));
      await _saveProfiles();
      await _refreshPanel(panel, showSnackBar: false);
      if (mounted) {
        _showHomeSnackBar('已添加子任务 “${request.name}”。');
      }
    } catch (error) {
      if (mounted) {
        _showHomeSnackBar('添加子任务失败：${_formatError(error)}');
      }
    }
  }

  Set<String> _panelTaskNames(EmTaskPanelProfile panel) {
    return _panelConnections(panel)
        .map((connection) => _panelTaskNameForProfile(connection.profile))
        .where((name) => name.trim().isNotEmpty)
        .map(_normalizeTaskNameKey)
        .toSet();
  }

  bool _panelTaskNameExists(EmTaskPanelProfile panel, String taskName) {
    final key = _normalizeTaskNameKey(taskName);
    return key.isNotEmpty && _panelTaskNames(panel).contains(key);
  }

  static String _normalizeTaskNameKey(String taskName) {
    return taskName.trim().toLowerCase();
  }

  Future<void> _refreshAllPanels() async {
    if (_panels.isEmpty) {
      _showHomeSnackBar('暂无面板可刷新。');
      return;
    }
    if (_refreshingPanels.length == _panels.length) {
      return;
    }

    final panels = _panels.toList(growable: false);
    var refreshed = 0;
    var failed = 0;
    for (final panel in panels) {
      if (!mounted || !_panels.any((item) => item.id == panel.id)) {
        continue;
      }
      final ok = await _refreshPanel(panel, showSnackBar: false);
      if (ok) {
        refreshed += 1;
      } else {
        failed += 1;
      }
    }
    if (mounted) {
      _showHomeSnackBar(
        failed == 0
            ? '已刷新 $refreshed 个面板。'
            : '已刷新 $refreshed 个面板，$failed 个失败或跳过。',
      );
    }
  }

  Future<void> _showQrImportOptions() async {
    final action = await showModalBottomSheet<_QrImportAction>(
      context: context,
      builder: (context) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(12, 8, 12, 12),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: <Widget>[
              ListTile(
                leading: const Icon(Icons.photo_camera_outlined),
                title: const Text('拍照扫描二维码'),
                subtitle: const Text('仅移动端使用摄像头实时识别'),
                enabled: _canUseCameraScanner,
                onTap: _canUseCameraScanner
                    ? () => Navigator.of(context).pop(_QrImportAction.camera)
                    : null,
              ),
              ListTile(
                leading: const Icon(Icons.crop_free_outlined),
                title: const Text('框选屏幕截图识别'),
                subtitle: const Text('使用内置截图选择器，框选屏幕中的二维码区域'),
                onTap: () => Navigator.of(context).pop(_QrImportAction.image),
              ),
              ListTile(
                leading: const Icon(Icons.upload_file_outlined),
                title: const Text('选择二维码文件导入'),
                subtitle: const Text(
                    '支持 emtask_panel_connect.svg 或包含 emtask1 payload 的文本'),
                onTap: () => Navigator.of(context).pop(_QrImportAction.file),
              ),
            ],
          ),
        ),
      ),
    );
    if (action == null) {
      return;
    }
    switch (action) {
      case _QrImportAction.camera:
        await _scanQrWithCamera();
      case _QrImportAction.image:
        await _importQrFromImage();
      case _QrImportAction.file:
        await _importQrFromTextFile();
    }
  }

  Future<void> _scanQrWithCamera() async {
    final payload = await Navigator.of(context).push<String>(
      MaterialPageRoute<String>(builder: (_) => const _QrScannerPage()),
    );
    if (payload != null) {
      await _importPanelFromQrText(payload);
    }
  }

  Future<void> _importQrFromImage() async {
    try {
      final bytes = await _captureScreenRegionImage();
      if (bytes == null || bytes.isEmpty) {
        _showHomeSnackBar('没有获取到框选截图。');
        return;
      }
      final payload = _decodeQrImage(bytes);
      await _importPanelFromQrText(payload);
    } catch (error) {
      _showHomeSnackBar('框选截图识别失败：${_formatError(error)}');
    }
  }

  Future<Uint8List?> _captureScreenRegionImage() async {
    if (!Platform.isWindows) {
      throw StateError('当前仅 Windows 支持直接框选屏幕截图；其他平台请使用二维码文件导入。');
    }

    WindowsWindowSnapshot? windowSnapshot;
    late WindowsScreenCaptureResult screen;
    _ScreenRegionSelection? selection;
    try {
      windowSnapshot = snapshotForegroundWindow();
      hideWindowsWindow(windowSnapshot.windowHandle);
      await Future<void>.delayed(const Duration(milliseconds: 120));
      screen = captureWindowsVirtualScreen();
      if (!mounted) {
        return null;
      }
      showWindowsFullscreenOverlay(windowSnapshot);
      selection = await showDialog<_ScreenRegionSelection>(
        context: context,
        barrierDismissible: false,
        builder: (context) => _ScreenRegionPicker(
          imageBytes: screen.pngBytes,
          imageWidth: screen.width,
          imageHeight: screen.height,
        ),
      );
    } finally {
      if (windowSnapshot != null) {
        restoreWindowsWindow(windowSnapshot);
      }
    }
    if (selection == null) {
      return null;
    }

    final image = img.decodeImage(screen.pngBytes);
    if (image == null) {
      throw StateError('无法读取屏幕截图。');
    }
    final cropped = img.copyCrop(
      image,
      x: selection.x,
      y: selection.y,
      width: selection.width,
      height: selection.height,
    );
    return Uint8List.fromList(img.encodePng(cropped));
  }

  String _decodeQrImage(List<int> bytes) {
    final image = img.decodeImage(Uint8List.fromList(bytes));
    if (image == null) {
      throw StateError('无法读取截图图片。');
    }
    final pixels = Int32List(image.width * image.height);
    var offset = 0;
    for (var y = 0; y < image.height; y += 1) {
      for (var x = 0; x < image.width; x += 1) {
        final pixel = image.getPixel(x, y);
        pixels[offset++] =
            (pixel.r.toInt() << 16) | (pixel.g.toInt() << 8) | pixel.b.toInt();
      }
    }
    final source = zxing.RGBLuminanceSource(image.width, image.height, pixels);
    final bitmap = zxing.BinaryBitmap(zxing.HybridBinarizer(source));
    final result = zxing.QRCodeReader().decode(bitmap);
    final text = result.text;
    if (!text.startsWith('emtask1')) {
      throw StateError('截图中没有 emtask 面板二维码。');
    }
    return text;
  }

  Future<void> _importQrFromTextFile() async {
    final picked = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: <String>['svg', 'txt', 'conf', 'json'],
      allowMultiple: false,
      withData: true,
    );
    final file = picked?.files.single;
    if (file == null) {
      return;
    }
    try {
      final bytes = file.bytes ?? await File(file.path!).readAsBytes();
      await _importPanelFromQrText(utf8.decode(bytes));
    } catch (error) {
      _showHomeSnackBar('二维码文件导入失败：${_formatError(error)}');
    }
  }

  bool get _canUseCameraScanner {
    if (kIsWeb) {
      return false;
    }
    return Platform.isAndroid || Platform.isIOS;
  }

  EmTaskPanelProfile _upsertPanel(EmTaskPanelProfile panel) {
    final index = _panels.indexWhere(
      (item) => item.host == panel.host && item.port == panel.port,
    );
    if (index < 0) {
      _panels.add(panel);
      return panel;
    } else {
      final updated = panel.copyWith(id: _panels[index].id);
      _panels[index] = updated;
      return updated;
    }
  }

  void _upsertPanelProfiles(
    EmTaskPanelProfile panel,
    List<EmTaskSessionProfile> profiles,
  ) {
    final normalized = profiles
        .map((profile) => _normalizePanelSession(panel, profile))
        .toList(growable: false);
    final usedSessionIndexes = <int>{};
    final nextConnections = <EmTaskConnection>[];

    for (final connection in _connections) {
      if (!_isPanelConnection(connection, panel)) {
        nextConnections.add(connection);
        continue;
      }

      var replacementIndex = -1;
      for (var i = 0; i < normalized.length; i += 1) {
        if (!usedSessionIndexes.contains(i) &&
            _isSamePanelEndpoint(connection.profile, normalized[i])) {
          replacementIndex = i;
          break;
        }
      }
      if (replacementIndex >= 0) {
        connection.profile = _mergePanelSessionFromServer(
          panel,
          connection.profile,
          normalized[replacementIndex],
        );
        nextConnections.add(connection);
        usedSessionIndexes.add(replacementIndex);
      } else {
        connection.dispose();
      }
    }

    for (var i = 0; i < normalized.length; i += 1) {
      if (!usedSessionIndexes.contains(i)) {
        nextConnections.add(EmTaskConnection(normalized[i]));
      }
    }
    _connections = nextConnections;
  }

  EmTaskSessionProfile _mergePanelSessionFromServer(
    EmTaskPanelProfile panel,
    EmTaskSessionProfile local,
    EmTaskSessionProfile remote,
  ) {
    final taskName = remote.panelTaskName.trim().isEmpty
        ? local.panelTaskName
        : remote.panelTaskName;
    final displayName = local.name.trim().isEmpty ? remote.name : local.name;
    return local.copyWith(
      id: '${panel.id}-${taskName.replaceAll(RegExp(r'[^A-Za-z0-9_.-]+'), '-')}-${local.panelTaskSyncPort ? remote.port : local.port}',
      name: displayName,
      host: local.panelTaskSyncHost ? remote.host : local.host,
      username:
          local.panelTaskSyncCredentials ? remote.username : local.username,
      password:
          local.panelTaskSyncCredentials ? remote.password : local.password,
      privateKeyPath: local.panelTaskSyncPrivateKey
          ? remote.privateKeyPath
          : local.privateKeyPath,
      privateKeyPassphrase: local.panelTaskSyncPrivateKey
          ? remote.privateKeyPassphrase
          : local.privateKeyPassphrase,
      port: local.panelTaskSyncPort ? remote.port : local.port,
      shellKind:
          local.panelTaskSyncCommand ? remote.shellKind : local.shellKind,
      supportsSftp:
          local.panelTaskSyncSftp ? remote.supportsSftp : local.supportsSftp,
      panelId: panel.id,
      panelTaskName: taskName,
      panelTaskCommand: local.panelTaskSyncCommand
          ? remote.panelTaskCommand
          : local.panelTaskCommand,
      panelTaskWorkingDir: local.panelTaskSyncWorkingDir
          ? remote.panelTaskWorkingDir
          : local.panelTaskWorkingDir,
      panelTaskStatus: remote.panelTaskStatus,
      panelTaskStatusMessage: remote.panelTaskStatusMessage,
      panelTaskFailureLog: remote.panelTaskFailureLog,
      panelTaskListenerOpen: remote.panelTaskListenerOpen,
      panelTaskTerminalRunning: remote.panelTaskTerminalRunning,
      panelTaskTerminalFaulted: remote.panelTaskTerminalFaulted,
      panelTaskLastExitStatus: remote.panelTaskLastExitStatus,
    );
  }

  EmTaskSessionProfile _normalizePanelSession(
    EmTaskPanelProfile panel,
    EmTaskSessionProfile profile,
  ) {
    final metadataTaskName = profile.panelTaskName.trim();
    final taskName = metadataTaskName.isNotEmpty
        ? metadataTaskName
        : profile.name.contains('/')
            ? profile.name.split('/').last.trim()
            : profile.name.trim();
    final safeTask = taskName.replaceAll(RegExp(r'[^A-Za-z0-9_.-]+'), '-');
    return profile.copyWith(
      id: '${panel.id}-$safeTask-${profile.port}',
      name: '${panel.name} / ${taskName.isEmpty ? 'task' : taskName}',
      host: profile.host.trim().isEmpty ? panel.host : profile.host,
      username: panel.username,
      password: panel.password,
      privateKeyPath: panel.privateKeyPath,
      privateKeyPassphrase: panel.privateKeyPassphrase,
      panelId: panel.id,
      panelTaskName: taskName,
      panelTaskCommand: profile.panelTaskCommand,
      panelTaskWorkingDir: profile.panelTaskWorkingDir,
      panelTaskStatus: profile.panelTaskStatus,
      panelTaskStatusMessage: profile.panelTaskStatusMessage,
      panelTaskFailureLog: profile.panelTaskFailureLog,
      panelTaskListenerOpen: profile.panelTaskListenerOpen,
      panelTaskTerminalRunning: profile.panelTaskTerminalRunning,
      panelTaskTerminalFaulted: profile.panelTaskTerminalFaulted,
      panelTaskLastExitStatus: profile.panelTaskLastExitStatus,
    );
  }

  bool _isPanelConnection(
    EmTaskConnection connection,
    EmTaskPanelProfile panel,
  ) {
    final profile = connection.profile;
    return profile.panelId == panel.id ||
        profile.id.startsWith('${panel.id}-') ||
        (profile.host == panel.host &&
            profile.name.startsWith('${panel.name} /'));
  }

  bool _isPanelProfile(EmTaskSessionProfile profile) {
    return _panels.any(
      (panel) =>
          profile.panelId == panel.id ||
          profile.id.startsWith('${panel.id}-') ||
          (profile.host == panel.host &&
              profile.name.startsWith('${panel.name} /')),
    );
  }

  EmTaskPanelProfile? _panelForProfile(EmTaskSessionProfile profile) {
    for (final panel in _panels) {
      if (profile.panelId == panel.id ||
          profile.id.startsWith('${panel.id}-') ||
          (profile.host == panel.host &&
              profile.name.startsWith('${panel.name} /'))) {
        return panel;
      }
    }
    return null;
  }

  String _panelTaskNameForProfile(EmTaskSessionProfile profile) {
    final metadataTaskName = profile.panelTaskName.trim();
    if (metadataTaskName.isNotEmpty) {
      return metadataTaskName;
    }
    if (profile.name.contains('/')) {
      return profile.name.split('/').last.trim();
    }
    return '';
  }

  List<EmTaskConnection> _panelConnections(EmTaskPanelProfile panel) {
    return _connections
        .where((connection) => _isPanelConnection(connection, panel))
        .toList(growable: false);
  }

  EmTaskConnection? _panelConnectionByTask(
    EmTaskPanelProfile panel,
    String taskName,
  ) {
    final key = _normalizeTaskNameKey(taskName);
    if (key.isEmpty) {
      return null;
    }
    for (final connection in _panelConnections(panel)) {
      if (_normalizeTaskNameKey(_panelTaskNameForProfile(connection.profile)) ==
          key) {
        return connection;
      }
    }
    return null;
  }

  bool _isSamePanelEndpoint(
    EmTaskSessionProfile left,
    EmTaskSessionProfile right,
  ) {
    final leftTask = left.panelTaskName.trim();
    final rightTask = right.panelTaskName.trim();
    if (leftTask.isNotEmpty && rightTask.isNotEmpty && leftTask == rightTask) {
      return true;
    }
    return left.host == right.host &&
        left.port == right.port &&
        left.username == right.username;
  }

  Future<void> _removeProfile(EmTaskConnection connection) async {
    final panel = _panelForProfile(connection.profile);
    final panelTaskName = _panelTaskNameForProfile(connection.profile);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('删除会话'),
        content: Text(
          panel == null
              ? '确定删除 “${connection.profile.name}” 吗？'
              : '确定删除 “${connection.profile.name}” 吗？这会同步删除服务端动态子任务。',
        ),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('删除'),
          ),
        ],
      ),
    );
    if (confirmed != true) {
      return;
    }

    await connection.disconnect(keepOutput: true);
    if (!mounted) {
      return;
    }

    if (panel != null) {
      if (panelTaskName.isEmpty) {
        _showHomeSnackBar('无法确定面板子任务名称，请先刷新面板后再删除。');
        return;
      }
      try {
        await _panelClient.deleteTask(panel, panelTaskName);
      } catch (error) {
        if (mounted) {
          _showHomeSnackBar('删除服务端子任务失败：${_formatError(error)}');
        }
        return;
      }
    }

    setState(() => _connections.remove(connection));
    connection.dispose();
    await _saveProfiles();
    if (panel != null) {
      await _refreshPanel(panel, showSnackBar: false);
      if (mounted) {
        _showHomeSnackBar('已删除服务端子任务 “$panelTaskName”。');
      }
    }
  }

  Future<void> _showPanelTaskStatus(EmTaskConnection connection) async {
    final panel = _panelForProfile(connection.profile);
    final taskName = _panelTaskNameForProfile(connection.profile);
    if (panel == null || taskName.isEmpty) {
      _showHomeSnackBar('无法确定面板子任务，请先刷新面板。');
      return;
    }

    var profile = connection.profile;
    try {
      final sessions = await _panelClient.fetchSessions(panel);
      if (!mounted || !_panels.any((item) => item.id == panel.id)) {
        return;
      }
      setState(() => _upsertPanelProfiles(panel, sessions));
      await _saveProfiles();
      profile = _panelConnectionByTask(panel, taskName)?.profile ?? profile;
    } catch (error) {
      if (mounted) {
        _showHomeSnackBar('刷新子任务状态失败，将显示本地缓存：${_formatError(error)}');
      }
    }

    if (!mounted) {
      return;
    }
    await showDialog<void>(
      context: context,
      builder: (context) => _PanelTaskStatusDialog(profile: profile),
    );
  }

  Future<void> _rerunPanelTask(EmTaskConnection connection) async {
    final panel = _panelForProfile(connection.profile);
    final taskName = _panelTaskNameForProfile(connection.profile);
    if (panel == null || taskName.isEmpty) {
      _showHomeSnackBar('无法确定面板子任务，请先刷新面板。');
      return;
    }

    try {
      final session = await _panelClient.rerunTask(panel, taskName);
      if (!mounted || !_panels.any((item) => item.id == panel.id)) {
        return;
      }
      setState(() => _upsertPanelProfiles(panel, <EmTaskSessionProfile>[
            _normalizePanelSession(panel, session),
          ]));
      await _saveProfiles();
      await _refreshPanel(panel, showSnackBar: false);
      if (!mounted) {
        return;
      }
      if (session.panelTaskStatus == 'failed' ||
          session.panelTaskTerminalFaulted) {
        final detail = session.panelTaskFailureLog.trim().isEmpty
            ? session.panelTaskStatusMessage
            : session.panelTaskFailureLog;
        _showHomeSnackBar('已请求重新运行，但子任务仍失败：${_formatError(detail)}');
      } else {
        _showHomeSnackBar('已重新运行子任务 “$taskName”。');
      }
    } catch (error) {
      if (mounted) {
        _showHomeSnackBar('重新运行子任务失败：${_formatError(error)}');
      }
    }
  }

  Future<void> _toggleConnection(EmTaskConnection connection) async {
    if (connection.isConnected || connection.isConnecting) {
      await connection.disconnect(keepOutput: true);
    } else {
      await connection.connect();
      if (!mounted) {
        return;
      }
      if (connection.isConnected) {
        _showHomeSnackBar('已连接 ${connection.profile.name}，现在可以点击会话进入终端。');
      } else {
        _showHomeSnackBar(
          connection.errorMessage == null
              ? '连接失败，请检查 IP、端口和账号。'
              : '连接失败：${_formatError(connection.errorMessage!)}',
        );
      }
    }
    if (mounted) {
      setState(() {});
    }
  }

  Future<void> _openSession(EmTaskConnection connection) async {
    if (!connection.isConnected) {
      _showHomeSnackBar(
        connection.isConnecting
            ? '正在连接 ${connection.profile.name}，请等待连接成功后再进入终端。'
            : '请先点击会话项里的“连接”，连接成功后再进入终端。',
      );
      return;
    }

    connection.setActive(true);
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (context) => EmTaskSessionPage(
          connection: connection,
          shortcutKeysEnabled: _settings.shortcutKeysEnabled,
          terminalKeyboardButtonOnly: _settings.terminalKeyboardButtonOnly,
          sftpSmallFileBytes: _settings.sftpSmallFileBytes,
          sftpPreviewHeight: _settings.sftpPreviewHeight,
          onProfilePathChanged: (path) => _saveEditedPath(connection, path),
        ),
      ),
    );
    if (mounted) {
      connection.setActive(false);
      setState(() {});
    }
  }

  void _showHomeSnackBar(String message) {
    if (!mounted) {
      return;
    }
    final messenger = ScaffoldMessenger.of(context);
    messenger.hideCurrentSnackBar();
    messenger.showSnackBar(
      SnackBar(
        duration: const Duration(seconds: 4),
        content: Text(message),
        action: SnackBarAction(
          label: '关闭',
          onPressed: () {
            ScaffoldMessenger.of(context).hideCurrentSnackBar();
          },
        ),
      ),
    );
  }

  Future<void> _saveEditedPath(
    EmTaskConnection connection,
    String path,
  ) async {
    connection.profile = connection.profile.copyWith(initialPath: path);
    await _saveProfiles();
    if (mounted) {
      setState(() {});
    }
  }

  @override
  void dispose() {
    _ticker?.cancel();
    for (final connection in _connections) {
      connection.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_loadingProfiles) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
    }

    final layout = _layoutForWidth(MediaQuery.sizeOf(context).width);
    return Scaffold(
      appBar: AppBar(
        title: const Text('emtask Client'),
        backgroundColor: const Color(0xff111827),
        actions: <Widget>[
          IconButton(
            tooltip: '新增会话',
            onPressed: () => _addOrEditProfile(),
            icon: const Icon(Icons.add_circle_outline),
          ),
          PopupMenuButton<_HomeMenuAction>(
            tooltip: '更多操作',
            onSelected: (action) async {
              switch (action) {
                case _HomeMenuAction.refreshPanels:
                  await _refreshAllPanels();
                case _HomeMenuAction.addPanel:
                  await _addPanel();
                case _HomeMenuAction.importPanelQr:
                  await _showQrImportOptions();
                case _HomeMenuAction.updater:
                  await _openUpdater();
                case _HomeMenuAction.settings:
                  await _openSettings();
              }
            },
            itemBuilder: (context) => <PopupMenuEntry<_HomeMenuAction>>[
              PopupMenuItem<_HomeMenuAction>(
                value: _HomeMenuAction.refreshPanels,
                enabled: _panels.isNotEmpty && _refreshingPanels.isEmpty,
                child: const ListTile(
                  leading: Icon(Icons.sync_outlined),
                  title: Text('刷新所有面板'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
              const PopupMenuItem<_HomeMenuAction>(
                value: _HomeMenuAction.addPanel,
                child: ListTile(
                  leading: Icon(Icons.dashboard_outlined),
                  title: Text('添加面板'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
              const PopupMenuItem<_HomeMenuAction>(
                value: _HomeMenuAction.importPanelQr,
                child: ListTile(
                  leading: Icon(Icons.qr_code_scanner),
                  title: Text('二维码添加面板'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
              const PopupMenuDivider(),
              const PopupMenuItem<_HomeMenuAction>(
                value: _HomeMenuAction.updater,
                child: ListTile(
                  leading: Icon(Icons.system_update_alt_outlined),
                  title: Text('检查更新'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
              const PopupMenuItem<_HomeMenuAction>(
                value: _HomeMenuAction.settings,
                child: ListTile(
                  leading: Icon(Icons.settings_outlined),
                  title: Text('设置'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
            ],
          ),
        ],
      ),
      body: SafeArea(
        child: Padding(
          padding: layout.pagePadding,
          child: _connections.isEmpty && _panels.isEmpty
              ? _EmptyState(onCreate: () => _addOrEditProfile())
              : _buildSessionGroups(layout),
        ),
      ),
    );
  }

  Widget _buildSessionGroups(_ResponsiveLayout layout) {
    final manualConnections = _connections
        .where((connection) => !_isPanelProfile(connection.profile))
        .toList(growable: false);
    return ListView(
      children: <Widget>[
        _buildSessionGroupCard(
          layout: layout,
          title: '会话',
          subtitle: '手动新建的会话统一放在这里',
          icon: Icons.hub_outlined,
          connections: manualConnections,
          emptyMessage: '暂无手动会话，点击右上角 + 新增。',
        ),
        for (final panel in _panels) ...<Widget>[
          const SizedBox(height: 10),
          _buildSessionGroupCard(
            layout: layout,
            title: panel.name,
            subtitle: '${panel.host}:${panel.port} · ${panel.authMode.label}',
            icon: Icons.dashboard_outlined,
            connections: _panelConnections(panel),
            emptyMessage: '此面板暂无会话，点击刷新重新获取。',
            trailing: _PanelActions(
              refreshing: _refreshingPanels.contains(panel.id),
              onRefresh: () => _refreshPanel(panel),
              onAddTask: () => _addPanelTask(panel),
              onRegisterKey: () => _registerPanelPublicKey(panel),
              onEdit: () => _editPanel(panel),
              onDelete: () => _removePanel(panel),
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildSessionGroupCard({
    required _ResponsiveLayout layout,
    required String title,
    required String subtitle,
    required IconData icon,
    required List<EmTaskConnection> connections,
    required String emptyMessage,
    Widget? trailing,
  }) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Row(
              children: <Widget>[
                Icon(icon, size: 20),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text(
                        title,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      Text(
                        subtitle,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: Theme.of(context).textTheme.labelSmall,
                      ),
                    ],
                  ),
                ),
                Text(
                  '${connections.length}',
                  style: Theme.of(context).textTheme.labelLarge,
                ),
                if (trailing != null) ...<Widget>[
                  const SizedBox(width: 6),
                  trailing,
                ],
              ],
            ),
            const SizedBox(height: 12),
            if (connections.isEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 14),
                child: Text(emptyMessage),
              )
            else if (layout.usesSessionGrid)
              GridView.builder(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                gridDelegate: const SliverGridDelegateWithMaxCrossAxisExtent(
                  maxCrossAxisExtent: 420,
                  mainAxisExtent: 132,
                  mainAxisSpacing: 10,
                  crossAxisSpacing: 10,
                ),
                itemCount: connections.length,
                itemBuilder: (context, index) =>
                    _buildSessionTile(connections[index]),
              )
            else
              ListView.separated(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                itemCount: connections.length,
                separatorBuilder: (_, __) => const SizedBox(height: 8),
                itemBuilder: (context, index) =>
                    _buildSessionTile(connections[index]),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildSessionTile(EmTaskConnection connection) {
    return AnimatedBuilder(
      animation: connection,
      builder: (context, _) {
        final panel = _panelForProfile(connection.profile);
        return _SessionTile(
          connection: connection,
          onOpen: () => _openSession(connection),
          onToggle: () => _toggleConnection(connection),
          onEdit: () => _addOrEditProfile(connection: connection),
          onShowPanelTaskStatus:
              panel == null ? null : () => _showPanelTaskStatus(connection),
          onRerunPanelTask:
              panel == null ? null : () => _rerunPanelTask(connection),
          onCreatePanelTaskFromTemplate: panel == null
              ? null
              : () => _addPanelTask(panel, template: connection.profile),
          onDelete: () => _removeProfile(connection),
        );
      },
    );
  }
}

class EmTaskSessionPage extends StatefulWidget {
  const EmTaskSessionPage({
    super.key,
    required this.connection,
    required this.shortcutKeysEnabled,
    required this.terminalKeyboardButtonOnly,
    required this.sftpSmallFileBytes,
    required this.sftpPreviewHeight,
    required this.onProfilePathChanged,
  });

  final EmTaskConnection connection;
  final bool shortcutKeysEnabled;
  final bool terminalKeyboardButtonOnly;
  final int sftpSmallFileBytes;
  final int sftpPreviewHeight;
  final Future<void> Function(String path) onProfilePathChanged;

  @override
  State<EmTaskSessionPage> createState() => _EmTaskSessionPageState();
}

class _EmTaskSessionPageState extends State<EmTaskSessionPage> {
  late final Terminal _terminal;
  late final TerminalController _terminalController;
  final _terminalFocusNode = FocusNode();
  final _sftpPathController = TextEditingController();
  final _sftpListScrollController = ScrollController();
  final _sftpPreviewScrollController = ScrollController();
  final _sftpEditorController = TextEditingController();
  final _sftpOffsetController = TextEditingController(text: '0');
  StreamSubscription<String>? _terminalOutputSubscription;

  bool _showSftp = false;
  bool _sftpBusy = false;
  String? _sftpError;
  String? _loadedDirectoryPath;
  String? _openedFilePath;
  EmTaskSftpFileContent? _openedFileContent;
  String? _openedFileText;
  String? _openedFileOriginalText;
  bool _openedFileEditable = false;
  bool _openedFileDirty = false;
  bool _openedFileEditingBinary = false;
  List<EmTaskSftpEntry> _sftpEntries = const <EmTaskSftpEntry>[];
  final _sftpEditCache = <String, _SftpEditCache>{};
  int _lastOutputLength = 0;
  bool _shortcutCtrl = false;
  bool _shortcutShift = false;
  bool _shortcutAlt = false;
  bool _terminalKeyboardUnlocked = true;
  bool _applyingSftpEditorText = false;

  @override
  void initState() {
    super.initState();
    _terminal = Terminal(
      maxLines: 5000,
      onOutput: (data) {
        try {
          widget.connection.writeText(_applyTerminalInputModifiers(data));
        } catch (error) {
          _terminal.write('\r\n$error\r\n');
        }
      },
      onResize: (columns, rows, pixelWidth, pixelHeight) {
        widget.connection.resizeTerminal(
          columns,
          rows,
          pixelWidth,
          pixelHeight,
        );
      },
    );
    _terminalController = TerminalController();
    widget.connection.setActive(true);
    _sftpPathController.text =
        _safeInitialSftpPath(widget.connection.profile.initialPath);
    _lastOutputLength = widget.connection.output.length;
    if (widget.connection.output.isNotEmpty) {
      _terminal.write(widget.connection.output.replaceAll('\n', '\r\n'));
    }
    _terminalOutputSubscription = widget.connection.terminalOutput.listen(
      _terminal.write,
    );
    widget.connection.addListener(_handleConnectionChanged);
    _sftpEditorController.addListener(_handleSftpEditorChanged);
    _terminalKeyboardUnlocked = !widget.terminalKeyboardButtonOnly;
  }

  @override
  void didUpdateWidget(covariant EmTaskSessionPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.terminalKeyboardButtonOnly !=
        widget.terminalKeyboardButtonOnly) {
      _terminalKeyboardUnlocked = !widget.terminalKeyboardButtonOnly;
      if (widget.terminalKeyboardButtonOnly) {
        _terminalFocusNode.unfocus();
      }
    }
  }

  void _handleConnectionChanged() {
    final currentLength = widget.connection.output.length;
    if (!_showSftp && currentLength != _lastOutputLength) {
      _lastOutputLength = currentLength;
    }
  }

  void _handleSftpEditorChanged() {
    if (_applyingSftpEditorText) {
      return;
    }
    final path = _openedFilePath;
    final originalText = _openedFileOriginalText;
    if (path == null || !_openedFileEditable || originalText == null) {
      return;
    }
    final editorText = _sftpEditorController.text;
    final dirty = editorText != originalText;
    if (dirty) {
      _sftpEditCache[path] = _SftpEditCache(
        originalText: originalText,
        editedText: editorText,
        editingBinary: _openedFileEditingBinary,
      );
    } else {
      _sftpEditCache.remove(path);
    }
    if (dirty != _openedFileDirty && mounted) {
      setState(() => _openedFileDirty = dirty);
    }
  }

  void _clearOpenedSftpFile() {
    _openedFilePath = null;
    _openedFileContent = null;
    _openedFileText = null;
    _openedFileOriginalText = null;
    _openedFileEditable = false;
    _openedFileDirty = false;
    _openedFileEditingBinary = false;
    _setSftpEditorText('');
    _sftpOffsetController.text = '0';
  }

  void _setSftpEditorText(String text) {
    _applyingSftpEditorText = true;
    _sftpEditorController.value = TextEditingValue(
      text: text,
      selection: TextSelection.collapsed(offset: text.length),
    );
    _applyingSftpEditorText = false;
  }

  @override
  void dispose() {
    widget.connection.removeListener(_handleConnectionChanged);
    widget.connection.setActive(false);
    _sftpEditorController.removeListener(_handleSftpEditorChanged);
    unawaited(_terminalOutputSubscription?.cancel());
    _terminalFocusNode.dispose();
    _sftpPathController.dispose();
    _sftpListScrollController.dispose();
    _sftpPreviewScrollController.dispose();
    _sftpEditorController.dispose();
    _sftpOffsetController.dispose();
    super.dispose();
  }

  Future<void> _toggleViewMode() async {
    if (!_showSftp && !widget.connection.profile.supportsSftp) {
      _showSnackBar('此会话配置未开启 SFTP。请先在会话配置里勾选“支持 SFTP”。');
      return;
    }
    setState(() => _showSftp = !_showSftp);
    if (_showSftp && widget.connection.isConnected) {
      final path = _sftpPathController.text.trim().isEmpty
          ? '.'
          : _sftpPathController.text.trim();
      if (_loadedDirectoryPath != path) {
        await _loadDirectory(path: path);
      }
    }
  }

  Future<void> _loadDirectory({String? path}) async {
    final connection = widget.connection;
    final rawPath = path ?? _sftpPathController.text;
    late final String targetPath;
    try {
      targetPath = EmTaskConnection.normalizeSftpVirtualPath(rawPath);
    } catch (error) {
      setState(() {
        _sftpError = _formatError(error);
        _sftpPathController.text = '.';
        _clearOpenedSftpFile();
      });
      return;
    }
    if (!connection.isConnected) {
      setState(() => _sftpError = '请先连接会话，然后再使用 SFTP。');
      return;
    }

    setState(() {
      _sftpBusy = true;
      _sftpError = null;
      _clearOpenedSftpFile();
    });

    try {
      final entries = await connection.listSftpDirectory(targetPath);
      if (!mounted) {
        return;
      }
      _sftpPathController.text = targetPath;
      setState(() {
        _sftpEntries = entries;
        _loadedDirectoryPath = targetPath;
      });
      await widget.onProfilePathChanged(targetPath);
      _scrollSftpListToTop();
    } catch (error) {
      if (mounted) {
        setState(() => _sftpError = _formatError(error));
      }
    } finally {
      if (mounted) {
        setState(() => _sftpBusy = false);
      }
    }
  }

  Future<void> _openFile(EmTaskSftpEntry entry) async {
    await _loadFilePage(
      entry.path,
      offset: 0,
      preferredLength: _initialSftpReadLength(entry),
    );
  }

  Future<void> _loadFilePage(
    String path, {
    required int offset,
    int? preferredLength,
  }) async {
    if (!widget.connection.isConnected) {
      setState(() => _sftpError = '请先连接会话，然后再读取文件。');
      return;
    }
    setState(() {
      _sftpBusy = true;
      _sftpError = null;
      _openedFilePath = path;
      _openedFileContent = null;
      _openedFileText = null;
      _openedFileOriginalText = null;
      _openedFileEditable = false;
      _openedFileDirty = false;
      _openedFileEditingBinary = false;
    });
    _setSftpEditorText('');

    try {
      final content = await widget.connection.readSftpFileContent(
        path,
        offset: offset,
        length: preferredLength ?? EmTaskConnection.sftpPageBytes,
      );
      if (!mounted) {
        return;
      }
      _applyOpenedFileContent(path, content, useCache: offset == 0);
      _scrollSftpPreviewToTop();
    } catch (error) {
      if (mounted) {
        setState(() => _sftpError = _formatError(error));
      }
    } finally {
      if (mounted) {
        setState(() => _sftpBusy = false);
      }
    }
  }

  void _applyOpenedFileContent(
    String path,
    EmTaskSftpFileContent content, {
    required bool useCache,
  }) {
    final cached = useCache ? _sftpEditCache[path] : null;
    final canUseCache = content.isEditable &&
        cached != null &&
        cached.editingBinary == content.isBinaryEditable;
    final editorText = canUseCache
        ? cached.editedText
        : content.isEditable
            ? content.editorText
            : '';
    final originalText = canUseCache
        ? cached.originalText
        : content.isEditable
            ? content.editorText
            : null;
    final dirty = originalText != null && editorText != originalText;

    setState(() {
      _openedFilePath = path;
      _openedFileContent = content;
      _openedFileText = content.displayText;
      _openedFileOriginalText = originalText;
      _openedFileEditable = content.isEditable;
      _openedFileDirty = dirty;
      _openedFileEditingBinary = content.isBinaryEditable;
    });
    _sftpOffsetController.text = content.offset.toString();
    _setSftpEditorText(editorText);
  }

  Future<void> _loadOpenedFileOffset() async {
    final path = _openedFilePath;
    if (path == null) {
      return;
    }
    final raw = _sftpOffsetController.text.trim();
    final offset = int.tryParse(raw);
    if (offset == null || offset < 0) {
      setState(() => _sftpError = '偏移必须是大于等于 0 的整数。');
      return;
    }
    await _loadFilePage(path, offset: offset);
  }

  Future<void> _loadPreviousFilePage() async {
    final path = _openedFilePath;
    final content = _openedFileContent;
    if (path == null || content == null || !content.canGoPrevious) {
      return;
    }
    await _loadFilePage(path, offset: content.previousOffset);
  }

  Future<void> _loadNextFilePage() async {
    final path = _openedFilePath;
    final content = _openedFileContent;
    if (path == null || content == null || !content.canGoNext) {
      return;
    }
    await _loadFilePage(path, offset: content.nextOffset);
  }

  int _initialSftpReadLength(EmTaskSftpEntry entry) {
    final size = entry.size;
    final smallFileBytes = EmTaskClientSettings.clampSftpSmallFileBytes(
      widget.sftpSmallFileBytes,
    );
    if (size != null && size >= 0 && size <= smallFileBytes) {
      return size == 0 ? 1 : size;
    }
    return EmTaskConnection.sftpPageBytes;
  }

  Future<void> _saveOpenedFile() async {
    final path = _openedFilePath;
    if (path == null || !_openedFileEditable) {
      return;
    }
    if (!widget.connection.isConnected) {
      setState(() => _sftpError = '请先连接会话，然后再保存文件。');
      return;
    }

    final nextText = _sftpEditorController.text;
    setState(() {
      _sftpBusy = true;
      _sftpError = null;
    });

    try {
      final nextBytes = _openedFileEditingBinary
          ? EmTaskSftpFileContent.parseHexBytes(nextText)
          : Uint8List.fromList(utf8.encode(nextText));
      if (_openedFileEditingBinary) {
        await widget.connection.writeSftpFileBytes(path, nextBytes);
      } else {
        await widget.connection.writeSftpFile(path, nextText);
      }
      List<EmTaskSftpEntry>? refreshedEntries;
      final currentDirectory = _loadedDirectoryPath;
      if (currentDirectory != null) {
        refreshedEntries =
            await widget.connection.listSftpDirectory(currentDirectory);
      }
      if (!mounted) {
        return;
      }
      final nextContent = EmTaskSftpFileContent(
        text: _openedFileEditingBinary ? '' : nextText,
        bytes: nextBytes,
        size: nextBytes.length,
        offset: 0,
        length: nextBytes.length,
        isTruncated: false,
        isUtf8Text: !_openedFileEditingBinary,
        pageBytes: EmTaskConnection.sftpPageBytes,
      );
      final nextEditorText = nextContent.editorText;
      _sftpEditCache.remove(path);
      setState(() {
        _openedFileText = nextContent.displayText;
        _openedFileOriginalText = nextEditorText;
        _openedFileContent = nextContent;
        _openedFileDirty = false;
        if (refreshedEntries != null) {
          _sftpEntries = refreshedEntries;
        }
      });
      _setSftpEditorText(nextEditorText);
      _showSnackBar('已保存 $path');
    } on FormatException catch (error) {
      if (mounted) {
        setState(() => _sftpError = 'HEX 内容格式错误：${error.message}');
      }
    } catch (error) {
      if (mounted) {
        setState(() => _sftpError = _formatError(error));
      }
    } finally {
      if (mounted) {
        setState(() => _sftpBusy = false);
      }
    }
  }

  Future<void> _openParentDirectory() async {
    await _loadDirectory(path: _parentSftpPath(_sftpPathController.text));
  }

  Future<void> _refreshSftpDirectory() async {
    final connection = widget.connection;
    if (!connection.isConnected) {
      setState(() => _sftpError = '请先连接会话，然后再刷新 SFTP。');
      return;
    }

    if (_sftpEditCache.isNotEmpty) {
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('刷新会丢弃未保存编辑'),
          content: Text(
            '当前有 ${_sftpEditCache.length} 个文件存在未保存的编辑缓存。刷新会清空这些缓存，并重新读取服务端目录和文件。是否继续？',
          ),
          actions: <Widget>[
            TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: const Text('取消'),
            ),
            FilledButton.icon(
              onPressed: () => Navigator.of(context).pop(true),
              icon: const Icon(Icons.refresh),
              label: const Text('刷新'),
            ),
          ],
        ),
      );
      if (confirmed != true) {
        return;
      }
    }

    final rawPath = _loadedDirectoryPath ?? _sftpPathController.text;
    late final String targetPath;
    try {
      targetPath = EmTaskConnection.normalizeSftpVirtualPath(rawPath);
    } catch (error) {
      setState(() => _sftpError = _formatError(error));
      return;
    }

    final previouslyOpenedPath = _openedFilePath;
    final previousOffset = _openedFileContent?.offset ?? 0;
    _sftpEditCache.clear();
    setState(() {
      _sftpBusy = true;
      _sftpError = null;
    });

    try {
      final entries = await connection.listSftpDirectory(targetPath);
      EmTaskSftpEntry? reopenedEntry;
      if (previouslyOpenedPath != null) {
        for (final entry in entries) {
          if (!entry.isDirectory && entry.path == previouslyOpenedPath) {
            reopenedEntry = entry;
            break;
          }
        }
      }

      EmTaskSftpFileContent? reopenedContent;
      if (reopenedEntry != null) {
        reopenedContent = await connection.readSftpFileContent(
          reopenedEntry.path,
          offset: previousOffset,
          length: previousOffset == 0
              ? _initialSftpReadLength(reopenedEntry)
              : EmTaskConnection.sftpPageBytes,
        );
      }

      if (!mounted) {
        return;
      }
      _sftpPathController.text = targetPath;
      setState(() {
        _sftpEntries = entries;
        _loadedDirectoryPath = targetPath;
      });
      if (reopenedEntry != null && reopenedContent != null) {
        _applyOpenedFileContent(
          reopenedEntry.path,
          reopenedContent,
          useCache: false,
        );
        _scrollSftpListToEntry(reopenedEntry.path);
        _scrollSftpPreviewToTop();
      } else {
        setState(_clearOpenedSftpFile);
        _scrollSftpListToTop();
      }
      await widget.onProfilePathChanged(targetPath);
    } catch (error) {
      if (mounted) {
        setState(() => _sftpError = _formatError(error));
      }
    } finally {
      if (mounted) {
        setState(() => _sftpBusy = false);
      }
    }
  }

  Future<void> _createSftpFile() async {
    await _createSftpEntry(isDirectory: false);
  }

  Future<void> _createSftpDirectory() async {
    await _createSftpEntry(isDirectory: true);
  }

  Future<void> _createSftpEntry({required bool isDirectory}) async {
    if (!widget.connection.isConnected) {
      setState(() => _sftpError = '请先连接会话，然后再新建。');
      return;
    }
    final name = await _showSftpNameDialog(
      title: isDirectory ? '新建文件夹' : '新建文件',
      labelText: isDirectory ? '文件夹名称' : '文件名称',
      confirmText: '新建',
    );
    if (name == null) {
      return;
    }

    late final String currentDirectory;
    try {
      currentDirectory = EmTaskConnection.normalizeSftpVirtualPath(
        _loadedDirectoryPath ?? _sftpPathController.text,
      );
    } catch (error) {
      setState(() => _sftpError = _formatError(error));
      return;
    }
    final targetPath = _joinSftpChildPath(currentDirectory, name);
    setState(() {
      _sftpBusy = true;
      _sftpError = null;
    });

    try {
      if (isDirectory) {
        await widget.connection.createSftpDirectory(targetPath);
      } else {
        await widget.connection.createSftpFile(targetPath);
      }
      final entries = await widget.connection.listSftpDirectory(
        currentDirectory,
      );
      if (!mounted) {
        return;
      }
      setState(() {
        _sftpEntries = entries;
        _loadedDirectoryPath = currentDirectory;
        _sftpPathController.text = currentDirectory;
      });
      if (isDirectory) {
        _scrollSftpListToEntry(targetPath);
      } else {
        await _loadFilePage(targetPath, offset: 0, preferredLength: 1);
        _scrollSftpListToEntry(targetPath);
      }
      _showSnackBar('已新建${isDirectory ? '文件夹' : '文件'} $targetPath');
    } catch (error) {
      if (mounted) {
        setState(() => _sftpError = _formatError(error));
      }
    } finally {
      if (mounted) {
        setState(() => _sftpBusy = false);
      }
    }
  }

  Future<void> _deleteSftpEntry(EmTaskSftpEntry entry) async {
    if (!widget.connection.isConnected) {
      setState(() => _sftpError = '请先连接会话，然后再删除。');
      return;
    }
    final cachedCount = entry.isDirectory
        ? _sftpCachedPathCountUnder(entry.path)
        : (_sftpEditCache.containsKey(entry.path) ? 1 : 0);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('删除${entry.isDirectory ? '文件夹' : '文件'}'),
        content: Text(
          '确定删除 “${entry.path}” 吗？${entry.isDirectory ? '\n文件夹必须为空才能删除。' : ''}${cachedCount > 0 ? '\n相关未保存编辑缓存也会被删除。' : ''}',
        ),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('取消'),
          ),
          FilledButton.icon(
            onPressed: () => Navigator.of(context).pop(true),
            icon: const Icon(Icons.delete_outline),
            label: const Text('删除'),
          ),
        ],
      ),
    );
    if (confirmed != true) {
      return;
    }

    setState(() {
      _sftpBusy = true;
      _sftpError = null;
    });

    try {
      await widget.connection.deleteSftpPath(
        entry.path,
        isDirectory: entry.isDirectory,
      );
      if (entry.isDirectory) {
        _removeSftpCachesUnder(entry.path);
      } else {
        _sftpEditCache.remove(entry.path);
      }
      final currentDirectory = EmTaskConnection.normalizeSftpVirtualPath(
        _loadedDirectoryPath ?? _sftpPathController.text,
      );
      final entries = await widget.connection.listSftpDirectory(
        currentDirectory,
      );
      if (!mounted) {
        return;
      }
      setState(() {
        _sftpEntries = entries;
        if (_openedFilePath == entry.path ||
            (entry.isDirectory &&
                _openedFilePath != null &&
                _isSftpPathUnder(_openedFilePath!, entry.path))) {
          _clearOpenedSftpFile();
        }
      });
      _showSnackBar('已删除 ${entry.path}');
    } catch (error) {
      if (mounted) {
        setState(() => _sftpError = _formatError(error));
      }
    } finally {
      if (mounted) {
        setState(() => _sftpBusy = false);
      }
    }
  }

  Future<void> _renameSftpEntry(EmTaskSftpEntry entry) async {
    if (!widget.connection.isConnected) {
      setState(() => _sftpError = '请先连接会话，然后再重命名。');
      return;
    }

    final nextName = await _showSftpNameDialog(
      title: '重命名${entry.isDirectory ? '文件夹' : '文件'}',
      labelText: entry.isDirectory ? '新的文件夹名称' : '新的文件名称',
      confirmText: '重命名',
      initialText: entry.name,
    );
    if (nextName == null || nextName == entry.name) {
      return;
    }

    final duplicate = _sftpEntries.any(
      (candidate) => candidate.path != entry.path && candidate.name == nextName,
    );
    if (duplicate) {
      setState(() => _sftpError = '当前目录已存在名为 “$nextName” 的条目。');
      return;
    }

    final newPath = _joinSftpChildPath(_parentSftpPath(entry.path), nextName);
    setState(() {
      _sftpBusy = true;
      _sftpError = null;
    });

    try {
      await widget.connection.renameSftpPath(entry.path, newPath);
      final currentDirectory = EmTaskConnection.normalizeSftpVirtualPath(
        _loadedDirectoryPath ?? _sftpPathController.text,
      );
      final entries = await widget.connection.listSftpDirectory(
        currentDirectory,
      );
      if (!mounted) {
        return;
      }
      final renamedOpenedPath = _openedFilePath == null
          ? null
          : _replaceSftpPathPrefix(_openedFilePath!, entry.path, newPath);
      _moveSftpCachesForRename(entry.path, newPath);
      setState(() {
        _sftpEntries = entries;
        if (renamedOpenedPath != null) {
          _openedFilePath = renamedOpenedPath;
        }
      });
      _scrollSftpListToEntry(newPath);
      _showSnackBar('已重命名为 $newPath');
    } catch (error) {
      if (mounted) {
        setState(() => _sftpError = _formatError(error));
      }
    } finally {
      if (mounted) {
        setState(() => _sftpBusy = false);
      }
    }
  }

  void _moveSftpCachesForRename(String oldPath, String newPath) {
    final moved = <String, _SftpEditCache>{};
    final removed = <String>[];
    for (final MapEntry(key: path, value: cache) in _sftpEditCache.entries) {
      final renamedPath = _replaceSftpPathPrefix(path, oldPath, newPath);
      if (renamedPath == null) {
        continue;
      }
      moved[renamedPath] = cache;
      removed.add(path);
    }
    for (final path in removed) {
      _sftpEditCache.remove(path);
    }
    _sftpEditCache.addAll(moved);
  }

  Future<void> _showSftpEditCacheDialog() async {
    if (_sftpEditCache.isEmpty) {
      _showSnackBar('当前没有未保存的文件编辑。');
      return;
    }

    final cachedPaths = _sftpEditCache.keys.toList()..sort();
    final selectedPaths = <String>{};
    final result = await showDialog<_SftpEditCacheDialogResult>(
      context: context,
      builder: (context) {
        final screenWidth = MediaQuery.sizeOf(context).width;
        final dialogWidth = math.min(560.0, math.max(280.0, screenWidth - 64));
        return StatefulBuilder(
          builder: (context, setDialogState) {
            void setSelected(String path, bool selected) {
              setDialogState(() {
                if (selected) {
                  selectedPaths.add(path);
                } else {
                  selectedPaths.remove(path);
                }
              });
            }

            return AlertDialog(
              title: Text('未保存的文件（已选 ${selectedPaths.length}）'),
              content: SizedBox(
                width: dialogWidth,
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxHeight: 360),
                  child: ListView.separated(
                    shrinkWrap: true,
                    itemCount: cachedPaths.length,
                    separatorBuilder: (_, __) => const Divider(height: 1),
                    itemBuilder: (context, index) {
                      final path = cachedPaths[index];
                      final cache = _sftpEditCache[path]!;
                      final selected = selectedPaths.contains(path);
                      return CheckboxListTile(
                        value: selected,
                        controlAffinity: ListTileControlAffinity.leading,
                        secondary: IconButton(
                          tooltip: '跳转到文件',
                          icon: const Icon(Icons.open_in_new),
                          onPressed: () => Navigator.of(context).pop(
                            _SftpEditCacheDialogResult.jump(path),
                          ),
                        ),
                        title: Text(
                          path,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        subtitle: Text(
                          cache.editingBinary ? '二进制 HEX 编辑' : '文本编辑',
                        ),
                        onChanged: (value) => setSelected(path, value ?? false),
                      );
                    },
                  ),
                ),
              ),
              actions: <Widget>[
                TextButton(
                  onPressed: selectedPaths.length == cachedPaths.length
                      ? null
                      : () => setDialogState(
                            () => selectedPaths.addAll(cachedPaths),
                          ),
                  child: const Text('全选'),
                ),
                TextButton(
                  onPressed: selectedPaths.isEmpty
                      ? null
                      : () => setDialogState(selectedPaths.clear),
                  child: const Text('清空'),
                ),
                TextButton.icon(
                  onPressed: selectedPaths.isEmpty
                      ? null
                      : () => Navigator.of(context).pop(
                            _SftpEditCacheDialogResult.restore(selectedPaths),
                          ),
                  icon: const Icon(Icons.restore),
                  label: const Text('恢复所选'),
                ),
                FilledButton.icon(
                  onPressed: selectedPaths.isEmpty
                      ? null
                      : () => Navigator.of(context).pop(
                            _SftpEditCacheDialogResult.save(selectedPaths),
                          ),
                  icon: const Icon(Icons.save_outlined),
                  label: const Text('保存所选'),
                ),
                TextButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: const Text('关闭'),
                ),
              ],
            );
          },
        );
      },
    );
    if (result == null) {
      return;
    }
    switch (result.action) {
      case _SftpEditCacheDialogAction.jump:
        await _jumpToSftpCachedFile(result.paths.single);
      case _SftpEditCacheDialogAction.save:
        await _saveSftpCachedFiles(result.paths);
      case _SftpEditCacheDialogAction.restore:
        _restoreSftpCachedFiles(result.paths);
    }
  }

  Future<void> _saveSftpCachedFiles(List<String> paths) async {
    if (!widget.connection.isConnected) {
      setState(() => _sftpError = '请先连接会话，然后再保存未保存文件。');
      return;
    }

    setState(() {
      _sftpBusy = true;
      _sftpError = null;
    });

    final saved = <String, EmTaskSftpFileContent>{};
    final failures = <String>[];
    for (final path in paths) {
      final cache = _sftpEditCache[path];
      if (cache == null) {
        continue;
      }
      try {
        final bytes = cache.editingBinary
            ? EmTaskSftpFileContent.parseHexBytes(cache.editedText)
            : Uint8List.fromList(utf8.encode(cache.editedText));
        await widget.connection.writeSftpFileBytes(path, bytes);
        saved[path] = EmTaskSftpFileContent(
          text: cache.editingBinary ? '' : cache.editedText,
          bytes: bytes,
          size: bytes.length,
          offset: 0,
          length: bytes.length,
          isTruncated: false,
          isUtf8Text: !cache.editingBinary,
          pageBytes: EmTaskConnection.sftpPageBytes,
        );
      } on FormatException catch (error) {
        failures.add('$path：HEX 内容格式错误：${error.message}');
      } catch (error) {
        failures.add('$path：${_formatError(error)}');
      }
    }

    List<EmTaskSftpEntry>? refreshedEntries;
    if (saved.isNotEmpty && _loadedDirectoryPath != null) {
      try {
        refreshedEntries = await widget.connection.listSftpDirectory(
          _loadedDirectoryPath!,
        );
      } catch (_) {
        // 保存已经完成；目录刷新失败不影响缓存清理。
      }
    }

    if (!mounted) {
      return;
    }
    setState(() {
      for (final path in saved.keys) {
        _sftpEditCache.remove(path);
      }
      if (refreshedEntries != null) {
        _sftpEntries = refreshedEntries;
      }
      final openedPath = _openedFilePath;
      if (openedPath != null && saved.containsKey(openedPath)) {
        final nextContent = saved[openedPath]!;
        final nextEditorText = nextContent.editorText;
        _openedFileText = nextContent.displayText;
        _openedFileOriginalText = nextEditorText;
        _openedFileContent = nextContent;
        _openedFileDirty = false;
        _openedFileEditingBinary = nextContent.isBinaryEditable;
        _setSftpEditorText(nextEditorText);
      }
      if (failures.isNotEmpty) {
        _sftpError = '部分未保存文件保存失败：\n${failures.take(3).join('\n')}';
      }
      _sftpBusy = false;
    });
    if (saved.isNotEmpty) {
      _showSnackBar('已保存 ${saved.length} 个未保存文件。');
    }
  }

  void _restoreSftpCachedFiles(List<String> paths) {
    String? restoredEditorText;
    var restoredCount = 0;
    setState(() {
      for (final path in paths) {
        final cache = _sftpEditCache.remove(path);
        if (cache == null) {
          continue;
        }
        restoredCount += 1;
        if (_openedFilePath == path) {
          restoredEditorText = cache.originalText;
          _openedFileDirty = false;
        }
      }
    });
    if (restoredEditorText != null) {
      _setSftpEditorText(restoredEditorText!);
    }
    if (restoredCount > 0) {
      _showSnackBar('已恢复 $restoredCount 个文件的未保存编辑。');
    }
  }

  Future<void> _jumpToSftpCachedFile(String path) async {
    if (!widget.connection.isConnected) {
      setState(() => _sftpError = '请先连接会话，然后再打开未保存文件。');
      return;
    }

    final directory = _parentSftpPath(path);
    if (_loadedDirectoryPath != directory) {
      await _loadDirectory(path: directory);
      if (!mounted || _loadedDirectoryPath != directory) {
        return;
      }
    }
    await _loadFilePage(path, offset: 0);
    _scrollSftpListToEntry(path);
  }

  Future<String?> _showSftpNameDialog({
    required String title,
    required String labelText,
    required String confirmText,
    String? initialText,
  }) async {
    final controller = TextEditingController(text: initialText);
    controller.selection = TextSelection(
      baseOffset: 0,
      extentOffset: controller.text.length,
    );
    return showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: InputDecoration(
            labelText: labelText,
            helperText: '仅输入名称，不要包含 /、\\、: 或 ..',
          ),
          onSubmitted: (_) {
            final name = controller.text.trim();
            if (_isValidSftpChildName(name)) {
              Navigator.of(context).pop(name);
            }
          },
        ),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () {
              final name = controller.text.trim();
              if (!_isValidSftpChildName(name)) {
                _showSnackBar('名称不能为空，且不能包含 /、\\、: 或 ..。');
                return;
              }
              Navigator.of(context).pop(name);
            },
            child: Text(confirmText),
          ),
        ],
      ),
    ).whenComplete(controller.dispose);
  }

  int _sftpCachedPathCountUnder(String directoryPath) {
    return _sftpEditCache.keys
        .where((path) => _isSftpPathUnder(path, directoryPath))
        .length;
  }

  void _removeSftpCachesUnder(String directoryPath) {
    _sftpEditCache.removeWhere(
      (path, _) => _isSftpPathUnder(path, directoryPath),
    );
  }

  Future<void> _resetSftpPath() async {
    await _loadDirectory(path: '.');
  }

  void _scrollSftpListToTop() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_sftpListScrollController.hasClients) {
        _sftpListScrollController.jumpTo(0);
      }
    });
  }

  void _scrollSftpListToEntry(String path) {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_sftpListScrollController.hasClients) {
        return;
      }
      final index = _sftpEntries.indexWhere((entry) => entry.path == path);
      if (index < 0) {
        return;
      }
      const estimatedItemExtent = 57.0;
      final parentOffset = _loadedDirectoryPath == null ? 0 : 1;
      final target = (index + parentOffset) * estimatedItemExtent;
      final position = _sftpListScrollController.position;
      _sftpListScrollController.jumpTo(
        target.clamp(position.minScrollExtent, position.maxScrollExtent),
      );
    });
  }

  void _scrollSftpPreviewToTop() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_sftpPreviewScrollController.hasClients) {
        _sftpPreviewScrollController.jumpTo(0);
      }
    });
  }

  void _showSnackBar(String message) {
    final messenger = ScaffoldMessenger.of(context);
    messenger.hideCurrentSnackBar();
    messenger.showSnackBar(
      SnackBar(
        duration: const Duration(seconds: 4),
        content: Text(message),
        action: SnackBarAction(
          label: '关闭',
          onPressed: () {
            ScaffoldMessenger.of(context).hideCurrentSnackBar();
          },
        ),
      ),
    );
  }

  Future<void> _restartRemoteTask() async {
    if (!widget.connection.isConnected) {
      _showSnackBar('请先连接会话，再重启远端应用。');
      return;
    }
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('重启应用'),
        content: const Text('将立即终止当前 emtask 应用进程并由服务端重新拉起。是否继续？'),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('取消'),
          ),
          FilledButton.icon(
            onPressed: () => Navigator.of(context).pop(true),
            icon: const Icon(Icons.restart_alt),
            label: const Text('重启'),
          ),
        ],
      ),
    );
    if (confirmed != true) {
      _terminalFocusNode.requestFocus();
      return;
    }
    try {
      await widget.connection.restartRemoteTask();
      _showSnackBar('已请求 emtask 快速重启应用。');
    } catch (error) {
      _showSnackBar('重启应用失败：${_formatError(error)}');
    } finally {
      _requestTerminalInputFocus();
    }
  }

  void _requestTerminalInputFocus() {
    if (!widget.connection.isConnected) {
      return;
    }
    if (widget.terminalKeyboardButtonOnly && !_terminalKeyboardUnlocked) {
      return;
    }
    _terminalFocusNode.requestFocus();
  }

  void _toggleTerminalKeyboardInput() {
    if (!widget.terminalKeyboardButtonOnly) {
      _terminalFocusNode.requestFocus();
      return;
    }
    if (!_terminalKeyboardUnlocked) {
      setState(() => _terminalKeyboardUnlocked = true);
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted && widget.connection.isConnected) {
          _terminalFocusNode.requestFocus();
        }
      });
      return;
    }
    setState(() => _terminalKeyboardUnlocked = false);
    _terminalFocusNode.unfocus();
  }

  void _sendTerminalShortcut(_TerminalShortcutKey key) {
    if (!widget.connection.isConnected) {
      _showSnackBar('请先连接会话，再发送终端快捷键。');
      return;
    }
    try {
      widget.connection.writeText(_terminalShortcutSequence(key));
      _requestTerminalInputFocus();
    } catch (error) {
      _showSnackBar(_formatError(error));
    }
  }

  String _applyTerminalInputModifiers(String data) {
    if (!widget.shortcutKeysEnabled || data.isEmpty) {
      return data;
    }
    if (!_shortcutCtrl && !_shortcutAlt && !_shortcutShift) {
      return data;
    }

    final transformed = _terminalInputWithModifiers(
      data,
      ctrl: _shortcutCtrl,
      shift: _shortcutShift,
      alt: _shortcutAlt,
    );
    if (_shortcutCtrl || _shortcutAlt) {
      setState(() {
        _shortcutCtrl = false;
        _shortcutAlt = false;
      });
    }
    return transformed;
  }

  String _terminalShortcutSequence(_TerminalShortcutKey key) {
    switch (key) {
      case _TerminalShortcutKey.tab:
        if (_shortcutShift && !_shortcutCtrl && !_shortcutAlt) {
          return '\x1b[Z';
        }
        final tab = _shortcutCtrl ? '\x09' : '\t';
        return _shortcutAlt ? '\x1b$tab' : tab;
      case _TerminalShortcutKey.up:
        return _modifiedArrowSequence('A');
      case _TerminalShortcutKey.down:
        return _modifiedArrowSequence('B');
      case _TerminalShortcutKey.right:
        return _modifiedArrowSequence('C');
      case _TerminalShortcutKey.left:
        return _modifiedArrowSequence('D');
    }
  }

  String _modifiedArrowSequence(String finalByte) {
    var modifier = 1;
    if (_shortcutShift) {
      modifier += 1;
    }
    if (_shortcutAlt) {
      modifier += 2;
    }
    if (_shortcutCtrl) {
      modifier += 4;
    }
    if (modifier == 1) {
      return '\x1b[$finalByte';
    }
    return '\x1b[1;$modifier$finalByte';
  }

  @override
  Widget build(BuildContext context) {
    final layout = _layoutForWidth(MediaQuery.sizeOf(context).width);
    return AnimatedBuilder(
      animation: widget.connection,
      builder: (context, _) {
        final connection = widget.connection;
        return Scaffold(
          resizeToAvoidBottomInset: _showSftp,
          appBar: AppBar(
            backgroundColor: const Color(0xff111827),
            title: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(
                  connection.profile.name,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                Text(
                  '${connection.profile.host}:${connection.profile.port}',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: Theme.of(context).textTheme.labelSmall,
                ),
              ],
            ),
            actions: <Widget>[
              if (!_showSftp)
                IconButton(
                  tooltip: widget.terminalKeyboardButtonOnly
                      ? (_terminalKeyboardUnlocked ? '锁定键盘输入' : '打开键盘输入')
                      : '打开键盘输入',
                  onPressed: connection.isConnected
                      ? _toggleTerminalKeyboardInput
                      : null,
                  icon: Icon(
                    widget.terminalKeyboardButtonOnly &&
                            !_terminalKeyboardUnlocked
                        ? Icons.keyboard_hide
                        : Icons.keyboard_outlined,
                  ),
                ),
              if (!_showSftp)
                IconButton(
                  tooltip: '重启应用',
                  onPressed: connection.isConnected ? _restartRemoteTask : null,
                  icon: const Icon(Icons.restart_alt),
                ),
              if (!_showSftp)
                IconButton(
                  tooltip: '清空终端输出',
                  onPressed: () {
                    widget.connection.clearOutput();
                    _terminal.write('\u001b[2J\u001b[H');
                    _terminalFocusNode.requestFocus();
                  },
                  icon: const Icon(Icons.cleaning_services_outlined),
                ),
              if (connection.profile.supportsSftp || _showSftp)
                TextButton.icon(
                  style: TextButton.styleFrom(
                    foregroundColor: Theme.of(context).colorScheme.primary,
                  ),
                  onPressed: _toggleViewMode,
                  icon: Icon(
                    _showSftp ? Icons.terminal : Icons.folder_open_outlined,
                  ),
                  label: Text(_showSftp ? '终端' : 'SFTP'),
                ),
            ],
          ),
          body: _showSftp
              ? SafeArea(
                  child: Padding(
                    padding: layout.pagePadding,
                    child: _buildSftpView(connection),
                  ),
                )
              : _buildTerminalView(connection),
        );
      },
    );
  }

  Widget _buildTerminalView(EmTaskConnection connection) {
    final keyboardInset = MediaQuery.viewInsetsOf(context).bottom;
    final keyboardVisible = keyboardInset > 0;
    final manualKeyboardLocked = widget.terminalKeyboardButtonOnly &&
        !_terminalKeyboardUnlocked &&
        connection.isConnected;
    const shortcutBarHeight = 48.0;
    final shortcutBottom = keyboardVisible ? keyboardInset + 8 : 8.0;
    final shortcutReserve =
        widget.shortcutKeysEnabled ? shortcutBarHeight + 18 : 0.0;
    final terminalBottomPadding =
        10.0 + shortcutReserve + (keyboardVisible ? keyboardInset : 0.0);

    return SafeArea(
      top: false,
      bottom: !keyboardVisible,
      child: Container(
        width: double.infinity,
        color: Colors.black,
        child: Stack(
          children: <Widget>[
            Positioned.fill(
              child: TerminalView(
                _terminal,
                controller: _terminalController,
                focusNode: _terminalFocusNode,
                autofocus: !widget.terminalKeyboardButtonOnly,
                readOnly: !connection.isConnected || manualKeyboardLocked,
                shortcuts: _terminalShortcutsForPlatform(defaultTargetPlatform),
                theme: TerminalThemes.whiteOnBlack,
                textStyle: const TerminalStyle(
                  fontFamily: 'Consolas',
                  fontFamilyFallback: <String>[
                    'Cascadia Mono',
                    'Microsoft YaHei UI',
                    'Menlo',
                    'monospace',
                  ],
                  fontSize: 14,
                  height: 1.28,
                ),
                padding: EdgeInsets.fromLTRB(
                  10,
                  10,
                  10,
                  terminalBottomPadding,
                ),
                cursorType: TerminalCursorType.block,
                alwaysShowCursor: true,
              ),
            ),
            if (manualKeyboardLocked)
              Positioned(
                top: 12,
                right: 12,
                child: DecoratedBox(
                  decoration: BoxDecoration(
                    color: const Color(0xdd111827),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: const Color(0xff334155)),
                  ),
                  child: Padding(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 12,
                      vertical: 8,
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: <Widget>[
                        const Icon(Icons.keyboard_hide, size: 16),
                        const SizedBox(width: 6),
                        TextButton(
                          style: TextButton.styleFrom(
                            padding: EdgeInsets.zero,
                            minimumSize: const Size(0, 32),
                          ),
                          onPressed: _toggleTerminalKeyboardInput,
                          child: const Text('点击键盘按钮后输入'),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            if (widget.shortcutKeysEnabled)
              AnimatedPositioned(
                duration: const Duration(milliseconds: 180),
                curve: Curves.easeOutCubic,
                left: 8,
                right: 8,
                bottom: shortcutBottom,
                child: _TerminalShortcutBar(
                  enabled: connection.isConnected,
                  ctrlActive: _shortcutCtrl,
                  shiftActive: _shortcutShift,
                  altActive: _shortcutAlt,
                  onToggleCtrl: () {
                    setState(() => _shortcutCtrl = !_shortcutCtrl);
                    _requestTerminalInputFocus();
                  },
                  onToggleShift: () {
                    setState(() => _shortcutShift = !_shortcutShift);
                    _requestTerminalInputFocus();
                  },
                  onToggleAlt: () {
                    setState(() => _shortcutAlt = !_shortcutAlt);
                    _requestTerminalInputFocus();
                  },
                  onSend: _sendTerminalShortcut,
                ),
              ),
            if (!connection.isConnected)
              AnimatedPositioned(
                duration: const Duration(milliseconds: 180),
                curve: Curves.easeOutCubic,
                right: 12,
                bottom: shortcutBottom + (widget.shortcutKeysEnabled ? 54 : 4),
                child: DecoratedBox(
                  decoration: BoxDecoration(
                    color: const Color(0xdd111827),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: const Color(0xff334155)),
                  ),
                  child: const Padding(
                    padding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    child: Text('会话已断开，请返回会话列表重新连接'),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildSftpView(EmTaskConnection connection) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Row(
              children: <Widget>[
                const Icon(Icons.folder_open_outlined, size: 20),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'SFTP 文件查看 / 编辑',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                ),
                if (_sftpBusy)
                  const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              '通过独立 SSH 连接打开 SFTP 子系统；根目录就是该任务工作路径，只能浏览工作路径及其子路径。',
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 12),
            _buildSftpToolbar(connection),
            if (_sftpError != null) ...<Widget>[
              const SizedBox(height: 10),
              _InlineError(message: _sftpError!),
            ],
            const SizedBox(height: 12),
            Expanded(
              child: connection.isConnected
                  ? _buildSftpContent()
                  : const _SftpPlaceholder(
                      message: '请先连接会话，然后使用右上角或页面内的连接按钮打开 SFTP。',
                    ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSftpToolbar(EmTaskConnection connection) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final pathField = TextField(
          controller: _sftpPathController,
          enabled: !_sftpBusy,
          decoration: const InputDecoration(
            labelText: 'SFTP 路径',
            hintText: '`.` 表示工作路径，例如 logs 或 logs/app.log',
            border: OutlineInputBorder(),
            isDense: true,
          ),
          onSubmitted: (_) => _loadDirectory(),
        );
        final buttons = Wrap(
          spacing: 8,
          runSpacing: 8,
          children: <Widget>[
            FilledButton.icon(
              onPressed: connection.isConnected && !_sftpBusy
                  ? () => _loadDirectory()
                  : null,
              icon: const Icon(Icons.list_alt),
              label: const Text('打开目录'),
            ),
            OutlinedButton.icon(
              onPressed: connection.isConnected && !_sftpBusy
                  ? _openParentDirectory
                  : null,
              icon: const Icon(Icons.drive_folder_upload_outlined),
              label: const Text('上级'),
            ),
            OutlinedButton.icon(
              onPressed:
                  connection.isConnected && !_sftpBusy ? _resetSftpPath : null,
              icon: const Icon(Icons.home_outlined),
              label: const Text('重置'),
            ),
            OutlinedButton.icon(
              onPressed: connection.isConnected && !_sftpBusy
                  ? _refreshSftpDirectory
                  : null,
              icon: const Icon(Icons.refresh),
              label: const Text('刷新'),
            ),
            OutlinedButton.icon(
              onPressed: connection.isConnected && !_sftpBusy
                  ? _createSftpDirectory
                  : null,
              icon: const Icon(Icons.create_new_folder_outlined),
              label: const Text('新建文件夹'),
            ),
            OutlinedButton.icon(
              onPressed:
                  connection.isConnected && !_sftpBusy ? _createSftpFile : null,
              icon: const Icon(Icons.note_add_outlined),
              label: const Text('新建文件'),
            ),
            if (_sftpEditCache.isNotEmpty)
              OutlinedButton.icon(
                onPressed: !_sftpBusy ? _showSftpEditCacheDialog : null,
                icon: const Icon(Icons.pending_actions_outlined),
                label: Text('未保存 ${_sftpEditCache.length}'),
              ),
          ],
        );

        if (constraints.maxWidth < 980) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              pathField,
              const SizedBox(height: 10),
              buttons,
            ],
          );
        }
        return Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Expanded(child: pathField),
            const SizedBox(width: 10),
            Flexible(child: buttons),
          ],
        );
      },
    );
  }

  Widget _buildSftpContent() {
    if (_sftpBusy && _loadedDirectoryPath == null) {
      return const Center(child: CircularProgressIndicator());
    }

    return LayoutBuilder(
      builder: (context, constraints) {
        final list = _buildSftpEntryList();
        final preview = _buildSftpPreview();
        if (constraints.maxWidth >= 820) {
          return Row(
            children: <Widget>[
              Expanded(flex: 2, child: list),
              const SizedBox(width: 12),
              Expanded(flex: 3, child: preview),
            ],
          );
        }

        final listHeight = _sftpEntries.isEmpty
            ? 150.0
            : math.min(300.0, math.max(190.0, constraints.maxHeight * 0.38));
        final previewHeight = EmTaskClientSettings.clampSftpPreviewHeight(
          widget.sftpPreviewHeight,
        ).toDouble();
        return SingleChildScrollView(
          padding: EdgeInsets.only(
              bottom: MediaQuery.paddingOf(context).bottom + 16),
          child: Column(
            children: <Widget>[
              SizedBox(height: listHeight, child: list),
              const SizedBox(height: 12),
              SizedBox(height: previewHeight, child: preview),
            ],
          ),
        );
      },
    );
  }

  Widget _buildSftpEntryList() {
    final emptyMessage =
        _loadedDirectoryPath == null ? '输入路径后点击“打开目录”。' : '目录为空。';
    final showParentEntry = _loadedDirectoryPath != null;
    final itemCount = _sftpEntries.length + (showParentEntry ? 1 : 0);

    return DecoratedBox(
      decoration: BoxDecoration(
        color: const Color(0xff020617),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0xff1f2937)),
      ),
      child: itemCount == 0
          ? Center(child: Text(emptyMessage))
          : Scrollbar(
              controller: _sftpListScrollController,
              child: ListView.separated(
                controller: _sftpListScrollController,
                padding: const EdgeInsets.symmetric(vertical: 8),
                itemCount: itemCount,
                separatorBuilder: (_, __) => const Divider(height: 1),
                itemBuilder: (context, index) {
                  if (showParentEntry && index == 0) {
                    final atRoot = _loadedDirectoryPath == '.';
                    return ListTile(
                      dense: true,
                      leading: const Icon(Icons.folder_outlined),
                      title: const Text('..'),
                      subtitle: Text(atRoot ? '工作路径根目录' : '上级目录'),
                      onTap: _openParentDirectory,
                    );
                  }
                  final entryIndex = showParentEntry ? index - 1 : index;
                  final entry = _sftpEntries[entryIndex];
                  return ListTile(
                    dense: true,
                    leading: Icon(
                      entry.isDirectory
                          ? Icons.folder_outlined
                          : entry.isSymbolicLink
                              ? Icons.link
                              : Icons.description_outlined,
                    ),
                    title: Text(
                      entry.name,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    subtitle: Text(
                      _entrySubtitle(entry),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    trailing: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: <Widget>[
                        IconButton(
                          tooltip: '重命名',
                          icon: const Icon(Icons.drive_file_rename_outline),
                          onPressed:
                              _sftpBusy ? null : () => _renameSftpEntry(entry),
                        ),
                        IconButton(
                          tooltip: '删除',
                          icon: const Icon(Icons.delete_outline),
                          onPressed:
                              _sftpBusy ? null : () => _deleteSftpEntry(entry),
                        ),
                      ],
                    ),
                    onTap: () => entry.isDirectory
                        ? _loadDirectory(path: entry.path)
                        : _openFile(entry),
                  );
                },
              ),
            ),
    );
  }

  Widget _buildSftpPreview() {
    final openedFilePath = _openedFilePath;
    final openedFileContent = _openedFileContent;
    final canSave = openedFilePath != null &&
        _openedFileEditable &&
        _openedFileDirty &&
        !_sftpBusy &&
        widget.connection.isConnected;

    return DecoratedBox(
      decoration: BoxDecoration(
        color: const Color(0xff020617),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0xff1f2937)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Padding(
            padding: const EdgeInsets.fromLTRB(14, 12, 14, 8),
            child: LayoutBuilder(
              builder: (context, constraints) {
                final compactHeader = constraints.maxWidth < 520;
                final title = Row(
                  children: <Widget>[
                    Icon(
                      openedFileContent?.isBinary == true
                          ? Icons.data_object
                          : Icons.article_outlined,
                      size: 18,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        openedFilePath == null
                            ? '文件预览'
                            : _openedFileDirty
                                ? '$openedFilePath *'
                                : openedFilePath,
                        maxLines: compactHeader ? 2 : 1,
                        overflow: TextOverflow.ellipsis,
                        style: Theme.of(context).textTheme.titleSmall,
                      ),
                    ),
                  ],
                );
                final saveButton = openedFilePath != null && _openedFileEditable
                    ? FilledButton.icon(
                        onPressed: canSave ? _saveOpenedFile : null,
                        icon: const Icon(Icons.save_outlined, size: 18),
                        label: const Text('保存'),
                      )
                    : null;

                return Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    if (compactHeader) ...<Widget>[
                      title,
                      if (saveButton != null) ...<Widget>[
                        const SizedBox(height: 8),
                        Align(
                            alignment: Alignment.centerRight,
                            child: saveButton),
                      ],
                    ] else
                      Row(
                        children: <Widget>[
                          Expanded(child: title),
                          if (saveButton != null) ...<Widget>[
                            const SizedBox(width: 8),
                            saveButton,
                          ],
                        ],
                      ),
                    if (openedFileContent != null) ...<Widget>[
                      const SizedBox(height: 8),
                      _buildSftpPreviewControls(openedFileContent),
                    ],
                  ],
                );
              },
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: openedFilePath != null && _openedFileEditable
                ? Scrollbar(
                    controller: _sftpPreviewScrollController,
                    child: TextField(
                      controller: _sftpEditorController,
                      scrollController: _sftpPreviewScrollController,
                      enabled: !_sftpBusy,
                      expands: true,
                      maxLines: null,
                      minLines: null,
                      keyboardType: TextInputType.multiline,
                      textInputAction: TextInputAction.newline,
                      decoration: InputDecoration(
                        hintText: _openedFileEditingBinary
                            ? '按 HEX 字节编辑，例如：00 1f a0 ff。空格、换行、逗号可分隔。'
                            : '文件为空，可直接输入内容后保存。',
                        border: InputBorder.none,
                        contentPadding: const EdgeInsets.all(14),
                      ),
                      style: const TextStyle(
                        fontFamily: 'Consolas',
                        fontFamilyFallback: <String>['Menlo', 'monospace'],
                        fontSize: 13,
                        height: 1.35,
                        color: Color(0xffd1d5db),
                      ),
                    ),
                  )
                : Scrollbar(
                    controller: _sftpPreviewScrollController,
                    child: SingleChildScrollView(
                      controller: _sftpPreviewScrollController,
                      padding: const EdgeInsets.all(14),
                      child: SelectableText(
                        _openedFileText ?? '点击左侧文件查看内容。',
                        style: const TextStyle(
                          fontFamily: 'Consolas',
                          fontFamilyFallback: <String>['Menlo', 'monospace'],
                          fontSize: 13,
                          height: 1.35,
                          color: Color(0xffd1d5db),
                        ),
                      ),
                    ),
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildSftpPreviewControls(EmTaskSftpFileContent content) {
    final metaChips = Wrap(
      spacing: 8,
      runSpacing: 6,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: <Widget>[
        Chip(
          visualDensity: VisualDensity.compact,
          label: Text(
            content.isBinary
                ? (content.isBinaryEditable ? '二进制 / HEX 可编辑' : '二进制 / HEX')
                : 'UTF-8 文本',
          ),
        ),
        Chip(
          visualDensity: VisualDensity.compact,
          label: Text(
            '大小 ${_formatBytes(content.size)} · 偏移 ${content.offset} · 本页 ${_formatBytes(content.length)}',
          ),
        ),
      ],
    );

    final offsetField = SizedBox(
      width: 150,
      child: TextField(
        controller: _sftpOffsetController,
        enabled: !_sftpBusy,
        keyboardType: TextInputType.number,
        decoration: const InputDecoration(
          labelText: '偏移',
          isDense: true,
          border: OutlineInputBorder(),
        ),
        onSubmitted: (_) => _loadOpenedFileOffset(),
      ),
    );

    final pageButtons = Wrap(
      spacing: 8,
      runSpacing: 8,
      children: <Widget>[
        OutlinedButton.icon(
          onPressed: content.canGoPrevious && !_sftpBusy
              ? _loadPreviousFilePage
              : null,
          icon: const Icon(Icons.chevron_left),
          label: const Text('上一页'),
        ),
        OutlinedButton.icon(
          onPressed: content.canGoNext && !_sftpBusy ? _loadNextFilePage : null,
          icon: const Icon(Icons.chevron_right),
          label: const Text('下一页'),
        ),
        FilledButton.tonalIcon(
          onPressed: !_sftpBusy ? _loadOpenedFileOffset : null,
          icon: const Icon(Icons.travel_explore),
          label: const Text('跳转'),
        ),
      ],
    );

    return LayoutBuilder(
      builder: (context, constraints) {
        final compact = constraints.maxWidth < 560;
        if (compact) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              metaChips,
              const SizedBox(height: 8),
              offsetField,
              const SizedBox(height: 8),
              pageButtons,
            ],
          );
        }

        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            metaChips,
            const SizedBox(height: 8),
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                offsetField,
                const SizedBox(width: 8),
                Expanded(child: pageButtons),
              ],
            ),
          ],
        );
      },
    );
  }

  static String _entrySubtitle(EmTaskSftpEntry entry) {
    final type = entry.isDirectory
        ? '目录'
        : entry.isSymbolicLink
            ? '链接'
            : '文件';
    final size = entry.isDirectory ? '' : ' · ${_formatBytes(entry.size)}';
    final modified = entry.modifiedAt == null
        ? ''
        : ' · ${_formatDateTime(entry.modifiedAt!)}';
    return '$type$size$modified';
  }
}

enum _SessionMenuAction {
  status,
  rerun,
  edit,
  createPanelTaskFromTemplate,
  delete,
}

enum _HomeMenuAction {
  refreshPanels,
  addPanel,
  importPanelQr,
  updater,
  settings,
}

enum _PanelMenuAction {
  addTask,
  registerKey,
  edit,
  delete,
}

enum _QrImportAction {
  camera,
  image,
  file,
}

enum _SftpEditCacheDialogAction {
  jump,
  save,
  restore,
}

class _SftpEditCacheDialogResult {
  const _SftpEditCacheDialogResult._({
    required this.action,
    required this.paths,
  });

  factory _SftpEditCacheDialogResult.jump(String path) {
    return _SftpEditCacheDialogResult._(
      action: _SftpEditCacheDialogAction.jump,
      paths: <String>[path],
    );
  }

  factory _SftpEditCacheDialogResult.save(Iterable<String> paths) {
    return _SftpEditCacheDialogResult._(
      action: _SftpEditCacheDialogAction.save,
      paths: List<String>.unmodifiable(paths),
    );
  }

  factory _SftpEditCacheDialogResult.restore(Iterable<String> paths) {
    return _SftpEditCacheDialogResult._(
      action: _SftpEditCacheDialogAction.restore,
      paths: List<String>.unmodifiable(paths),
    );
  }

  final _SftpEditCacheDialogAction action;
  final List<String> paths;
}

class _SftpEditCache {
  const _SftpEditCache({
    required this.originalText,
    required this.editedText,
    required this.editingBinary,
  });

  final String originalText;
  final String editedText;
  final bool editingBinary;
}

class _ScreenRegionSelection {
  const _ScreenRegionSelection({
    required this.x,
    required this.y,
    required this.width,
    required this.height,
  });

  final int x;
  final int y;
  final int width;
  final int height;
}

class _ScreenRegionPicker extends StatefulWidget {
  const _ScreenRegionPicker({
    required this.imageBytes,
    required this.imageWidth,
    required this.imageHeight,
  });

  final Uint8List imageBytes;
  final int imageWidth;
  final int imageHeight;

  @override
  State<_ScreenRegionPicker> createState() => _ScreenRegionPickerState();
}

class _ScreenRegionPickerState extends State<_ScreenRegionPicker> {
  Offset? _dragStart;
  Offset? _dragCurrent;

  @override
  Widget build(BuildContext context) {
    return Dialog.fullscreen(
      backgroundColor: Colors.black,
      child: LayoutBuilder(
        builder: (context, constraints) {
          final viewport = Size(constraints.maxWidth, constraints.maxHeight);
          final imageRect = _containedImageRect(viewport);
          final selectionRect = _selectionRect(imageRect);
          return Stack(
            children: <Widget>[
              Positioned.fill(
                child: ColoredBox(
                  color: Colors.black,
                  child: Center(
                    child: SizedBox.fromSize(
                      size: imageRect.size,
                      child: Image.memory(
                        widget.imageBytes,
                        fit: BoxFit.fill,
                        gaplessPlayback: true,
                      ),
                    ),
                  ),
                ),
              ),
              Positioned.fill(
                child: GestureDetector(
                  behavior: HitTestBehavior.opaque,
                  onPanStart: (details) {
                    if (!imageRect.contains(details.localPosition)) {
                      return;
                    }
                    setState(() {
                      _dragStart =
                          _clampOffset(details.localPosition, imageRect);
                      _dragCurrent = _dragStart;
                    });
                  },
                  onPanUpdate: (details) {
                    if (_dragStart == null) {
                      return;
                    }
                    setState(() {
                      _dragCurrent =
                          _clampOffset(details.localPosition, imageRect);
                    });
                  },
                ),
              ),
              Positioned.fill(
                child: IgnorePointer(
                  child: CustomPaint(
                    painter: _ScreenRegionPainter(
                      imageRect: imageRect,
                      selectionRect: selectionRect,
                    ),
                  ),
                ),
              ),
              Positioned(
                top: 16,
                left: 16,
                right: 16,
                child: SafeArea(
                  child: Center(
                    child: Card(
                      color: const Color(0xdd111827),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 14,
                          vertical: 10,
                        ),
                        child: Text(
                          '拖拽框选屏幕截图中的 emtask 面板二维码区域',
                          textAlign: TextAlign.center,
                          style: Theme.of(context).textTheme.bodyMedium,
                        ),
                      ),
                    ),
                  ),
                ),
              ),
              Positioned(
                left: 16,
                right: 16,
                bottom: 16,
                child: SafeArea(
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: <Widget>[
                      FilledButton.tonal(
                        onPressed: () => Navigator.of(context).pop(),
                        child: const Text('取消'),
                      ),
                      const SizedBox(width: 12),
                      FilledButton.icon(
                        onPressed: _isValidSelection(selectionRect)
                            ? () => _confirmSelection(imageRect, selectionRect!)
                            : null,
                        icon: const Icon(Icons.qr_code_scanner_outlined),
                        label: const Text('识别此区域'),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  Rect _containedImageRect(Size viewport) {
    final imageSize = Size(
      widget.imageWidth.toDouble(),
      widget.imageHeight.toDouble(),
    );
    if (viewport.width <= 0 || viewport.height <= 0) {
      return Rect.zero;
    }
    final imageAspect = imageSize.width / imageSize.height;
    final viewportAspect = viewport.width / viewport.height;
    if (viewportAspect > imageAspect) {
      final height = viewport.height;
      final width = height * imageAspect;
      return Rect.fromLTWH((viewport.width - width) / 2, 0, width, height);
    }
    final width = viewport.width;
    final height = width / imageAspect;
    return Rect.fromLTWH(0, (viewport.height - height) / 2, width, height);
  }

  Rect? _selectionRect(Rect imageRect) {
    final start = _dragStart;
    final current = _dragCurrent;
    if (start == null || current == null) {
      return null;
    }
    return Rect.fromPoints(start, current).intersect(imageRect);
  }

  Offset _clampOffset(Offset offset, Rect bounds) {
    return Offset(
      offset.dx.clamp(bounds.left, bounds.right).toDouble(),
      offset.dy.clamp(bounds.top, bounds.bottom).toDouble(),
    );
  }

  bool _isValidSelection(Rect? selection) {
    return selection != null && selection.width >= 8 && selection.height >= 8;
  }

  void _confirmSelection(Rect imageRect, Rect selection) {
    final scaleX = widget.imageWidth / imageRect.width;
    final scaleY = widget.imageHeight / imageRect.height;
    final x = ((selection.left - imageRect.left) * scaleX)
        .round()
        .clamp(0, widget.imageWidth - 1);
    final y = ((selection.top - imageRect.top) * scaleY)
        .round()
        .clamp(0, widget.imageHeight - 1);
    final width = math.max(
      1,
      (selection.width * scaleX).round().clamp(1, widget.imageWidth - x),
    );
    final height = math.max(
      1,
      (selection.height * scaleY).round().clamp(1, widget.imageHeight - y),
    );
    Navigator.of(context).pop(
      _ScreenRegionSelection(x: x, y: y, width: width, height: height),
    );
  }
}

class _ScreenRegionPainter extends CustomPainter {
  const _ScreenRegionPainter({
    required this.imageRect,
    required this.selectionRect,
  });

  final Rect imageRect;
  final Rect? selectionRect;

  @override
  void paint(Canvas canvas, Size size) {
    final selection = selectionRect;
    final overlay = Paint()..color = Colors.black.withOpacity(0.45);
    final overlayPath = Path()
      ..fillType = PathFillType.evenOdd
      ..addRect(Rect.fromLTWH(0, 0, size.width, size.height));
    if (selection != null) {
      overlayPath.addRect(selection);
    }
    canvas.drawPath(overlayPath, overlay);

    final imageBorder = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1
      ..color = const Color(0xff64748b);
    canvas.drawRect(imageRect, imageBorder);

    if (selection == null) {
      return;
    }

    final border = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2
      ..color = const Color(0xff22c55e);
    canvas.drawRect(selection, border);

    final corner = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 4
      ..strokeCap = StrokeCap.square
      ..color = const Color(0xffbbf7d0);
    const cornerLength = 22.0;
    final points = <Offset, Offset>{
      selection.topLeft: const Offset(1, 1),
      selection.topRight: const Offset(-1, 1),
      selection.bottomLeft: const Offset(1, -1),
      selection.bottomRight: const Offset(-1, -1),
    };
    for (final entry in points.entries) {
      final origin = entry.key;
      final direction = entry.value;
      canvas
        ..drawLine(
          origin,
          origin + Offset(direction.dx * cornerLength, 0),
          corner,
        )
        ..drawLine(
          origin,
          origin + Offset(0, direction.dy * cornerLength),
          corner,
        );
    }
  }

  @override
  bool shouldRepaint(covariant _ScreenRegionPainter oldDelegate) {
    return oldDelegate.imageRect != imageRect ||
        oldDelegate.selectionRect != selectionRect;
  }
}

class _PanelActions extends StatelessWidget {
  const _PanelActions({
    required this.refreshing,
    required this.onRefresh,
    required this.onAddTask,
    required this.onRegisterKey,
    required this.onEdit,
    required this.onDelete,
  });

  final bool refreshing;
  final VoidCallback onRefresh;
  final VoidCallback onAddTask;
  final VoidCallback onRegisterKey;
  final VoidCallback onEdit;
  final VoidCallback onDelete;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: <Widget>[
        IconButton(
          tooltip: '刷新面板会话',
          onPressed: refreshing ? null : onRefresh,
          icon: refreshing
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.refresh),
        ),
        PopupMenuButton<_PanelMenuAction>(
          tooltip: '面板操作',
          onSelected: (action) {
            switch (action) {
              case _PanelMenuAction.addTask:
                onAddTask();
              case _PanelMenuAction.registerKey:
                onRegisterKey();
              case _PanelMenuAction.edit:
                onEdit();
              case _PanelMenuAction.delete:
                onDelete();
            }
          },
          itemBuilder: (context) => const <PopupMenuEntry<_PanelMenuAction>>[
            PopupMenuItem<_PanelMenuAction>(
              value: _PanelMenuAction.addTask,
              child: Text('添加子任务'),
            ),
            PopupMenuItem<_PanelMenuAction>(
              value: _PanelMenuAction.registerKey,
              child: Text('注册 SSH 公钥'),
            ),
            PopupMenuItem<_PanelMenuAction>(
              value: _PanelMenuAction.edit,
              child: Text('编辑面板'),
            ),
            PopupMenuItem<_PanelMenuAction>(
              value: _PanelMenuAction.delete,
              child: Text('删除面板'),
            ),
          ],
        ),
      ],
    );
  }
}

class _PanelTaskDialog extends StatefulWidget {
  const _PanelTaskDialog({
    required this.panel,
    this.template,
    this.existingTaskNames = const <String>{},
  });

  final EmTaskPanelProfile panel;
  final EmTaskSessionProfile? template;
  final Set<String> existingTaskNames;

  @override
  State<_PanelTaskDialog> createState() => _PanelTaskDialogState();
}

class _PanelTaskDialogState extends State<_PanelTaskDialog> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _nameController;
  late final TextEditingController _listenAddressController;
  late final TextEditingController _portController;
  late final TextEditingController _commandController;
  late final TextEditingController _workingDirController;
  var _useSftp = true;
  var _useConpty = true;

  @override
  void initState() {
    super.initState();
    final template = widget.template;
    final templateTaskName = template == null
        ? ''
        : (template.panelTaskName.trim().isNotEmpty
            ? template.panelTaskName.trim()
            : _panelTaskNameFromSessionName(template.name));
    _nameController = TextEditingController(
      text: template == null ? '' : _suggestCopyTaskName(templateTaskName),
    );
    _listenAddressController = TextEditingController(
      text: template?.host.trim() ?? '',
    );
    _portController = TextEditingController(
      text: template == null ? '' : '${template.port}',
    );
    _commandController = TextEditingController(
      text: template?.panelTaskCommand.trim().isNotEmpty == true
          ? template!.panelTaskCommand.trim()
          : Platform.isWindows
              ? 'cmd.exe'
              : '/bin/sh',
    );
    _workingDirController = TextEditingController(
      text: template == null
          ? '.'
          : (template.panelTaskWorkingDir.trim().isEmpty
              ? '.'
              : template.panelTaskWorkingDir.trim()),
    );
    if (template != null) {
      _useSftp = template.supportsSftp;
      _useConpty = template.shellKind == EmTaskShellKind.cmd ||
          template.shellKind == EmTaskShellKind.powershell ||
          (Platform.isWindows && template.shellKind == EmTaskShellKind.auto);
    }
  }

  @override
  void dispose() {
    _nameController.dispose();
    _listenAddressController.dispose();
    _portController.dispose();
    _commandController.dispose();
    _workingDirController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(
        widget.template == null
            ? '添加子任务到 ${widget.panel.name}'
            : '以当前任务为模板新增子任务',
      ),
      content: SizedBox(
        width: 520,
        child: Form(
          key: _formKey,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: <Widget>[
                TextFormField(
                  controller: _nameController,
                  decoration: const InputDecoration(
                    labelText: '子任务名称',
                    hintText: '例如 app-shell',
                  ),
                  validator: (value) {
                    if (value == null || value.trim().isEmpty) {
                      return '请输入子任务名称';
                    }
                    if (widget.existingTaskNames.contains(
                      _EmTaskHomePageState._normalizeTaskNameKey(value),
                    )) {
                      return '子任务名称已存在';
                    }
                    return null;
                  },
                ),
                const SizedBox(height: 12),
                TextFormField(
                  controller: _portController,
                  decoration: const InputDecoration(
                    labelText: 'SSH 监听端口',
                    hintText: '例如 2223',
                  ),
                  keyboardType: TextInputType.number,
                  validator: (value) {
                    final port = int.tryParse(value?.trim() ?? '');
                    if (port == null || port <= 0 || port > 65535) {
                      return '请输入 1-65535 之间的端口';
                    }
                    return null;
                  },
                ),
                const SizedBox(height: 12),
                TextFormField(
                  controller: _commandController,
                  decoration: const InputDecoration(
                    labelText: '启动命令',
                    hintText: '例如 cmd.exe 或 /bin/sh',
                  ),
                  validator: (value) {
                    if (value == null || value.trim().isEmpty) {
                      return '请输入启动命令';
                    }
                    return null;
                  },
                ),
                const SizedBox(height: 12),
                TextFormField(
                  controller: _workingDirController,
                  decoration: const InputDecoration(
                    labelText: '工作目录',
                    hintText: '默认 .',
                  ),
                ),
                const SizedBox(height: 12),
                TextFormField(
                  controller: _listenAddressController,
                  decoration: const InputDecoration(
                    labelText: '监听地址（可选）',
                    hintText: '留空表示 0.0.0.0',
                  ),
                ),
                const SizedBox(height: 12),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('启用 SFTP'),
                  value: _useSftp,
                  onChanged: (value) => setState(() => _useSftp = value),
                ),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('使用 ConPTY（Windows 可选）'),
                  value: _useConpty,
                  onChanged: (value) => setState(() => _useConpty = value),
                ),
              ],
            ),
          ),
        ),
      ),
      actions: <Widget>[
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('取消'),
        ),
        FilledButton(
          onPressed: _submit,
          child: const Text('添加'),
        ),
      ],
    );
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    Navigator.of(context).pop(
      EmTaskPanelCreateTaskRequest(
        name: _nameController.text.trim(),
        port: int.parse(_portController.text.trim()),
        command: _commandController.text.trim(),
        listenAddress: _listenAddressController.text.trim(),
        workingDir: _workingDirController.text.trim().isEmpty
            ? '.'
            : _workingDirController.text.trim(),
        useSftp: _useSftp,
        useConpty: _useConpty,
      ),
    );
  }

  String _suggestCopyTaskName(String baseName) {
    final normalizedBase = baseName.trim().isEmpty ? 'task' : baseName.trim();
    final first = '$normalizedBase-copy';
    if (!widget.existingTaskNames.contains(
      _EmTaskHomePageState._normalizeTaskNameKey(first),
    )) {
      return first;
    }
    for (var index = 2; index < 1000; index += 1) {
      final candidate = '$normalizedBase-copy-$index';
      if (!widget.existingTaskNames.contains(
        _EmTaskHomePageState._normalizeTaskNameKey(candidate),
      )) {
        return candidate;
      }
    }
    return '$normalizedBase-copy-${DateTime.now().millisecondsSinceEpoch}';
  }
}

class _QrScannerPage extends StatefulWidget {
  const _QrScannerPage();

  @override
  State<_QrScannerPage> createState() => _QrScannerPageState();
}

class _QrScannerPageState extends State<_QrScannerPage> {
  final _controller = MobileScannerController(
    formats: const <BarcodeFormat>[BarcodeFormat.qrCode],
  );
  bool _done = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('拍照扫描面板二维码'),
        backgroundColor: const Color(0xff111827),
      ),
      body: Stack(
        children: <Widget>[
          MobileScanner(
            controller: _controller,
            onDetect: (capture) {
              if (_done) {
                return;
              }
              for (final barcode in capture.barcodes) {
                final value = barcode.rawValue;
                if (value != null && value.startsWith('emtask1')) {
                  _done = true;
                  Navigator.of(context).pop(value);
                  return;
                }
              }
            },
          ),
          Positioned.fill(
            child: IgnorePointer(
              child: DecoratedBox(
                decoration: BoxDecoration(
                  border: Border.all(color: const Color(0xff22c55e), width: 3),
                ),
                child: const Center(
                  child: Card(
                    child: Padding(
                      padding: EdgeInsets.all(12),
                      child: Text('对准 emtask 面板二维码'),
                    ),
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _PanelDialog extends StatefulWidget {
  const _PanelDialog({this.panel});

  final EmTaskPanelProfile? panel;

  @override
  State<_PanelDialog> createState() => _PanelDialogState();
}

class _PanelDialogState extends State<_PanelDialog> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _nameController;
  late final TextEditingController _hostController;
  late final TextEditingController _portController;
  late final TextEditingController _tokenController;
  late final TextEditingController _otpSecretController;
  late final TextEditingController _otpDigitsController;
  late final TextEditingController _otpStepController;
  late final TextEditingController _otpWindowController;
  late final TextEditingController _usernameController;
  late final TextEditingController _passwordController;
  late final TextEditingController _privateKeyPathController;
  late final TextEditingController _privateKeyPassphraseController;
  late EmTaskPanelAuthMode _authMode;

  @override
  void initState() {
    super.initState();
    final panel = widget.panel ?? EmTaskPanelProfile.defaults();
    _nameController = TextEditingController(text: panel.name);
    _hostController = TextEditingController(text: panel.host);
    _portController = TextEditingController(text: '${panel.port}');
    _tokenController = TextEditingController(text: panel.token);
    _otpSecretController = TextEditingController(text: panel.otpSecret);
    _otpDigitsController = TextEditingController(text: '${panel.otpDigits}');
    _otpStepController = TextEditingController(text: '${panel.otpStepSeconds}');
    _otpWindowController = TextEditingController(text: '${panel.otpWindow}');
    _usernameController = TextEditingController(text: panel.username);
    _passwordController = TextEditingController(text: panel.password);
    _privateKeyPathController =
        TextEditingController(text: panel.privateKeyPath);
    _privateKeyPassphraseController =
        TextEditingController(text: panel.privateKeyPassphrase);
    _authMode = panel.authMode;
  }

  @override
  void dispose() {
    _nameController.dispose();
    _hostController.dispose();
    _portController.dispose();
    _tokenController.dispose();
    _otpSecretController.dispose();
    _otpDigitsController.dispose();
    _otpStepController.dispose();
    _otpWindowController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    _privateKeyPathController.dispose();
    _privateKeyPassphraseController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final screenSize = MediaQuery.sizeOf(context);
    final dialogWidth = screenSize.width <= 0
        ? 620.0
        : math.min(620.0, math.max(280.0, screenSize.width - 32));
    final dialogHeight = screenSize.height <= 0
        ? 700.0
        : math.min(700.0, math.max(340.0, screenSize.height - 48));

    return Dialog(
      insetPadding: const EdgeInsets.all(16),
      child: SizedBox(
        width: dialogWidth,
        height: dialogHeight,
        child: Column(
          children: <Widget>[
            Padding(
              padding: const EdgeInsets.fromLTRB(22, 18, 22, 12),
              child: Row(
                children: <Widget>[
                  const Icon(Icons.dashboard_outlined),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      widget.panel == null ? '添加面板' : '编辑面板',
                      style: Theme.of(context).textTheme.titleLarge,
                    ),
                  ),
                ],
              ),
            ),
            const Divider(height: 1),
            Expanded(
              child: Form(
                key: _formKey,
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    children: <Widget>[
                      TextFormField(
                        controller: _nameController,
                        decoration: const InputDecoration(labelText: '面板名称'),
                        validator: _required,
                      ),
                      const SizedBox(height: 10),
                      _buildFieldPair(
                        TextFormField(
                          controller: _hostController,
                          decoration:
                              const InputDecoration(labelText: '面板 IP / 主机名'),
                          validator: _required,
                        ),
                        TextFormField(
                          controller: _portController,
                          decoration: const InputDecoration(labelText: '面板端口'),
                          keyboardType: TextInputType.number,
                          validator: _portValidator,
                        ),
                        firstFlex: 2,
                      ),
                      const SizedBox(height: 10),
                      DropdownButtonFormField<EmTaskPanelAuthMode>(
                        value: _authMode,
                        decoration: const InputDecoration(labelText: '面板鉴权'),
                        items: EmTaskPanelAuthMode.values
                            .map(
                              (mode) => DropdownMenuItem<EmTaskPanelAuthMode>(
                                value: mode,
                                child: Text(mode.label),
                              ),
                            )
                            .toList(growable: false),
                        onChanged: (value) {
                          if (value != null) {
                            setState(() => _authMode = value);
                          }
                        },
                      ),
                      if (_authMode.usesToken) ...<Widget>[
                        const SizedBox(height: 10),
                        TextFormField(
                          controller: _tokenController,
                          decoration:
                              const InputDecoration(labelText: 'Panel Token'),
                          validator: _required,
                        ),
                      ],
                      if (_authMode.usesOtp) ...<Widget>[
                        const SizedBox(height: 10),
                        TextFormField(
                          controller: _otpSecretController,
                          decoration:
                              const InputDecoration(labelText: 'OTP Secret'),
                          validator: _required,
                        ),
                        const SizedBox(height: 10),
                        _buildFieldPair(
                          TextFormField(
                            controller: _otpDigitsController,
                            decoration:
                                const InputDecoration(labelText: 'OTP 位数'),
                            keyboardType: TextInputType.number,
                            validator: _positiveIntValidator,
                          ),
                          TextFormField(
                            controller: _otpStepController,
                            decoration:
                                const InputDecoration(labelText: 'OTP 步长秒'),
                            keyboardType: TextInputType.number,
                            validator: _positiveIntValidator,
                          ),
                        ),
                        const SizedBox(height: 10),
                        TextFormField(
                          controller: _otpWindowController,
                          decoration:
                              const InputDecoration(labelText: 'OTP 时间窗口'),
                          keyboardType: TextInputType.number,
                          validator: _nonNegativeIntValidator,
                        ),
                      ],
                      const SizedBox(height: 14),
                      Align(
                        alignment: Alignment.centerLeft,
                        child: Text(
                          'SSH 默认账号',
                          style: Theme.of(context).textTheme.titleSmall,
                        ),
                      ),
                      const SizedBox(height: 10),
                      _buildFieldPair(
                        TextFormField(
                          controller: _usernameController,
                          decoration: const InputDecoration(labelText: '用户名'),
                          validator: _required,
                        ),
                        TextFormField(
                          controller: _passwordController,
                          decoration: const InputDecoration(labelText: '密码'),
                          obscureText: true,
                        ),
                      ),
                      const SizedBox(height: 10),
                      _buildPrivateKeyPicker(),
                      const SizedBox(height: 10),
                      TextFormField(
                        controller: _privateKeyPassphraseController,
                        decoration: const InputDecoration(
                          labelText: '私钥口令',
                          hintText: '私钥未加密可留空',
                        ),
                        obscureText: true,
                      ),
                    ],
                  ),
                ),
              ),
            ),
            const Divider(height: 1),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 10, 16, 12),
              child: OverflowBar(
                alignment: MainAxisAlignment.end,
                spacing: 8,
                children: <Widget>[
                  TextButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: const Text('取消'),
                  ),
                  FilledButton(
                    onPressed: _submit,
                    child: Text(widget.panel == null ? '添加并获取会话' : '保存并刷新'),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  String? _required(String? value) {
    if (value == null || value.trim().isEmpty) {
      return '必填';
    }
    return null;
  }

  String? _portValidator(String? value) {
    final port = int.tryParse(value ?? '');
    if (port == null || port < 1 || port > 65535) {
      return '端口无效';
    }
    return null;
  }

  String? _positiveIntValidator(String? value) {
    final parsed = int.tryParse(value ?? '');
    if (parsed == null || parsed <= 0) {
      return '必须大于 0';
    }
    return null;
  }

  String? _nonNegativeIntValidator(String? value) {
    final parsed = int.tryParse(value ?? '');
    if (parsed == null || parsed < 0) {
      return '不能小于 0';
    }
    return null;
  }

  Widget _buildFieldPair(
    Widget first,
    Widget second, {
    int firstFlex = 1,
    int secondFlex = 1,
  }) {
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 440) {
          return Column(
            children: <Widget>[
              first,
              const SizedBox(height: 10),
              second,
            ],
          );
        }
        return Row(
          children: <Widget>[
            Expanded(flex: firstFlex, child: first),
            const SizedBox(width: 10),
            Expanded(flex: secondFlex, child: second),
          ],
        );
      },
    );
  }

  Widget _buildPrivateKeyPicker() {
    final pathField = TextFormField(
      controller: _privateKeyPathController,
      readOnly: true,
      decoration: const InputDecoration(
        labelText: '默认登录密钥私钥文件',
        hintText: '作为面板会话的默认 SSH 私钥',
      ),
    );
    final buttons = Wrap(
      spacing: 8,
      runSpacing: 8,
      children: <Widget>[
        OutlinedButton.icon(
          onPressed: _pickPrivateKeyFile,
          icon: const Icon(Icons.key_outlined),
          label: const Text('选择私钥'),
        ),
        if (_privateKeyPathController.text.isNotEmpty)
          TextButton.icon(
            onPressed: () {
              setState(() {
                _privateKeyPathController.clear();
                _privateKeyPassphraseController.clear();
              });
            },
            icon: const Icon(Icons.clear),
            label: const Text('清除'),
          ),
      ],
    );

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 560) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              pathField,
              const SizedBox(height: 8),
              buttons,
            ],
          );
        }
        return Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Expanded(child: pathField),
            const SizedBox(width: 10),
            buttons,
          ],
        );
      },
    );
  }

  Future<void> _pickPrivateKeyFile() async {
    final picked = await FilePicker.platform.pickFiles(
      type: FileType.any,
      allowMultiple: false,
    );
    final file = picked?.files.single;
    if (file == null) {
      return;
    }
    final path = file.path;
    if (path == null || path.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('无法获取私钥文件路径，请重新选择本地文件。')),
        );
      }
      return;
    }
    setState(() => _privateKeyPathController.text = path);
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    Navigator.of(context).pop(
      EmTaskPanelProfile.defaults(
        id: widget.panel?.id,
        name: _nameController.text.trim(),
        host: _hostController.text.trim(),
        port: int.parse(_portController.text.trim()),
        authMode: _authMode,
        token: _tokenController.text.trim(),
        otpSecret: _otpSecretController.text.trim(),
        otpDigits: int.tryParse(_otpDigitsController.text.trim()) ?? 6,
        otpStepSeconds: int.tryParse(_otpStepController.text.trim()) ?? 60,
        otpWindow: int.tryParse(_otpWindowController.text.trim()) ?? 1,
        username: _usernameController.text.trim(),
        password: _passwordController.text,
        privateKeyPath: _privateKeyPathController.text.trim(),
        privateKeyPassphrase: _privateKeyPassphraseController.text,
      ),
    );
  }
}

class _PanelTaskStatusDialog extends StatelessWidget {
  const _PanelTaskStatusDialog({required this.profile});

  final EmTaskSessionProfile profile;

  @override
  Widget build(BuildContext context) {
    final failureLog = profile.panelTaskFailureLog.trim();
    return AlertDialog(
      title: Text('子任务状态：${profile.panelTaskName}'),
      content: SizedBox(
        width: 560,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              _StatusLine(label: '状态', value: _statusLabel(profile)),
              _StatusLine(
                label: '监听',
                value: profile.panelTaskListenerOpen ? '已打开' : '未打开/等待重试',
              ),
              _StatusLine(
                label: '终端',
                value: profile.panelTaskTerminalRunning
                    ? '运行中'
                    : profile.panelTaskTerminalFaulted
                        ? '失败'
                        : '未运行',
              ),
              _StatusLine(
                label: '退出码',
                value: '${profile.panelTaskLastExitStatus}',
              ),
              if (profile.panelTaskStatusMessage.trim().isNotEmpty)
                _StatusLine(
                  label: '说明',
                  value: profile.panelTaskStatusMessage.trim(),
                ),
              const SizedBox(height: 12),
              Text(
                '失败日志',
                style: Theme.of(context).textTheme.titleSmall,
              ),
              const SizedBox(height: 6),
              Container(
                width: double.infinity,
                constraints: const BoxConstraints(minHeight: 96),
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: const Color(0xff020617),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: const Color(0xff334155)),
                ),
                child: SelectableText(
                  failureLog.isEmpty ? '暂无失败日志。' : failureLog,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
      actions: <Widget>[
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('关闭'),
        ),
      ],
    );
  }

  static String _statusLabel(EmTaskSessionProfile profile) {
    switch (profile.panelTaskStatus) {
      case 'running':
        return '运行中';
      case 'failed':
        return '失败';
      case 'exited':
        return '已退出';
      case 'pending':
        return '等待启动';
      case 'stopped':
        return '已停止';
      default:
        return profile.panelTaskStatus.isEmpty ? '未知' : profile.panelTaskStatus;
    }
  }
}

class _StatusLine extends StatelessWidget {
  const _StatusLine({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          SizedBox(
            width: 72,
            child: Text(
              label,
              style: Theme.of(context).textTheme.labelMedium,
            ),
          ),
          Expanded(child: SelectableText(value)),
        ],
      ),
    );
  }
}

class _SessionTile extends StatelessWidget {
  const _SessionTile({
    required this.connection,
    required this.onOpen,
    required this.onToggle,
    required this.onEdit,
    this.onShowPanelTaskStatus,
    this.onRerunPanelTask,
    this.onCreatePanelTaskFromTemplate,
    required this.onDelete,
  });

  final EmTaskConnection connection;
  final VoidCallback onOpen;
  final VoidCallback onToggle;
  final VoidCallback onEdit;
  final VoidCallback? onShowPanelTaskStatus;
  final VoidCallback? onRerunPanelTask;
  final VoidCallback? onCreatePanelTaskFromTemplate;
  final VoidCallback onDelete;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    final taskFailed = _isPanelTaskFailed(connection.profile);
    final statusLabel = _panelTaskStatusLabel(connection.profile);
    final borderColor = connection.isConnected
        ? colors.primary.withOpacity(0.72)
        : taskFailed
            ? colors.error.withOpacity(0.75)
            : const Color(0xff1f2937);
    return InkWell(
      onTap: onOpen,
      mouseCursor: connection.isConnected
          ? SystemMouseCursors.click
          : SystemMouseCursors.basic,
      borderRadius: BorderRadius.circular(14),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(14),
          color: connection.isConnected
              ? colors.primary.withOpacity(0.10)
              : taskFailed
                  ? colors.error.withOpacity(0.08)
                  : const Color(0xff0f172a),
          border: Border.all(color: borderColor),
        ),
        child: Row(
          children: <Widget>[
            _UnreadDot(
              visible: connection.hasUnread,
              connected: connection.isConnected,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  Text(
                    connection.profile.name,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                  const SizedBox(height: 3),
                  Text(
                    statusLabel == null
                        ? '${connection.profile.host}:${connection.profile.port}'
                        : '${connection.profile.host}:${connection.profile.port} · $statusLabel',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: taskFailed ? colors.error : null,
                        ),
                  ),
                  const SizedBox(height: 5),
                  Text(
                    _sessionElapsed(connection.lastUpdateAt),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context).textTheme.labelSmall,
                  ),
                  const SizedBox(height: 3),
                  Text(
                    _sessionAccessHint(connection),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context).textTheme.labelSmall?.copyWith(
                          color: connection.isConnected
                              ? colors.primary
                              : const Color(0xff94a3b8),
                        ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8),
            _SessionConnectionButton(
              connection: connection,
              onToggle: onToggle,
            ),
            PopupMenuButton<_SessionMenuAction>(
              tooltip: '会话操作',
              onSelected: (action) {
                switch (action) {
                  case _SessionMenuAction.status:
                    onShowPanelTaskStatus?.call();
                  case _SessionMenuAction.rerun:
                    onRerunPanelTask?.call();
                  case _SessionMenuAction.edit:
                    onEdit();
                  case _SessionMenuAction.createPanelTaskFromTemplate:
                    onCreatePanelTaskFromTemplate?.call();
                  case _SessionMenuAction.delete:
                    onDelete();
                }
              },
              itemBuilder: (context) => <PopupMenuEntry<_SessionMenuAction>>[
                if (onShowPanelTaskStatus != null)
                  const PopupMenuItem<_SessionMenuAction>(
                    value: _SessionMenuAction.status,
                    child: Text('查看子任务状态/失败日志'),
                  ),
                if (onRerunPanelTask != null)
                  const PopupMenuItem<_SessionMenuAction>(
                    value: _SessionMenuAction.rerun,
                    child: Text('重新运行子任务'),
                  ),
                if (onShowPanelTaskStatus != null || onRerunPanelTask != null)
                  const PopupMenuDivider(),
                const PopupMenuItem<_SessionMenuAction>(
                  value: _SessionMenuAction.edit,
                  child: Text('编辑'),
                ),
                if (onCreatePanelTaskFromTemplate != null)
                  const PopupMenuItem<_SessionMenuAction>(
                    value: _SessionMenuAction.createPanelTaskFromTemplate,
                    child: Text('以此为模板新增子任务'),
                  ),
                const PopupMenuItem<_SessionMenuAction>(
                  value: _SessionMenuAction.delete,
                  child: Text('删除'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  static String _sessionAccessHint(EmTaskConnection connection) {
    if (connection.isConnected) {
      return '已连接，点击会话进入终端';
    }
    if (connection.isConnecting) {
      return '正在连接，成功后可进入终端';
    }
    if (connection.status == EmTaskConnectionStatus.error) {
      return '连接失败，点击连接重试';
    }
    if (_isPanelTaskFailed(connection.profile)) {
      return '服务端子任务失败，可在菜单查看日志/重跑';
    }
    return '先连接，成功后可进入终端';
  }

  static bool _isPanelTaskFailed(EmTaskSessionProfile profile) {
    return profile.panelTaskStatus == 'failed' ||
        profile.panelTaskTerminalFaulted;
  }

  static String? _panelTaskStatusLabel(EmTaskSessionProfile profile) {
    if (profile.panelId.trim().isEmpty &&
        profile.panelTaskName.trim().isEmpty) {
      return null;
    }
    switch (profile.panelTaskStatus) {
      case 'running':
        return '运行中';
      case 'failed':
        return '失败';
      case 'exited':
        return '已退出(${profile.panelTaskLastExitStatus})';
      case 'pending':
        return '等待启动';
      case 'stopped':
        return '已停止';
      default:
        if (profile.panelTaskTerminalRunning) {
          return '运行中';
        }
        if (profile.panelTaskTerminalFaulted) {
          return '失败';
        }
        return profile.panelTaskListenerOpen ? '监听中' : '状态未知';
    }
  }
}

class _SessionConnectionButton extends StatelessWidget {
  const _SessionConnectionButton({
    required this.connection,
    required this.onToggle,
  });

  final EmTaskConnection connection;
  final VoidCallback onToggle;

  @override
  Widget build(BuildContext context) {
    final label = connection.isConnecting
        ? '连接中'
        : connection.isConnected
            ? '断开'
            : '连接';
    final icon = connection.isConnecting
        ? const SizedBox(
            width: 16,
            height: 16,
            child: CircularProgressIndicator(strokeWidth: 2),
          )
        : Icon(connection.isConnected ? Icons.link_off : Icons.link);
    return FilledButton.tonalIcon(
      onPressed: connection.isConnecting ? null : onToggle,
      icon: icon,
      label: Text(label),
      style: FilledButton.styleFrom(
        minimumSize: const Size(92, 38),
        padding: const EdgeInsets.symmetric(horizontal: 10),
      ),
    );
  }
}

class _UnreadDot extends StatelessWidget {
  const _UnreadDot({required this.visible, required this.connected});

  final bool visible;
  final bool connected;

  @override
  Widget build(BuildContext context) {
    final color = visible
        ? const Color(0xff22c55e)
        : connected
            ? const Color(0xff64748b)
            : const Color(0xff334155);
    return AnimatedContainer(
      duration: const Duration(milliseconds: 220),
      width: visible ? 14 : 10,
      height: visible ? 14 : 10,
      decoration: BoxDecoration(
        color: color,
        shape: BoxShape.circle,
        boxShadow: visible
            ? <BoxShadow>[
                BoxShadow(
                  color: color.withOpacity(0.55),
                  blurRadius: 12,
                  spreadRadius: 2,
                ),
              ]
            : null,
      ),
    );
  }
}

class _InlineError extends StatelessWidget {
  const _InlineError({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: const Color(0xff7f1d1d).withOpacity(0.24),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xffef4444).withOpacity(0.35)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          const Icon(Icons.error_outline, size: 18, color: Color(0xfffca5a5)),
          const SizedBox(width: 8),
          Expanded(child: Text(message)),
        ],
      ),
    );
  }
}

class _SftpPlaceholder extends StatelessWidget {
  const _SftpPlaceholder({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: const Color(0xff020617),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0xff1f2937)),
      ),
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Text(
            message,
            textAlign: TextAlign.center,
          ),
        ),
      ),
    );
  }
}

enum _TerminalShortcutKey {
  tab,
  left,
  up,
  down,
  right,
}

class _TerminalShortcutBar extends StatelessWidget {
  const _TerminalShortcutBar({
    required this.enabled,
    required this.ctrlActive,
    required this.shiftActive,
    required this.altActive,
    required this.onToggleCtrl,
    required this.onToggleShift,
    required this.onToggleAlt,
    required this.onSend,
  });

  final bool enabled;
  final bool ctrlActive;
  final bool shiftActive;
  final bool altActive;
  final VoidCallback onToggleCtrl;
  final VoidCallback onToggleShift;
  final VoidCallback onToggleAlt;
  final void Function(_TerminalShortcutKey key) onSend;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: const Color(0xee0f172a),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xff334155)),
        boxShadow: const <BoxShadow>[
          BoxShadow(
            color: Color(0x66000000),
            blurRadius: 18,
            offset: Offset(0, 8),
          ),
        ],
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
        child: Row(
          children: <Widget>[
            _ShortcutToggleChip(
              label: 'CTRL',
              selected: ctrlActive,
              enabled: enabled,
              onPressed: onToggleCtrl,
            ),
            _ShortcutToggleChip(
              label: 'Shift',
              selected: shiftActive,
              enabled: enabled,
              onPressed: onToggleShift,
            ),
            _ShortcutToggleChip(
              label: 'Alt',
              selected: altActive,
              enabled: enabled,
              onPressed: onToggleAlt,
            ),
            const SizedBox(width: 8),
            _ShortcutActionChip(
              label: 'Tab',
              enabled: enabled,
              onPressed: () => onSend(_TerminalShortcutKey.tab),
            ),
            _ShortcutActionChip(
              label: '←',
              tooltip: '左键',
              enabled: enabled,
              onPressed: () => onSend(_TerminalShortcutKey.left),
            ),
            _ShortcutActionChip(
              label: '↑',
              tooltip: '上键',
              enabled: enabled,
              onPressed: () => onSend(_TerminalShortcutKey.up),
            ),
            _ShortcutActionChip(
              label: '↓',
              tooltip: '下键',
              enabled: enabled,
              onPressed: () => onSend(_TerminalShortcutKey.down),
            ),
            _ShortcutActionChip(
              label: '→',
              tooltip: '右键',
              enabled: enabled,
              onPressed: () => onSend(_TerminalShortcutKey.right),
            ),
          ],
        ),
      ),
    );
  }
}

class _ShortcutToggleChip extends StatelessWidget {
  const _ShortcutToggleChip({
    required this.label,
    required this.selected,
    required this.enabled,
    required this.onPressed,
  });

  final String label;
  final bool selected;
  final bool enabled;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 3),
      child: FilterChip(
        label: Text(label),
        selected: selected,
        showCheckmark: false,
        onSelected: enabled ? (_) => onPressed() : null,
      ),
    );
  }
}

class _ShortcutActionChip extends StatelessWidget {
  const _ShortcutActionChip({
    required this.label,
    required this.enabled,
    required this.onPressed,
    this.tooltip,
  });

  final String label;
  final String? tooltip;
  final bool enabled;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    final button = Padding(
      padding: const EdgeInsets.symmetric(horizontal: 3),
      child: OutlinedButton(
        style: OutlinedButton.styleFrom(
          minimumSize: const Size(46, 36),
          padding: const EdgeInsets.symmetric(horizontal: 12),
        ),
        onPressed: enabled ? onPressed : null,
        child: Text(label),
      ),
    );
    if (tooltip == null) {
      return button;
    }
    return Tooltip(message: tooltip!, child: button);
  }
}

String _defaultClientUpdatePattern() {
  if (Platform.isWindows) {
    return 'emtask-client-windows-x64*';
  }
  if (Platform.isLinux) {
    return 'emtask-client-linux-x64*';
  }
  if (Platform.isAndroid) {
    return 'emtask-client-android*';
  }
  return 'emtask-client-*';
}

class _SettingsPage extends StatefulWidget {
  const _SettingsPage({
    required this.settings,
    required this.onChanged,
  });

  final EmTaskClientSettings settings;
  final ValueChanged<EmTaskClientSettings> onChanged;

  @override
  State<_SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<_SettingsPage> {
  late EmTaskClientSettings _settings;

  @override
  void initState() {
    super.initState();
    _settings = widget.settings;
  }

  void _updateSettings(EmTaskClientSettings settings) {
    setState(() => _settings = settings);
    widget.onChanged(settings);
  }

  @override
  Widget build(BuildContext context) {
    final layout = _layoutForWidth(MediaQuery.sizeOf(context).width);
    return Scaffold(
      appBar: AppBar(
        title: const Text('设置'),
        backgroundColor: const Color(0xff111827),
      ),
      body: SafeArea(
        child: ListView(
          padding: layout.pagePadding,
          children: <Widget>[
            _SettingsSectionCard(
              icon: Icons.keyboard_outlined,
              title: '启动快捷键',
              subtitle: '在终端底部显示 CTRL、Shift、Alt、Tab 和方向键，方便移动端输入组合键。',
              child: Column(
                children: <Widget>[
                  SwitchListTile.adaptive(
                    contentPadding: EdgeInsets.zero,
                    value: _settings.shortcutKeysEnabled,
                    onChanged: (value) => _updateSettings(
                      _settings.copyWith(shortcutKeysEnabled: value),
                    ),
                    title: const Text('显示终端快捷键栏'),
                    subtitle: const Text('启用后进入终端页可点击按键发送 Tab、方向键或组合键。'),
                  ),
                  const Divider(height: 1),
                  SwitchListTile.adaptive(
                    contentPadding: EdgeInsets.zero,
                    value: _settings.terminalKeyboardButtonOnly,
                    onChanged: (value) => _updateSettings(
                      _settings.copyWith(terminalKeyboardButtonOnly: value),
                    ),
                    title: const Text('手动打开终端键盘'),
                    subtitle: const Text(
                      '启用后点击终端不会自动弹出软键盘，只有点击终端页键盘按钮才允许输入。',
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
            _SettingsSectionCard(
              icon: Icons.folder_open_outlined,
              title: 'SFTP 文件预览',
              subtitle: '小于等于阈值的 UTF-8 文本会完整加载并允许编辑；超过阈值的大文件按 64KB 分页读取。',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  DropdownButtonFormField<int>(
                    value: _sftpSmallFileThresholdValue(
                      _settings.sftpSmallFileBytes,
                    ),
                    decoration: const InputDecoration(
                      labelText: '小文件阈值',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                    items: _sftpSmallFileThresholdOptions
                        .map(
                          (value) => DropdownMenuItem<int>(
                            value: value,
                            child: Text(_formatBytes(value)),
                          ),
                        )
                        .toList(growable: false),
                    onChanged: (value) {
                      if (value == null) {
                        return;
                      }
                      _updateSettings(
                        _settings.copyWith(sftpSmallFileBytes: value),
                      );
                    },
                  ),
                  const SizedBox(height: 12),
                  DropdownButtonFormField<int>(
                    value: _sftpPreviewHeightValue(
                      _settings.sftpPreviewHeight,
                    ),
                    decoration: const InputDecoration(
                      labelText: '预览框高度',
                      helperText: '移动端上下布局时生效；增大后页面可上下滚动。',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                    items: _sftpPreviewHeightOptions
                        .map(
                          (value) => DropdownMenuItem<int>(
                            value: value,
                            child: Text('$value px'),
                          ),
                        )
                        .toList(growable: false),
                    onChanged: (value) {
                      if (value == null) {
                        return;
                      }
                      _updateSettings(
                        _settings.copyWith(sftpPreviewHeight: value),
                      );
                    },
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
            const _AboutSettingsCard(),
          ],
        ),
      ),
    );
  }
}

const List<int> _sftpSmallFileThresholdOptions = <int>[
  64 * 1024,
  128 * 1024,
  256 * 1024,
  512 * 1024,
  1024 * 1024,
  2 * 1024 * 1024,
  4 * 1024 * 1024,
];

const List<int> _sftpPreviewHeightOptions = <int>[
  420,
  520,
  640,
  760,
  900,
  1100,
  1400,
];

int _sftpSmallFileThresholdValue(int value) {
  return _sftpSmallFileThresholdOptions.contains(value)
      ? value
      : EmTaskClientSettings.defaultSftpSmallFileBytes;
}

int _sftpPreviewHeightValue(int value) {
  return _sftpPreviewHeightOptions.contains(value)
      ? value
      : EmTaskClientSettings.defaultSftpPreviewHeight;
}

class _SettingsSectionCard extends StatelessWidget {
  const _SettingsSectionCard({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.child,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Icon(icon, size: 24),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text(
                        title,
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        subtitle,
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            child,
          ],
        ),
      ),
    );
  }
}

class _AboutSettingsCard extends StatelessWidget {
  const _AboutSettingsCard();

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Row(
              children: <Widget>[
                Image.asset(
                  'assets/icons/emtask_icon.png',
                  width: 42,
                  height: 42,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text(
                        '关于',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 4),
                      const Text('$_appDisplayName · v$_appVersion'),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 14),
            const Text('跨平台 emtask SSH / SFTP 客户端。'),
            const SizedBox(height: 8),
            Text(
              '支持 Android、Windows、Linux、macOS、iOS，多会话连接、终端输入、SFTP 文件查看/编辑和面板二维码导入。',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState({required this.onCreate});

  final VoidCallback onCreate;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: <Widget>[
              const Icon(Icons.terminal, size: 56),
              const SizedBox(height: 16),
              Text(
                '还没有 emtask 会话',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 8),
              const Text('新建一个 IP/端口会话后即可后台连接。'),
              const SizedBox(height: 18),
              FilledButton.icon(
                onPressed: onCreate,
                icon: const Icon(Icons.add),
                label: const Text('新建会话'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _ProfileDialog extends StatefulWidget {
  const _ProfileDialog({this.profile, this.isPanelSession = false});

  final EmTaskSessionProfile? profile;
  final bool isPanelSession;

  @override
  State<_ProfileDialog> createState() => _ProfileDialogState();
}

class _ProfileDialogState extends State<_ProfileDialog> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _nameController;
  late final TextEditingController _hostController;
  late final TextEditingController _portController;
  late final TextEditingController _usernameController;
  late final TextEditingController _passwordController;
  late final TextEditingController _privateKeyPathController;
  late final TextEditingController _privateKeyPassphraseController;
  late final TextEditingController _pathController;
  late final TextEditingController _panelCommandController;
  late final TextEditingController _panelWorkingDirController;
  late final EmTaskShellKind _shellKind;
  late bool _supportsSftp;
  late bool _syncPanelHost;
  late bool _syncPanelPort;
  late bool _syncPanelCredentials;
  late bool _syncPanelPrivateKey;
  late bool _syncPanelCommand;
  late bool _syncPanelWorkingDir;
  late bool _syncPanelSftp;

  @override
  void initState() {
    super.initState();
    final profile = widget.profile ??
        EmTaskSessionProfile.defaults(id: EmTaskSessionProfile.newId());
    _nameController = TextEditingController(text: profile.name);
    _hostController = TextEditingController(text: profile.host);
    _portController = TextEditingController(text: '${profile.port}');
    _usernameController = TextEditingController(text: profile.username);
    _passwordController = TextEditingController(text: profile.password);
    _privateKeyPathController =
        TextEditingController(text: profile.privateKeyPath);
    _privateKeyPassphraseController =
        TextEditingController(text: profile.privateKeyPassphrase);
    _pathController = TextEditingController(text: profile.initialPath);
    _panelCommandController =
        TextEditingController(text: profile.panelTaskCommand);
    _panelWorkingDirController = TextEditingController(
      text: profile.panelTaskWorkingDir.trim().isEmpty
          ? '.'
          : profile.panelTaskWorkingDir,
    );
    _shellKind = profile.shellKind;
    _supportsSftp = profile.supportsSftp;
    _syncPanelHost = profile.panelTaskSyncHost;
    _syncPanelPort = profile.panelTaskSyncPort;
    _syncPanelCredentials = profile.panelTaskSyncCredentials;
    _syncPanelPrivateKey = profile.panelTaskSyncPrivateKey;
    _syncPanelCommand = profile.panelTaskSyncCommand;
    _syncPanelWorkingDir = profile.panelTaskSyncWorkingDir;
    _syncPanelSftp = profile.panelTaskSyncSftp;
  }

  @override
  void dispose() {
    _nameController.dispose();
    _hostController.dispose();
    _portController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    _privateKeyPathController.dispose();
    _privateKeyPassphraseController.dispose();
    _pathController.dispose();
    _panelCommandController.dispose();
    _panelWorkingDirController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final screenSize = MediaQuery.sizeOf(context);
    final dialogWidth = screenSize.width <= 0
        ? 560.0
        : math.min(560.0, math.max(260.0, screenSize.width - 32));
    final dialogHeight = screenSize.height <= 0
        ? 640.0
        : math.min(640.0, math.max(300.0, screenSize.height - 48));

    return Dialog(
      insetPadding: const EdgeInsets.all(16),
      child: SizedBox(
        width: dialogWidth,
        height: dialogHeight,
        child: Column(
          children: <Widget>[
            Padding(
              padding: const EdgeInsets.fromLTRB(22, 18, 22, 12),
              child: Row(
                children: <Widget>[
                  Icon(widget.profile == null ? Icons.add : Icons.edit),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      widget.profile == null ? '新增会话' : '编辑会话',
                      style: Theme.of(context).textTheme.titleLarge,
                    ),
                  ),
                ],
              ),
            ),
            const Divider(height: 1),
            Expanded(
              child: Form(
                key: _formKey,
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: <Widget>[
                      TextFormField(
                        controller: _nameController,
                        decoration: InputDecoration(
                          labelText: '名称',
                          helperText: widget.isPanelSession
                              ? '服务端任务名是唯一标识，不会通过编辑会话同步修改。'
                              : null,
                        ),
                        validator: _required,
                      ),
                      const SizedBox(height: 10),
                      _buildFieldPair(
                        TextFormField(
                          controller: _hostController,
                          decoration:
                              const InputDecoration(labelText: 'IP / 主机名'),
                          validator: _required,
                        ),
                        TextFormField(
                          controller: _portController,
                          decoration: const InputDecoration(labelText: '端口'),
                          keyboardType: TextInputType.number,
                          validator: (value) {
                            final port = int.tryParse(value ?? '');
                            if (port == null || port < 1 || port > 65535) {
                              return '端口无效';
                            }
                            return null;
                          },
                        ),
                        firstFlex: 2,
                      ),
                      if (widget.isPanelSession)
                        _buildPanelSyncSwitch(
                          title: 'IP / 主机名同步到服务端',
                          value: _syncPanelHost,
                          onChanged: (value) =>
                              setState(() => _syncPanelHost = value),
                        ),
                      if (widget.isPanelSession)
                        _buildPanelSyncSwitch(
                          title: '端口同步到服务端',
                          value: _syncPanelPort,
                          onChanged: (value) =>
                              setState(() => _syncPanelPort = value),
                        ),
                      const SizedBox(height: 10),
                      _buildFieldPair(
                        TextFormField(
                          controller: _usernameController,
                          decoration: const InputDecoration(labelText: '用户名'),
                          validator: _required,
                        ),
                        TextFormField(
                          controller: _passwordController,
                          decoration:
                              const InputDecoration(labelText: '密码 / 键盘口令'),
                          obscureText: true,
                        ),
                      ),
                      if (widget.isPanelSession)
                        _buildPanelSyncSwitch(
                          title: '用户名 / 密码同步到面板默认账号',
                          subtitle: '勾选后保存为面板默认 SSH 账号；刷新面板会用默认账号覆盖此会话。',
                          value: _syncPanelCredentials,
                          onChanged: (value) => setState(
                            () => _syncPanelCredentials = value,
                          ),
                        ),
                      const SizedBox(height: 10),
                      _buildPrivateKeyPicker(),
                      const SizedBox(height: 10),
                      TextFormField(
                        controller: _privateKeyPassphraseController,
                        decoration: const InputDecoration(
                          labelText: '私钥口令',
                          hintText: '私钥未加密可留空',
                        ),
                        obscureText: true,
                      ),
                      if (widget.isPanelSession)
                        _buildPanelSyncSwitch(
                          title: '登录密钥同步到面板默认密钥',
                          subtitle: '勾选后保存为面板默认 SSH 私钥；刷新面板会用默认密钥覆盖此会话。',
                          value: _syncPanelPrivateKey,
                          onChanged: (value) => setState(
                            () => _syncPanelPrivateKey = value,
                          ),
                        ),
                      const SizedBox(height: 8),
                      Align(
                        alignment: Alignment.centerLeft,
                        child: Text(
                          '可选择 OpenSSH/RSA 私钥文件；若同时填写密码，会在密钥认证不可用时继续尝试密码或键盘交互认证。',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ),
                      const SizedBox(height: 10),
                      TextFormField(
                        controller: _pathController,
                        decoration: const InputDecoration(
                          labelText: '默认 SFTP 路径',
                          hintText: '`.` 表示任务工作路径，例如 logs',
                        ),
                        validator: _sftpPathValidator,
                      ),
                      const SizedBox(height: 8),
                      Align(
                        alignment: Alignment.centerLeft,
                        child: Text(
                          '文件查看使用 SFTP；路径只能位于任务工作路径内，不能填写本机绝对路径或 .. 上级路径。',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ),
                      const SizedBox(height: 10),
                      SwitchListTile.adaptive(
                        contentPadding: EdgeInsets.zero,
                        value: _supportsSftp,
                        onChanged: (value) {
                          setState(() => _supportsSftp = value);
                        },
                        title: const Text('支持 SFTP'),
                        subtitle: const Text(
                          '勾选后终端页右上角显示 SFTP 入口；服务端任务配置也需要 use_sftp = true。',
                        ),
                      ),
                      if (widget.isPanelSession) ...<Widget>[
                        _buildPanelSyncSwitch(
                          title: 'SFTP 支持同步到服务端',
                          value: _syncPanelSftp,
                          onChanged: (value) =>
                              setState(() => _syncPanelSftp = value),
                        ),
                        const Divider(height: 28),
                        Align(
                          alignment: Alignment.centerLeft,
                          child: Text(
                            '服务端任务字段',
                            style: Theme.of(context).textTheme.titleSmall,
                          ),
                        ),
                        const SizedBox(height: 8),
                        TextFormField(
                          controller: _panelCommandController,
                          decoration: const InputDecoration(
                            labelText: '服务端命令 command',
                            hintText: '例如 cmd.exe、powershell、bash',
                          ),
                          validator: (value) {
                            final nextCommand = value?.trim() ?? '';
                            final previousCommand =
                                widget.profile?.panelTaskCommand.trim() ?? '';
                            if (_syncPanelCommand &&
                                nextCommand.isEmpty &&
                                previousCommand.isNotEmpty) {
                              return '同步命令时不能为空';
                            }
                            return null;
                          },
                        ),
                        _buildPanelSyncSwitch(
                          title: '命令同步到服务端',
                          value: _syncPanelCommand,
                          onChanged: (value) =>
                              setState(() => _syncPanelCommand = value),
                        ),
                        const SizedBox(height: 10),
                        TextFormField(
                          controller: _panelWorkingDirController,
                          decoration: const InputDecoration(
                            labelText: '服务端工作目录 working_dir',
                            hintText: '. 表示 emtask 工作目录',
                          ),
                        ),
                        _buildPanelSyncSwitch(
                          title: '工作目录同步到服务端',
                          value: _syncPanelWorkingDir,
                          onChanged: (value) =>
                              setState(() => _syncPanelWorkingDir = value),
                        ),
                        Align(
                          alignment: Alignment.centerLeft,
                          child: Text(
                            '未勾选同步的字段：保存时只修改本机；以后刷新面板时服务端值也不会覆盖这个字段。',
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ),
            const Divider(height: 1),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 10, 16, 12),
              child: OverflowBar(
                alignment: MainAxisAlignment.end,
                spacing: 8,
                children: <Widget>[
                  TextButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: const Text('取消'),
                  ),
                  FilledButton(
                    onPressed: _submit,
                    child: const Text('保存'),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  String? _required(String? value) {
    if (value == null || value.trim().isEmpty) {
      return '必填';
    }
    return null;
  }

  String? _sftpPathValidator(String? value) {
    try {
      EmTaskConnection.normalizeSftpVirtualPath(value ?? '.');
      return null;
    } catch (error) {
      return _formatError(error);
    }
  }

  Widget _buildFieldPair(
    Widget first,
    Widget second, {
    int firstFlex = 1,
    int secondFlex = 1,
  }) {
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 440) {
          return Column(
            children: <Widget>[
              first,
              const SizedBox(height: 10),
              second,
            ],
          );
        }
        return Row(
          children: <Widget>[
            Expanded(flex: firstFlex, child: first),
            const SizedBox(width: 10),
            Expanded(flex: secondFlex, child: second),
          ],
        );
      },
    );
  }

  Widget _buildPanelSyncSwitch({
    required String title,
    required bool value,
    required ValueChanged<bool> onChanged,
    String subtitle = '不勾选时不上传到服务端，刷新面板也不会覆盖此项。',
  }) {
    return CheckboxListTile(
      contentPadding: EdgeInsets.zero,
      dense: true,
      value: value,
      onChanged: (value) => onChanged(value ?? false),
      controlAffinity: ListTileControlAffinity.leading,
      title: Text(title),
      subtitle: Text(subtitle),
    );
  }

  Widget _buildPrivateKeyPicker() {
    final pathField = TextFormField(
      controller: _privateKeyPathController,
      readOnly: true,
      decoration: const InputDecoration(
        labelText: '登录密钥私钥文件',
        hintText: '例如 id_rsa、id_ed25519 或 OpenSSH 私钥',
      ),
    );
    final buttons = Wrap(
      spacing: 8,
      runSpacing: 8,
      children: <Widget>[
        OutlinedButton.icon(
          onPressed: _pickPrivateKeyFile,
          icon: const Icon(Icons.key_outlined),
          label: const Text('选择私钥'),
        ),
        if (_privateKeyPathController.text.isNotEmpty)
          TextButton.icon(
            onPressed: () {
              setState(() {
                _privateKeyPathController.clear();
                _privateKeyPassphraseController.clear();
              });
            },
            icon: const Icon(Icons.clear),
            label: const Text('清除'),
          ),
      ],
    );

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 560) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              pathField,
              const SizedBox(height: 8),
              buttons,
            ],
          );
        }
        return Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Expanded(child: pathField),
            const SizedBox(width: 10),
            buttons,
          ],
        );
      },
    );
  }

  Future<void> _pickPrivateKeyFile() async {
    final picked = await FilePicker.platform.pickFiles(
      type: FileType.any,
      allowMultiple: false,
    );
    final file = picked?.files.single;
    if (file == null) {
      return;
    }
    final path = file.path;
    if (path == null || path.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('无法获取私钥文件路径，请重新选择本地文件。')),
        );
      }
      return;
    }
    setState(() => _privateKeyPathController.text = path);
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    final original = widget.profile;
    final panelTaskName = widget.isPanelSession
        ? (original?.panelTaskName.trim().isNotEmpty == true
            ? original!.panelTaskName
            : _panelTaskNameFromSessionName(_nameController.text))
        : (original?.panelTaskName ?? '');
    Navigator.of(context).pop(
      EmTaskSessionProfile(
        id: original?.id ?? EmTaskSessionProfile.newId(),
        name: _nameController.text.trim(),
        host: _hostController.text.trim(),
        port: int.parse(_portController.text.trim()),
        username: _usernameController.text.trim(),
        password: _passwordController.text,
        privateKeyPath: _privateKeyPathController.text.trim(),
        privateKeyPassphrase: _privateKeyPassphraseController.text,
        shellKind: _shellKind,
        initialPath:
            EmTaskConnection.normalizeSftpVirtualPath(_pathController.text),
        supportsSftp: _supportsSftp,
        panelId: original?.panelId ?? '',
        panelTaskName: panelTaskName,
        panelTaskCommand: widget.isPanelSession
            ? _panelCommandController.text.trim()
            : (original?.panelTaskCommand ?? ''),
        panelTaskWorkingDir: widget.isPanelSession
            ? (_panelWorkingDirController.text.trim().isEmpty
                ? '.'
                : _panelWorkingDirController.text.trim())
            : (original?.panelTaskWorkingDir ?? '.'),
        panelTaskSyncName: widget.isPanelSession ? false : true,
        panelTaskSyncHost: widget.isPanelSession ? _syncPanelHost : true,
        panelTaskSyncPort: widget.isPanelSession ? _syncPanelPort : true,
        panelTaskSyncCredentials:
            widget.isPanelSession ? _syncPanelCredentials : true,
        panelTaskSyncPrivateKey:
            widget.isPanelSession ? _syncPanelPrivateKey : false,
        panelTaskSyncCommand: widget.isPanelSession ? _syncPanelCommand : true,
        panelTaskSyncWorkingDir:
            widget.isPanelSession ? _syncPanelWorkingDir : true,
        panelTaskSyncSftp: widget.isPanelSession ? _syncPanelSftp : true,
        panelTaskStatus: original?.panelTaskStatus ?? 'unknown',
        panelTaskStatusMessage: original?.panelTaskStatusMessage ?? '',
        panelTaskFailureLog: original?.panelTaskFailureLog ?? '',
        panelTaskListenerOpen: original?.panelTaskListenerOpen ?? false,
        panelTaskTerminalRunning: original?.panelTaskTerminalRunning ?? false,
        panelTaskTerminalFaulted: original?.panelTaskTerminalFaulted ?? false,
        panelTaskLastExitStatus: original?.panelTaskLastExitStatus ?? 0,
      ),
    );
  }
}

String _sessionElapsed(DateTime? time) {
  if (time == null) {
    return '还没有内容更新';
  }
  final elapsed = DateTime.now().difference(time);
  if (elapsed.inSeconds < 5) {
    return '内容刚刚更新';
  }
  if (elapsed.inMinutes < 1) {
    return '内容更新于 ${elapsed.inSeconds} 秒前';
  }
  if (elapsed.inHours < 1) {
    return '内容更新于 ${elapsed.inMinutes} 分钟前';
  }
  return '内容更新于 ${elapsed.inHours} 小时前';
}

String _panelTaskNameFromSessionName(String name) {
  final trimmed = name.trim();
  if (trimmed.contains('/')) {
    final last = trimmed.split('/').last.trim();
    if (last.isNotEmpty) {
      return last;
    }
  }
  return trimmed;
}

String _formatError(Object error) {
  return error
      .toString()
      .replaceFirst('Bad state: ', '')
      .replaceFirst('StateError: ', '');
}

@visibleForTesting
String terminalInputWithModifiersForTest(
  String data, {
  required bool ctrl,
  required bool shift,
  required bool alt,
}) {
  return _terminalInputWithModifiers(
    data,
    ctrl: ctrl,
    shift: shift,
    alt: alt,
  );
}

String _terminalInputWithModifiers(
  String data, {
  required bool ctrl,
  required bool shift,
  required bool alt,
}) {
  if (data.isEmpty) {
    return data;
  }

  final buffer = StringBuffer();
  for (final codeUnit in data.codeUnits) {
    var output = String.fromCharCode(codeUnit);
    if (shift && codeUnit >= 0x61 && codeUnit <= 0x7a) {
      output = String.fromCharCode(codeUnit - 0x20);
    }
    if (ctrl) {
      final ctrlCode = _ctrlCodeUnit(output.codeUnitAt(0));
      if (ctrlCode != null) {
        output = String.fromCharCode(ctrlCode);
      }
    }
    if (alt) {
      buffer.write('\x1b');
    }
    buffer.write(output);
  }
  return buffer.toString();
}

int? _ctrlCodeUnit(int codeUnit) {
  if (codeUnit >= 0x61 && codeUnit <= 0x7a) {
    return codeUnit - 0x60;
  }
  if (codeUnit >= 0x41 && codeUnit <= 0x5a) {
    return codeUnit - 0x40;
  }
  switch (codeUnit) {
    case 0x40: // @
      return 0x00;
    case 0x5b: // [
      return 0x1b;
    case 0x5c: // \
      return 0x1c;
    case 0x5d: // ]
      return 0x1d;
    case 0x5e: // ^
      return 0x1e;
    case 0x5f: // _
      return 0x1f;
    case 0x3f: // ?
      return 0x7f;
  }
  return null;
}

String _formatBytes(int? value) {
  if (value == null) {
    return '未知大小';
  }
  if (value < 1024) {
    return '$value B';
  }
  if (value < 1024 * 1024) {
    return '${(value / 1024).toStringAsFixed(1)} KB';
  }
  return '${(value / 1024 / 1024).toStringAsFixed(1)} MB';
}

String _formatDateTime(DateTime value) {
  String two(int item) => item.toString().padLeft(2, '0');
  return '${value.year}-${two(value.month)}-${two(value.day)} '
      '${two(value.hour)}:${two(value.minute)}';
}

String _parentSftpPath(String path) {
  final value = EmTaskConnection.normalizeSftpVirtualPath(path);
  if (value == '.') {
    return '.';
  }
  final slash = value.lastIndexOf('/');
  if (slash <= 0) {
    return '.';
  }
  return value.substring(0, slash);
}

String _joinSftpChildPath(String directory, String name) {
  final base = EmTaskConnection.normalizeSftpVirtualPath(directory);
  if (base == '.') {
    return name;
  }
  return '$base/$name';
}

bool _isValidSftpChildName(String name) {
  return name.isNotEmpty &&
      name != '.' &&
      name != '..' &&
      !name.contains('/') &&
      !name.contains('\\') &&
      !name.contains(':') &&
      !name.contains('\u0000');
}

bool _isSftpPathUnder(String path, String directoryPath) {
  final normalizedPath = EmTaskConnection.normalizeSftpVirtualPath(path);
  final normalizedDirectory =
      EmTaskConnection.normalizeSftpVirtualPath(directoryPath);
  if (normalizedPath == normalizedDirectory) {
    return true;
  }
  if (normalizedDirectory == '.') {
    return normalizedPath != '.';
  }
  return normalizedPath.startsWith('$normalizedDirectory/');
}

String? _replaceSftpPathPrefix(String path, String oldPath, String newPath) {
  final normalizedPath = EmTaskConnection.normalizeSftpVirtualPath(path);
  final normalizedOldPath = EmTaskConnection.normalizeSftpVirtualPath(oldPath);
  final normalizedNewPath = EmTaskConnection.normalizeSftpVirtualPath(newPath);
  if (normalizedPath == normalizedOldPath) {
    return normalizedNewPath;
  }
  final oldPrefix = '$normalizedOldPath/';
  if (!normalizedPath.startsWith(oldPrefix)) {
    return null;
  }
  return '$normalizedNewPath/${normalizedPath.substring(oldPrefix.length)}';
}

String _safeInitialSftpPath(String path) {
  try {
    return EmTaskConnection.normalizeSftpVirtualPath(path);
  } catch (_) {
    return '.';
  }
}
