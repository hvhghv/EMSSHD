import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:image/image.dart' as img;
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:xterm/xterm.dart';
import 'package:zxing2/qrcode.dart' as zxing;

import 'src/emtask_connection.dart';
import 'src/models.dart';
import 'src/panel_client.dart';
import 'src/profile_store.dart';
import 'src/windows_screen_capture.dart';

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

  List<EmTaskConnection> _connections = <EmTaskConnection>[];
  List<EmTaskPanelProfile> _panels = <EmTaskPanelProfile>[];
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
    if (!mounted) {
      return;
    }
    setState(() {
      _connections = profiles.map(EmTaskConnection.new).toList();
      _panels = panels;
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

  Future<void> _addOrEditProfile({EmTaskConnection? connection}) async {
    final profile = await showDialog<EmTaskSessionProfile>(
      context: context,
      builder: (context) => _ProfileDialog(profile: connection?.profile),
    );
    if (profile == null) {
      return;
    }

    setState(() {
      if (connection == null) {
        _connections.add(EmTaskConnection(profile));
      } else {
        connection.profile = profile;
      }
    });
    await _saveProfiles();
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
        previous.password != updated.password;
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
            _normalizePanelSession(updated, connection.profile);
      }
    });
    await _savePanels();
    await _saveProfiles();
    await _refreshPanel(updated);
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
      _showHomeSnackBar('已通过二维码添加面板，正在获取所有会话。');
      await _refreshPanel(panel);
    } catch (error) {
      _showHomeSnackBar('二维码导入失败：${_formatError(error)}');
    }
  }

  Future<void> _refreshPanel(EmTaskPanelProfile panel) async {
    if (_refreshingPanels.contains(panel.id)) {
      return;
    }
    setState(() => _refreshingPanels.add(panel.id));
    try {
      final sessions = await _panelClient.fetchSessions(panel);
      if (!mounted) {
        return;
      }
      if (!_panels.any((item) => item.id == panel.id)) {
        return;
      }
      setState(() => _upsertPanelProfiles(panel, sessions));
      await _saveProfiles();
      _showHomeSnackBar('已从 ${panel.name} 获取 ${sessions.length} 个会话。');
    } catch (error) {
      if (mounted) {
        _showHomeSnackBar('刷新面板失败：${_formatError(error)}');
      }
    } finally {
      if (mounted) {
        setState(() => _refreshingPanels.remove(panel.id));
      }
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
        connection.profile = normalized[replacementIndex];
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

  EmTaskSessionProfile _normalizePanelSession(
    EmTaskPanelProfile panel,
    EmTaskSessionProfile profile,
  ) {
    final taskName = profile.name.contains('/')
        ? profile.name.split('/').last.trim()
        : profile.name.trim();
    final safeTask = taskName.replaceAll(RegExp(r'[^A-Za-z0-9_.-]+'), '-');
    return profile.copyWith(
      id: '${panel.id}-$safeTask-${profile.port}',
      name: '${panel.name} / ${taskName.isEmpty ? 'task' : taskName}',
      host: panel.host,
      username: panel.username,
      password: panel.password,
    );
  }

  bool _isPanelConnection(
    EmTaskConnection connection,
    EmTaskPanelProfile panel,
  ) {
    final profile = connection.profile;
    return profile.id.startsWith('${panel.id}-') ||
        (profile.host == panel.host &&
            profile.name.startsWith('${panel.name} /'));
  }

  bool _isPanelProfile(EmTaskSessionProfile profile) {
    return _panels.any(
      (panel) =>
          profile.id.startsWith('${panel.id}-') ||
          (profile.host == panel.host &&
              profile.name.startsWith('${panel.name} /')),
    );
  }

  List<EmTaskConnection> _panelConnections(EmTaskPanelProfile panel) {
    return _connections
        .where((connection) => _isPanelConnection(connection, panel))
        .toList(growable: false);
  }

  bool _isSamePanelEndpoint(
    EmTaskSessionProfile left,
    EmTaskSessionProfile right,
  ) {
    return left.host == right.host &&
        left.port == right.port &&
        left.username == right.username;
  }

  Future<void> _removeProfile(EmTaskConnection connection) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('删除会话'),
        content: Text('确定删除 “${connection.profile.name}” 吗？'),
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
    setState(() => _connections.remove(connection));
    connection.dispose();
    await _saveProfiles();
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
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message)),
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
            tooltip: '添加面板',
            onPressed: _addPanel,
            icon: const Icon(Icons.dashboard_outlined),
          ),
          IconButton(
            tooltip: '二维码添加面板',
            onPressed: _showQrImportOptions,
            icon: const Icon(Icons.qr_code_scanner),
          ),
          IconButton(
            tooltip: '新增会话',
            onPressed: () => _addOrEditProfile(),
            icon: const Icon(Icons.add_circle_outline),
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
        return _SessionTile(
          connection: connection,
          onOpen: () => _openSession(connection),
          onToggle: () => _toggleConnection(connection),
          onEdit: () => _addOrEditProfile(connection: connection),
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
    required this.onProfilePathChanged,
  });

  final EmTaskConnection connection;
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
  StreamSubscription<String>? _terminalOutputSubscription;

  bool _showSftp = false;
  bool _sftpBusy = false;
  String? _sftpError;
  String? _loadedDirectoryPath;
  String? _openedFilePath;
  String? _openedFileText;
  List<EmTaskSftpEntry> _sftpEntries = const <EmTaskSftpEntry>[];
  int _lastOutputLength = 0;

  @override
  void initState() {
    super.initState();
    _terminal = Terminal(
      maxLines: 5000,
      onOutput: (data) {
        try {
          widget.connection.writeText(data);
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
  }

  void _handleConnectionChanged() {
    final currentLength = widget.connection.output.length;
    if (!_showSftp && currentLength != _lastOutputLength) {
      _lastOutputLength = currentLength;
    }
  }

  @override
  void dispose() {
    widget.connection.removeListener(_handleConnectionChanged);
    widget.connection.setActive(false);
    unawaited(_terminalOutputSubscription?.cancel());
    _terminalFocusNode.dispose();
    _sftpPathController.dispose();
    _sftpListScrollController.dispose();
    _sftpPreviewScrollController.dispose();
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
        _openedFilePath = null;
        _openedFileText = null;
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
      _openedFilePath = null;
      _openedFileText = null;
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
    if (!widget.connection.isConnected) {
      setState(() => _sftpError = '请先连接会话，然后再读取文件。');
      return;
    }
    setState(() {
      _sftpBusy = true;
      _sftpError = null;
      _openedFilePath = entry.path;
      _openedFileText = null;
    });

    try {
      final content = await widget.connection.readSftpFile(entry.path);
      if (!mounted) {
        return;
      }
      setState(() => _openedFileText = content.isEmpty ? '文件为空。' : content);
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

  Future<void> _openParentDirectory() async {
    await _loadDirectory(path: _parentSftpPath(_sftpPathController.text));
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

  void _scrollSftpPreviewToTop() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_sftpPreviewScrollController.hasClients) {
        _sftpPreviewScrollController.jumpTo(0);
      }
    });
  }

  void _showSnackBar(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message)),
    );
  }

  @override
  Widget build(BuildContext context) {
    final layout = _layoutForWidth(MediaQuery.sizeOf(context).width);
    return AnimatedBuilder(
      animation: widget.connection,
      builder: (context, _) {
        final connection = widget.connection;
        return Scaffold(
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
    return SafeArea(
      top: false,
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
                autofocus: true,
                readOnly: !connection.isConnected,
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
                padding: const EdgeInsets.fromLTRB(10, 10, 10, 10),
                cursorType: TerminalCursorType.block,
                alwaysShowCursor: true,
              ),
            ),
            if (!connection.isConnected)
              Positioned(
                right: 12,
                bottom: 12,
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
                    'SFTP 文件查看',
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
                  ? () => _loadDirectory(path: _loadedDirectoryPath)
                  : null,
              icon: const Icon(Icons.refresh),
              label: const Text('刷新'),
            ),
          ],
        );

        if (constraints.maxWidth < 660) {
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
            buttons,
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

        final previewHeight = math.min(
          280.0,
          math.max(160.0, constraints.maxHeight * 0.42),
        );
        return Column(
          children: <Widget>[
            Expanded(child: list),
            const SizedBox(height: 12),
            SizedBox(height: previewHeight, child: preview),
          ],
        );
      },
    );
  }

  Widget _buildSftpEntryList() {
    final emptyMessage =
        _loadedDirectoryPath == null ? '输入路径后点击“打开目录”。' : '目录为空。';

    return DecoratedBox(
      decoration: BoxDecoration(
        color: const Color(0xff020617),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0xff1f2937)),
      ),
      child: _sftpEntries.isEmpty
          ? Center(child: Text(emptyMessage))
          : Scrollbar(
              controller: _sftpListScrollController,
              child: ListView.separated(
                controller: _sftpListScrollController,
                padding: const EdgeInsets.symmetric(vertical: 8),
                itemCount: _sftpEntries.length,
                separatorBuilder: (_, __) => const Divider(height: 1),
                itemBuilder: (context, index) {
                  final entry = _sftpEntries[index];
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
            child: Row(
              children: <Widget>[
                const Icon(Icons.article_outlined, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    _openedFilePath ?? '文件预览',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: Scrollbar(
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
  edit,
  delete,
}

enum _PanelMenuAction {
  edit,
  delete,
}

enum _QrImportAction {
  camera,
  image,
  file,
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
    required this.onEdit,
    required this.onDelete,
  });

  final bool refreshing;
  final VoidCallback onRefresh;
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
              case _PanelMenuAction.edit:
                onEdit();
              case _PanelMenuAction.delete:
                onDelete();
            }
          },
          itemBuilder: (context) => const <PopupMenuEntry<_PanelMenuAction>>[
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
    required this.onDelete,
  });

  final EmTaskConnection connection;
  final VoidCallback onOpen;
  final VoidCallback onToggle;
  final VoidCallback onEdit;
  final VoidCallback onDelete;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    final borderColor = connection.isConnected
        ? colors.primary.withOpacity(0.72)
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
                    '${connection.profile.host}:${connection.profile.port}',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context).textTheme.bodySmall,
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
                  case _SessionMenuAction.edit:
                    onEdit();
                  case _SessionMenuAction.delete:
                    onDelete();
                }
              },
              itemBuilder: (context) =>
                  const <PopupMenuEntry<_SessionMenuAction>>[
                PopupMenuItem<_SessionMenuAction>(
                  value: _SessionMenuAction.edit,
                  child: Text('编辑'),
                ),
                PopupMenuItem<_SessionMenuAction>(
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
    return '先连接，成功后可进入终端';
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
  const _ProfileDialog({this.profile});

  final EmTaskSessionProfile? profile;

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
  late final TextEditingController _pathController;
  late final EmTaskShellKind _shellKind;
  late bool _supportsSftp;

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
    _pathController = TextEditingController(text: profile.initialPath);
    _shellKind = profile.shellKind;
    _supportsSftp = profile.supportsSftp;
  }

  @override
  void dispose() {
    _nameController.dispose();
    _hostController.dispose();
    _portController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    _pathController.dispose();
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
                        decoration: const InputDecoration(labelText: '名称'),
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

  void _submit() {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    final original = widget.profile;
    Navigator.of(context).pop(
      EmTaskSessionProfile(
        id: original?.id ?? EmTaskSessionProfile.newId(),
        name: _nameController.text.trim(),
        host: _hostController.text.trim(),
        port: int.parse(_portController.text.trim()),
        username: _usernameController.text.trim(),
        password: _passwordController.text,
        shellKind: _shellKind,
        initialPath:
            EmTaskConnection.normalizeSftpVirtualPath(_pathController.text),
        supportsSftp: _supportsSftp,
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

String _formatError(Object error) {
  return error
      .toString()
      .replaceFirst('Bad state: ', '')
      .replaceFirst('StateError: ', '');
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

String _safeInitialSftpPath(String path) {
  try {
    return EmTaskConnection.normalizeSftpVirtualPath(path);
  } catch (_) {
    return '.';
  }
}
