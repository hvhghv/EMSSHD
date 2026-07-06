import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show LogicalKeyboardKey;
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:emtask_client/main.dart';
import 'package:emtask_client/src/emtask_connection.dart';
import 'package:emtask_client/src/models.dart';
import 'package:emtask_client/src/panel_client.dart';
import 'package:emtask_client/src/panel_key_manager.dart';
import 'package:emtask_client/src/profile_store.dart';
import 'package:emtask_client/src/updater/updater.dart';

void main() {
  testWidgets('home screen only shows sessions', (WidgetTester tester) async {
    await _pumpClient(tester, const Size(800, 600));

    expect(find.text('emtask Client'), findsOneWidget);
    expect(find.text('还没有 emtask 会话'), findsOneWidget);
    expect(find.text('新建一个 IP/端口会话后即可后台连接。'), findsOneWidget);
    expect(find.text('emtask shell'), findsNothing);
    expect(find.text('emtask powershell'), findsNothing);
    expect(find.byTooltip('新增会话'), findsOneWidget);
    expect(find.byTooltip('更多操作'), findsOneWidget);
    expect(find.byTooltip('设置'), findsNothing);
    expect(find.byTooltip('添加面板'), findsNothing);
    expect(find.byTooltip('二维码添加面板'), findsNothing);
    expect(find.text('连接'), findsNothing);
    expect(find.text('先连接，成功后可进入终端'), findsNothing);
    expect(find.text('SFTP 文件查看'), findsNothing);
    expect(find.text('输入命令后回车发送到 emtask 终端'), findsNothing);
  });

  testWidgets('tap disconnected session does not open terminal',
      (WidgetTester tester) async {
    await _pumpClient(tester, const Size(390, 844));

    await tester.tap(find.byTooltip('新增会话'));
    await tester.pumpAndSettle();

    expect(find.text('新增会话'), findsOneWidget);
    expect(find.text('请先点击会话项里的“连接”，连接成功后再进入终端。'), findsNothing);
    expect(find.text('输入命令后回车发送到 emtask 终端'), findsNothing);
    expect(find.text('SFTP'), findsNothing);
  });

  testWidgets('add session dialog opens without layout exception',
      (WidgetTester tester) async {
    await _pumpClient(tester, const Size(390, 844));

    await tester.tap(find.byTooltip('新增会话'));
    await tester.pumpAndSettle();

    expect(find.text('新增会话'), findsOneWidget);
    expect(find.text('名称'), findsOneWidget);
    expect(find.text('IP / 主机名'), findsOneWidget);
    expect(find.text('端口'), findsOneWidget);
    expect(find.text('登录密钥私钥文件'), findsOneWidget);
    expect(find.text('私钥口令'), findsOneWidget);
    expect(find.text('选择私钥'), findsOneWidget);
    expect(find.text('支持 SFTP'), findsOneWidget);
    expect(find.text('保存'), findsOneWidget);
  });

  testWidgets('add panel dialog opens', (WidgetTester tester) async {
    await _pumpClient(tester, const Size(390, 844));

    await _tapHomeMenuItem(tester, '添加面板');
    await tester.pumpAndSettle();

    expect(find.text('添加面板'), findsOneWidget);
    expect(find.text('面板 IP / 主机名'), findsOneWidget);
    expect(find.text('面板端口'), findsOneWidget);
    expect(find.text('面板鉴权'), findsOneWidget);
    expect(find.text('添加并获取会话'), findsOneWidget);
  });

  testWidgets('panel menu includes add task action',
      (WidgetTester tester) async {
    final panel = EmTaskPanelProfile.defaults(
      name: '测试面板',
      host: '127.0.0.1',
    );
    await _pumpClient(
      tester,
      const Size(390, 844),
      initialValues: <String, Object>{
        'emtask_client.panels.v1': <String>[panel.encode()],
      },
    );

    expect(find.text('测试面板'), findsOneWidget);

    await tester.tap(find.byTooltip('面板操作'));
    await tester.pumpAndSettle();

    expect(find.text('添加子任务'), findsOneWidget);
    expect(find.text('编辑面板'), findsOneWidget);
    expect(find.text('删除面板'), findsOneWidget);
  });

  testWidgets('qr import options include camera screenshot and file',
      (WidgetTester tester) async {
    await _pumpClient(tester, const Size(390, 844));

    await _tapHomeMenuItem(tester, '二维码添加面板');
    await tester.pumpAndSettle();

    expect(find.text('拍照扫描二维码'), findsOneWidget);
    expect(find.text('框选屏幕截图识别'), findsOneWidget);
    expect(find.text('选择二维码文件导入'), findsOneWidget);
  });

  testWidgets('settings page includes shortcut keys and about',
      (WidgetTester tester) async {
    await _pumpClient(tester, const Size(390, 844));

    await _tapHomeMenuItem(tester, '设置');
    await tester.pumpAndSettle();

    expect(find.text('设置'), findsOneWidget);
    expect(find.text('启动快捷键'), findsOneWidget);
    expect(find.text('显示终端快捷键栏'), findsOneWidget);
    expect(find.text('手动打开终端键盘'), findsOneWidget);
    expect(find.text('SFTP 文件预览'), findsOneWidget);
    expect(find.text('小文件阈值'), findsOneWidget);
    expect(find.text('512.0 KB'), findsOneWidget);
    expect(find.text('预览框高度'), findsOneWidget);
    expect(find.text('640 px'), findsOneWidget);
    expect(find.text('关于'), findsOneWidget);
    expect(find.text('emtask Client · v1.0.0+1'), findsOneWidget);

    final switchFinder = find.byType(Switch);
    expect(switchFinder, findsNWidgets(2));
    await tester.tap(switchFinder.first);
    await tester.pumpAndSettle();
  });

  testWidgets('terminal page exposes restart button',
      (WidgetTester tester) async {
    final connection = EmTaskConnection(
      EmTaskSessionProfile.defaults(name: '测试会话'),
    );
    addTearDown(connection.dispose);

    await _pumpSessionPage(tester, connection, const Size(390, 844));

    expect(find.text('测试会话'), findsOneWidget);
    expect(find.byTooltip('整页文本输入'), findsOneWidget);
    expect(find.byTooltip('重启应用'), findsOneWidget);
    expect(find.byTooltip('清空终端输出'), findsOneWidget);
  });

  test('empty panel store returns mutable list for QR import', () async {
    SharedPreferences.setMockInitialValues(<String, Object>{});

    final panels = await EmTaskProfileStore().loadPanels();
    panels.add(EmTaskPanelProfile.defaults());

    expect(panels, hasLength(1));
  });

  test('panel defaults match emtask server auth defaults', () {
    final panel = EmTaskPanelProfile.defaults();

    expect(panel.port, 6024);
    expect(panel.authMode, EmTaskPanelAuthMode.tokenOtp);
    expect(panel.otpStepSeconds, 60);
  });

  test('panel create task request serializes server fields', () {
    const request = EmTaskPanelCreateTaskRequest(
      name: 'shell',
      port: 2223,
      command: '/bin/sh',
      listenAddress: '127.0.0.1',
      workingDir: '/tmp',
      useSftp: false,
      useConpty: true,
      replayOnAttach: false,
      repaintOnAttach: false,
      screenSnapshot: false,
    );

    expect(request.toJson(), <String, Object?>{
      'name': 'shell',
      'port': 2223,
      'command': '/bin/sh',
      'listen_address': '127.0.0.1',
      'working_dir': '/tmp',
      'use_sftp': false,
      'use_conpty': true,
      'replay_on_attach': false,
      'repaint_on_attach': false,
      'screen_snapshot': false,
    });
  });

  test('generated panel key material is valid OpenSSH ed25519', () {
    final material =
        EmTaskPanelKeyManager.createEd25519KeyMaterial('emtask-client-test');
    final keys = SSHKeyPair.fromPem(material.privateKeyPem);

    expect(keys, hasLength(1));
    expect(keys.single.name, 'ssh-ed25519');
    expect(
      material.publicKeyLine,
      'ssh-ed25519 ${base64Encode(keys.single.toPublicKey().encode())} emtask-client-test',
    );
  });

  test('session profile saves private key settings', () {
    final profile = EmTaskSessionProfile.defaults(
      privateKeyPath: r'C:\Users\Administrator\.ssh\id_rsa',
      privateKeyPassphrase: 'secret',
    );

    final restored = EmTaskSessionProfile.fromJson(profile.toJson());

    expect(restored.privateKeyPath, r'C:\Users\Administrator\.ssh\id_rsa');
    expect(restored.privateKeyPassphrase, 'secret');
    expect(restored.hasPrivateKey, isTrue);
  });

  test('client settings persist sftp small file threshold', () {
    final settings = EmTaskClientSettings.defaults(
      shortcutKeysEnabled: true,
      terminalKeyboardButtonOnly: true,
      sftpSmallFileBytes: 2 * 1024 * 1024,
      sftpPreviewHeight: 900,
    );

    final restored = EmTaskClientSettings.fromJson(settings.toJson());

    expect(restored.shortcutKeysEnabled, isTrue);
    expect(restored.terminalKeyboardButtonOnly, isTrue);
    expect(restored.sftpSmallFileBytes, 2 * 1024 * 1024);
    expect(restored.sftpPreviewHeight, 900);
    expect(
      EmTaskClientSettings.defaults(sftpSmallFileBytes: 1).sftpSmallFileBytes,
      EmTaskClientSettings.minSftpSmallFileBytes,
    );
    expect(
      EmTaskClientSettings.defaults(
        sftpSmallFileBytes: 99 * 1024 * 1024,
      ).sftpSmallFileBytes,
      EmTaskClientSettings.maxSftpSmallFileBytes,
    );
    expect(
      EmTaskClientSettings.defaults(sftpPreviewHeight: 1).sftpPreviewHeight,
      EmTaskClientSettings.minSftpPreviewHeight,
    );
    expect(
      EmTaskClientSettings.defaults(sftpPreviewHeight: 9999).sftpPreviewHeight,
      EmTaskClientSettings.maxSftpPreviewHeight,
    );
  });

  test('github updater parses repository addresses', () {
    expect(GitHubRepositoryRef.parse('owner/repo').toString(), 'owner/repo');
    expect(
      GitHubRepositoryRef.parse('https://github.com/owner/repo.git').toString(),
      'owner/repo',
    );
    expect(
      GitHubRepositoryRef.parse('git@github.com:owner/repo.git').toString(),
      'owner/repo',
    );
  });

  test('github updater models parse release and action json', () {
    final release = GitHubUpdateVersion.fromReleaseJson(<String, Object?>{
      'tag_name': 'v1.0.0',
      'name': 'v1.0.0',
      'prerelease': false,
      'published_at': '2026-06-15T00:00:00Z',
      'assets': <Object?>[<String, Object?>{}],
    });
    final run = GitHubUpdateVersion.fromActionRunJson(<String, Object?>{
      'id': 123,
      'run_number': 7,
      'name': 'Build packages',
      'display_title': 'main build',
      'head_branch': 'main',
      'head_sha': 'abcdef0123456789',
      'created_at': '2026-06-15T00:00:00Z',
    });
    final asset = GitHubUpdateAsset.fromActionArtifactJson(<String, Object?>{
      'name': 'emtask-client-windows-x64',
      'size_in_bytes': 42,
      'archive_download_url': 'https://api.github.com/download',
    });

    expect(release.id, 'v1.0.0');
    expect(release.assetCount, 1);
    expect(run.id, '123');
    expect(run.subtitle, contains('#7'));
    expect(asset.requiresToken, isTrue);
    expect(asset.sizeBytes, 42);
    expect(asset.downloadFileName, 'emtask-client-windows-x64.zip');
    expect(asset.downloadAcceptHeader, 'application/vnd.github+json');
  });

  testWidgets('github updater filters and pages versions',
      (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1000, 1800);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    SharedPreferences.setMockInitialValues(<String, Object>{});
    final versions = List<GitHubUpdateVersion>.generate(
      25,
      (index) => GitHubUpdateVersion(
        id: '$index',
        title: 'Version ${index.toString().padLeft(2, '0')}',
        subtitle: index.isEven ? 'main branch' : 'feature branch',
        createdAt: DateTime.utc(2026, 7, 1, 0, index),
        assetCount: 1,
        channel: GitHubUpdateChannel.action,
      ),
    );

    await tester.pumpWidget(
      MaterialApp(
        home: GitHubUpdatePage(
          config: const GitHubUpdatePageConfig(
            initialRepository: 'owner/repo',
          ),
          client: _FakeGitHubUpdateClient(versions),
        ),
      ),
    );
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));

    await tester.tap(find.text('列出版本'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));

    expect(find.text('Version 00'), findsOneWidget);
    expect(find.text('Version 09'), findsOneWidget);
    expect(find.text('Version 10'), findsNothing);
    expect(find.text('第 1 / 3 页 · 共 25 个'), findsOneWidget);

    await tester.tap(find.byTooltip('下一页'));
    await tester.pump();

    expect(find.text('Version 10'), findsOneWidget);
    expect(find.text('Version 00'), findsNothing);
    expect(find.text('第 2 / 3 页 · 共 25 个'), findsOneWidget);

    await tester.enterText(
      find.byKey(const Key('github_update_version_page')),
      '3',
    );
    await tester.tap(find.byTooltip('跳转页码'));
    await tester.pump();

    expect(find.text('Version 20'), findsOneWidget);
    expect(find.text('Version 19'), findsNothing);
    expect(find.text('第 3 / 3 页 · 共 25 个'), findsOneWidget);

    await tester.enterText(
      find.byKey(const Key('github_update_version_search')),
      'Version 23',
    );
    await tester.pump();

    expect(
      find.descendant(
        of: find.byType(ListTile),
        matching: find.text('Version 23'),
      ),
      findsOneWidget,
    );
    expect(find.text('Version 10'), findsNothing);
    expect(find.text('第 1 / 1 页 · 共 1 个'), findsOneWidget);
  });

  test('github updater defaults parse info.dat', () {
    final defaults = GitHubUpdateInfoDefaults.fromJson(<String, Object?>{
      'repo': 'hvhghv/EMSSHD',
      'channel': 'action',
      'artifact': 'emtask-client-windows-x64',
      'workflow': 'build.yml',
      'branch': 'main',
    });

    expect(defaults.repository, 'hvhghv/EMSSHD');
    expect(defaults.channel, GitHubUpdateChannel.action);
    expect(defaults.namePattern, 'emtask-client-windows-x64*');
    expect(defaults.workflow, 'build.yml');
    expect(defaults.branch, 'main');
  });

  test('github updater saved input persists last values', () async {
    SharedPreferences.setMockInitialValues(<String, Object>{});
    const key = 'github_updater.test.last_input';
    const input = GitHubUpdateSavedInput(
      repository: 'owner/repo',
      namePattern: 'app-windows*',
      workflow: 'ci.yml',
      branch: 'main',
      token: 'secret',
      channel: GitHubUpdateChannel.action,
    );

    await input.save(key: key);
    final restored = await GitHubUpdateSavedInput.load(key: key);
    final restoredWithoutToken = await GitHubUpdateSavedInput.load(
      key: key,
      persistToken: false,
    );

    expect(restored.repository, 'owner/repo');
    expect(restored.namePattern, 'app-windows*');
    expect(restored.workflow, 'ci.yml');
    expect(restored.branch, 'main');
    expect(restored.token, 'secret');
    expect(restored.channel, GitHubUpdateChannel.action);
    expect(restoredWithoutToken.token, isEmpty);
  });

  test('github updater locates local package from info.dat', () async {
    final root = await Directory.systemTemp.createTemp('github-updater-test-');
    addTearDown(() async {
      if (await root.exists()) {
        await root.delete(recursive: true);
      }
    });
    final packageDir =
        Directory('${root.path}${Platform.pathSeparator}emtask-client-test');
    await packageDir.create();
    await File('${packageDir.path}${Platform.pathSeparator}info.Dat')
        .writeAsString(jsonEncode(<String, Object?>{
      'repo': 'owner/repo',
      'channel': 'action',
      'artifact': 'emtask-client-test',
    }));
    final updaterScriptName =
        Platform.isWindows ? 'github-update.ps1' : 'github-update.sh';
    final updaterScript =
        File('${root.path}${Platform.pathSeparator}$updaterScriptName');
    await updaterScript.writeAsString('');

    final local = await GitHubUpdateLocalPackage.locate(
      infoFilePath: packageDir.path,
    );

    expect(local.packageName, 'emtask-client-test');
    expect(local.packageDir.path, packageDir.path);
    expect(local.installRoot.path, root.path);
    expect(local.updaterScript.path, updaterScript.path);
  }, skip: !GitHubUpdateLocalPackage.isDesktopSupported);

  test('terminal modifiers convert soft keyboard input', () {
    expect(
      terminalInputWithModifiersForTest(
        'c',
        ctrl: true,
        shift: false,
        alt: false,
      ),
      '\x03',
    );
    expect(
      terminalInputWithModifiersForTest(
        'C',
        ctrl: true,
        shift: false,
        alt: false,
      ),
      '\x03',
    );
    expect(
      terminalInputWithModifiersForTest(
        'x',
        ctrl: false,
        shift: true,
        alt: true,
      ),
      '\x1bX',
    );
  });

  test('powershell terminal input is encoded as utf8', () {
    final expected = Uint8List.fromList(<int>[
      0xe4,
      0xb8,
      0xad,
      0xe6,
      0x96,
      0x87,
    ]);

    expect(
      encodeEmTaskTerminalInput('中文', EmTaskShellKind.auto),
      expected,
    );
    expect(
      encodeEmTaskTerminalInput('中文', EmTaskShellKind.powershell),
      expected,
    );
    expect(
      encodeEmTaskTerminalInput('中文', EmTaskShellKind.posix),
      expected,
    );
  });

  test('terminal shortcuts leave Ctrl+C for remote interrupt', () {
    final shortcuts =
        terminalShortcutsForPlatformForTest(TargetPlatform.windows);

    expect(
      shortcuts.containsKey(
        const SingleActivator(LogicalKeyboardKey.keyC, control: true),
      ),
      isFalse,
    );
    expect(
      shortcuts[const SingleActivator(
        LogicalKeyboardKey.keyC,
        control: true,
        shift: true,
      )],
      CopySelectionTextIntent.copy,
    );
  });

  test('terminal text composer converts line feeds to carriage returns', () {
    expect(terminalComposerPayloadForTest('echo 1\necho 2'), 'echo 1\recho 2');
    expect(terminalComposerPayloadForTest('a\r\nb\rc'), 'a\rb\rc');
  });

  test('sftp virtual path is limited to working directory tree', () {
    expect(EmTaskConnection.normalizeSftpVirtualPath(''), '.');
    expect(EmTaskConnection.normalizeSftpVirtualPath('/'), '.');
    expect(EmTaskConnection.normalizeSftpVirtualPath('logs/./app.log'),
        'logs/app.log');
    expect(
        EmTaskConnection.normalizeSftpVirtualPath(r'logs\today'), 'logs/today');

    expect(
      () => EmTaskConnection.normalizeSftpVirtualPath('../secret.txt'),
      throwsStateError,
    );
    expect(
      () => EmTaskConnection.normalizeSftpVirtualPath(r'C:\secret.txt'),
      throwsStateError,
    );
    expect(
      () => EmTaskConnection.normalizeSftpVirtualPath('/opt/emtask'),
      throwsStateError,
    );
  });

  test('sftp file content allows safe text and full binary editing', () {
    final textFile = EmTaskSftpFileContent(
      text: 'hello',
      bytes: Uint8List(0),
      size: 5,
      offset: 0,
      length: 5,
      isTruncated: false,
      isUtf8Text: true,
      pageBytes: 512,
    );
    final largeFile = EmTaskSftpFileContent(
      text: 'head',
      bytes: Uint8List(0),
      size: 2048,
      offset: 0,
      length: 512,
      isTruncated: true,
      isUtf8Text: true,
      pageBytes: 512,
    );
    final binaryFile = EmTaskSftpFileContent(
      text: '',
      bytes: Uint8List.fromList(<int>[0, 1, 2, 65, 66, 67]),
      size: 6,
      offset: 0,
      length: 6,
      isTruncated: false,
      isUtf8Text: false,
      pageBytes: 512,
    );

    expect(textFile.isEditable, isTrue);
    expect(textFile.displayText, 'hello');
    expect(largeFile.isEditable, isFalse);
    expect(largeFile.displayText, contains('文件较大'));
    expect(binaryFile.isEditable, isTrue);
    expect(binaryFile.isBinaryEditable, isTrue);
    expect(binaryFile.isBinary, isTrue);
    expect(binaryFile.editorText, '00 01 02 41 42 43');
    expect(binaryFile.displayText, contains('00000000'));
    expect(binaryFile.displayText, contains('00 01 02 41 42 43'));
  });

  test('sftp binary hex editor parses byte input', () {
    final bytes = EmTaskSftpFileContent.parseHexBytes('00 1f, a0\nff 0X7e');

    expect(bytes, <int>[0x00, 0x1f, 0xa0, 0xff, 0x7e]);
    expect(EmTaskSftpFileContent.formatHexBytes(Uint8List.fromList(bytes)),
        '00 1f a0 ff 7e');
    expect(
      () => EmTaskSftpFileContent.parseHexBytes('000'),
      throwsFormatException,
    );
    expect(
      () => EmTaskSftpFileContent.parseHexBytes('zz'),
      throwsFormatException,
    );
  });

  test('sftp file content exposes paging offsets', () {
    final page = EmTaskSftpFileContent(
      text: '',
      bytes: Uint8List.fromList(List<int>.generate(16, (index) => index)),
      size: 100,
      offset: 32,
      length: 16,
      isTruncated: true,
      isUtf8Text: false,
      pageBytes: 16,
    );

    expect(page.canGoPrevious, isTrue);
    expect(page.canGoNext, isTrue);
    expect(page.previousOffset, 16);
    expect(page.nextOffset, 48);
    expect(page.displayText, contains('00000020'));
  });
}

Future<void> _pumpClient(
  WidgetTester tester,
  Size size, {
  Map<String, Object> initialValues = const <String, Object>{},
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  SharedPreferences.setMockInitialValues(initialValues);
  await tester.pumpWidget(const EmTaskClientApp());
  await tester.pumpAndSettle();
}

Future<void> _pumpSessionPage(
  WidgetTester tester,
  EmTaskConnection connection,
  Size size,
) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  await tester.pumpWidget(
    MaterialApp(
      home: EmTaskSessionPage(
        connection: connection,
        shortcutKeysEnabled: true,
        terminalKeyboardButtonOnly: false,
        sftpSmallFileBytes: EmTaskClientSettings.defaultSftpSmallFileBytes,
        sftpPreviewHeight: EmTaskClientSettings.defaultSftpPreviewHeight,
        onProfilePathChanged: (_) async {},
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> _tapHomeMenuItem(WidgetTester tester, String label) async {
  await tester.tap(find.byTooltip('更多操作'));
  await tester.pumpAndSettle();
  await tester.tap(find.text(label));
}

class _FakeGitHubUpdateClient extends GitHubUpdateClient {
  _FakeGitHubUpdateClient(this.versions);

  final List<GitHubUpdateVersion> versions;

  @override
  Future<List<GitHubUpdateVersion>> listVersions({
    required String repo,
    required GitHubUpdateChannel channel,
    String? token,
    String? workflow,
    String? branch,
    bool includePrerelease = false,
  }) async {
    return versions;
  }

  @override
  Future<List<GitHubUpdateAsset>> listAssets({
    required String repo,
    required GitHubUpdateChannel channel,
    required String version,
    String? token,
    String? namePattern,
  }) async {
    return const <GitHubUpdateAsset>[];
  }
}
