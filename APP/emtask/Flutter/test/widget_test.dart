import 'dart:ui';

import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:emtask_client/main.dart';
import 'package:emtask_client/src/emtask_connection.dart';
import 'package:emtask_client/src/models.dart';
import 'package:emtask_client/src/profile_store.dart';

void main() {
  testWidgets('home screen only shows sessions', (WidgetTester tester) async {
    await _pumpClient(tester, const Size(800, 600));

    expect(find.text('emtask Client'), findsOneWidget);
    expect(find.text('会话'), findsOneWidget);
    expect(find.text('emtask shell'), findsOneWidget);
    expect(find.byTooltip('添加面板'), findsOneWidget);
    expect(find.byTooltip('二维码添加面板'), findsOneWidget);
    expect(find.text('连接'), findsWidgets);
    expect(find.text('先连接，成功后可进入终端'), findsWidgets);
    expect(find.text('SFTP 文件查看'), findsNothing);
    expect(find.text('输入命令后回车发送到 emtask 终端'), findsNothing);
  });

  testWidgets('tap disconnected session does not open terminal',
      (WidgetTester tester) async {
    await _pumpClient(tester, const Size(390, 844));

    await tester.tap(find.text('emtask shell'));
    await tester.pumpAndSettle();

    expect(find.text('请先点击会话项里的“连接”，连接成功后再进入终端。'), findsOneWidget);
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
    expect(find.text('支持 SFTP'), findsOneWidget);
    expect(find.text('保存'), findsOneWidget);
  });

  testWidgets('add panel dialog opens', (WidgetTester tester) async {
    await _pumpClient(tester, const Size(390, 844));

    await tester.tap(find.byTooltip('添加面板'));
    await tester.pumpAndSettle();

    expect(find.text('添加面板'), findsOneWidget);
    expect(find.text('面板 IP / 主机名'), findsOneWidget);
    expect(find.text('面板端口'), findsOneWidget);
    expect(find.text('面板鉴权'), findsOneWidget);
    expect(find.text('添加并获取会话'), findsOneWidget);
  });

  testWidgets('qr import options include camera screenshot and file',
      (WidgetTester tester) async {
    await _pumpClient(tester, const Size(390, 844));

    await tester.tap(find.byTooltip('二维码添加面板'));
    await tester.pumpAndSettle();

    expect(find.text('拍照扫描二维码'), findsOneWidget);
    expect(find.text('框选屏幕截图识别'), findsOneWidget);
    expect(find.text('选择二维码文件导入'), findsOneWidget);
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
}

Future<void> _pumpClient(WidgetTester tester, Size size) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  SharedPreferences.setMockInitialValues(<String, Object>{});
  await tester.pumpWidget(const EmTaskClientApp());
  await tester.pumpAndSettle();
}
