import 'dart:ui';

import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:emtask_client/main.dart';

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

    expect(find.text('请先点击会话项里的“连接”，连接成功后再进入终端。'),
        findsOneWidget);
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

  testWidgets('qr import options include camera image and file',
      (WidgetTester tester) async {
    await _pumpClient(tester, const Size(390, 844));

    await tester.tap(find.byTooltip('二维码添加面板'));
    await tester.pumpAndSettle();

    expect(find.text('拍照扫描二维码'), findsOneWidget);
    expect(find.text('选择截图图片识别'), findsOneWidget);
    expect(find.text('选择二维码文件导入'), findsOneWidget);
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