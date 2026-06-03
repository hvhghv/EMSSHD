import 'dart:convert';

enum EmTaskShellKind {
  auto,
  cmd,
  powershell,
  posix,
}

extension EmTaskShellKindX on EmTaskShellKind {
  String get wireName {
    switch (this) {
      case EmTaskShellKind.auto:
        return 'auto';
      case EmTaskShellKind.cmd:
        return 'cmd';
      case EmTaskShellKind.powershell:
        return 'powershell';
      case EmTaskShellKind.posix:
        return 'posix';
    }
  }

  String get label {
    switch (this) {
      case EmTaskShellKind.auto:
        return '自动（cmd 模板）';
      case EmTaskShellKind.cmd:
        return 'Windows cmd';
      case EmTaskShellKind.powershell:
        return 'PowerShell';
      case EmTaskShellKind.posix:
        return 'Linux/macOS sh';
    }
  }

  String get description {
    switch (this) {
      case EmTaskShellKind.auto:
        return '按 emtask 默认 cmd.exe /Q /K 生成文件命令。';
      case EmTaskShellKind.cmd:
        return '适用于 Windows cmd.exe 任务。';
      case EmTaskShellKind.powershell:
        return '适用于 PowerShell 任务。';
      case EmTaskShellKind.posix:
        return '适用于 Linux、macOS、MSYS2、Cygwin shell。';
    }
  }

  static EmTaskShellKind fromWireName(String? value) {
    switch (value) {
      case 'cmd':
        return EmTaskShellKind.cmd;
      case 'powershell':
        return EmTaskShellKind.powershell;
      case 'posix':
        return EmTaskShellKind.posix;
      case 'auto':
      default:
        return EmTaskShellKind.auto;
    }
  }
}

enum EmTaskConnectionStatus {
  disconnected,
  connecting,
  connected,
  error,
}

enum EmTaskFileCommand {
  listDirectory,
  readFile,
}

enum EmTaskPanelAuthMode {
  none,
  token,
  otp,
  tokenOtp,
}

extension EmTaskPanelAuthModeX on EmTaskPanelAuthMode {
  String get wireName {
    switch (this) {
      case EmTaskPanelAuthMode.none:
        return 'none';
      case EmTaskPanelAuthMode.token:
        return 'token';
      case EmTaskPanelAuthMode.otp:
        return 'otp';
      case EmTaskPanelAuthMode.tokenOtp:
        return 'token+otp';
    }
  }

  String get label {
    switch (this) {
      case EmTaskPanelAuthMode.none:
        return '无鉴权';
      case EmTaskPanelAuthMode.token:
        return 'Token';
      case EmTaskPanelAuthMode.otp:
        return 'OTP';
      case EmTaskPanelAuthMode.tokenOtp:
        return 'Token + OTP';
    }
  }

  bool get usesToken =>
      this == EmTaskPanelAuthMode.token || this == EmTaskPanelAuthMode.tokenOtp;

  bool get usesOtp =>
      this == EmTaskPanelAuthMode.otp || this == EmTaskPanelAuthMode.tokenOtp;

  int get authBits {
    switch (this) {
      case EmTaskPanelAuthMode.none:
        return 0;
      case EmTaskPanelAuthMode.token:
        return 1;
      case EmTaskPanelAuthMode.otp:
        return 2;
      case EmTaskPanelAuthMode.tokenOtp:
        return 3;
    }
  }

  static EmTaskPanelAuthMode fromWireName(String? value) {
    switch (value) {
      case 'token':
        return EmTaskPanelAuthMode.token;
      case 'otp':
      case 'totp':
        return EmTaskPanelAuthMode.otp;
      case 'both':
      case 'token+otp':
      case 'otp+token':
      case 'token,otp':
      case 'otp,token':
        return EmTaskPanelAuthMode.tokenOtp;
      case 'none':
      default:
        return EmTaskPanelAuthMode.none;
    }
  }

  static EmTaskPanelAuthMode fromBits(int? value) {
    switch (value ?? 0) {
      case 1:
        return EmTaskPanelAuthMode.token;
      case 2:
        return EmTaskPanelAuthMode.otp;
      case 3:
        return EmTaskPanelAuthMode.tokenOtp;
      case 0:
      default:
        return EmTaskPanelAuthMode.none;
    }
  }
}

class EmTaskPanelProfile {
  const EmTaskPanelProfile({
    required this.id,
    required this.name,
    required this.host,
    required this.port,
    required this.authMode,
    required this.token,
    required this.otpSecret,
    required this.otpDigits,
    required this.otpStepSeconds,
    required this.otpWindow,
    required this.username,
    required this.password,
    required this.startCommand,
    required this.stopCommand,
  });

  factory EmTaskPanelProfile.defaults({
    String? id,
    String name = 'emtask 面板',
    String host = '127.0.0.1',
    int port = 8080,
    EmTaskPanelAuthMode authMode = EmTaskPanelAuthMode.none,
    String token = '',
    String otpSecret = '',
    int otpDigits = 6,
    int otpStepSeconds = 30,
    int otpWindow = 1,
    String username = 'emtask',
    String password = 'emtask',
    String startCommand = '',
    String stopCommand = '',
  }) {
    return EmTaskPanelProfile(
      id: id ?? newId(),
      name: name,
      host: host,
      port: port,
      authMode: authMode,
      token: token,
      otpSecret: otpSecret,
      otpDigits: otpDigits,
      otpStepSeconds: otpStepSeconds,
      otpWindow: otpWindow,
      username: username,
      password: password,
      startCommand: startCommand,
      stopCommand: stopCommand,
    );
  }

  factory EmTaskPanelProfile.fromJson(Map<String, Object?> json) {
    return EmTaskPanelProfile(
      id: json['id'] as String? ?? newId(),
      name: json['name'] as String? ?? 'emtask 面板',
      host: json['host'] as String? ?? '127.0.0.1',
      port: json['port'] as int? ?? 8080,
      authMode: EmTaskPanelAuthModeX.fromWireName(
        json['authMode'] as String?,
      ),
      token: json['token'] as String? ?? '',
      otpSecret: json['otpSecret'] as String? ?? '',
      otpDigits: json['otpDigits'] as int? ?? 6,
      otpStepSeconds: json['otpStepSeconds'] as int? ?? 30,
      otpWindow: json['otpWindow'] as int? ?? 1,
      username: json['username'] as String? ?? 'emtask',
      password: json['password'] as String? ?? 'emtask',
      startCommand: json['startCommand'] as String? ?? '',
      stopCommand: json['stopCommand'] as String? ?? '',
    );
  }

  final String id;
  final String name;
  final String host;
  final int port;
  final EmTaskPanelAuthMode authMode;
  final String token;
  final String otpSecret;
  final int otpDigits;
  final int otpStepSeconds;
  final int otpWindow;
  final String username;
  final String password;
  final String startCommand;
  final String stopCommand;

  Uri get tasksUri => Uri(
        scheme: 'http',
        host: host,
        port: port,
        path: '/tasks',
      );

  Map<String, Object?> toJson() {
    return <String, Object?>{
      'id': id,
      'name': name,
      'host': host,
      'port': port,
      'authMode': authMode.wireName,
      'token': token,
      'otpSecret': otpSecret,
      'otpDigits': otpDigits,
      'otpStepSeconds': otpStepSeconds,
      'otpWindow': otpWindow,
      'username': username,
      'password': password,
      'startCommand': startCommand,
      'stopCommand': stopCommand,
    };
  }

  String encode() => jsonEncode(toJson());

  EmTaskPanelProfile copyWith({
    String? id,
    String? name,
    String? host,
    int? port,
    EmTaskPanelAuthMode? authMode,
    String? token,
    String? otpSecret,
    int? otpDigits,
    int? otpStepSeconds,
    int? otpWindow,
    String? username,
    String? password,
    String? startCommand,
    String? stopCommand,
  }) {
    return EmTaskPanelProfile(
      id: id ?? this.id,
      name: name ?? this.name,
      host: host ?? this.host,
      port: port ?? this.port,
      authMode: authMode ?? this.authMode,
      token: token ?? this.token,
      otpSecret: otpSecret ?? this.otpSecret,
      otpDigits: otpDigits ?? this.otpDigits,
      otpStepSeconds: otpStepSeconds ?? this.otpStepSeconds,
      otpWindow: otpWindow ?? this.otpWindow,
      username: username ?? this.username,
      password: password ?? this.password,
      startCommand: startCommand ?? this.startCommand,
      stopCommand: stopCommand ?? this.stopCommand,
    );
  }

  static String newId() =>
      'panel-${DateTime.now().microsecondsSinceEpoch}';
}

class EmTaskImportedPanel {
  const EmTaskImportedPanel({
    required this.panel,
    required this.firstSession,
  });

  final EmTaskPanelProfile panel;
  final EmTaskSessionProfile? firstSession;
}

class EmTaskSessionProfile {
  const EmTaskSessionProfile({
    required this.id,
    required this.name,
    required this.host,
    required this.port,
    required this.username,
    required this.password,
    required this.shellKind,
    required this.initialPath,
    required this.supportsSftp,
  });

  factory EmTaskSessionProfile.defaults({
    String id = 'default-shell',
    String name = 'emtask shell',
    String host = '127.0.0.1',
    int port = 2222,
    String username = 'emtask',
    String password = 'emtask',
    EmTaskShellKind shellKind = EmTaskShellKind.cmd,
    String initialPath = '.',
    bool supportsSftp = false,
  }) {
    return EmTaskSessionProfile(
      id: id,
      name: name,
      host: host,
      port: port,
      username: username,
      password: password,
      shellKind: shellKind,
      initialPath: initialPath,
      supportsSftp: supportsSftp,
    );
  }

  factory EmTaskSessionProfile.fromJson(Map<String, Object?> json) {
    return EmTaskSessionProfile(
      id: json['id'] as String? ?? _newId(),
      name: json['name'] as String? ?? 'emtask',
      host: json['host'] as String? ?? '127.0.0.1',
      port: json['port'] as int? ?? 2222,
      username: json['username'] as String? ?? 'emtask',
      password: json['password'] as String? ?? '',
      shellKind: EmTaskShellKindX.fromWireName(json['shellKind'] as String?),
      initialPath: json['initialPath'] as String? ?? '.',
      supportsSftp: json['supportsSftp'] as bool? ?? false,
    );
  }

  final String id;
  final String name;
  final String host;
  final int port;
  final String username;
  final String password;
  final EmTaskShellKind shellKind;
  final String initialPath;
  final bool supportsSftp;

  Map<String, Object?> toJson() {
    return <String, Object?>{
      'id': id,
      'name': name,
      'host': host,
      'port': port,
      'username': username,
      'password': password,
      'shellKind': shellKind.wireName,
      'initialPath': initialPath,
      'supportsSftp': supportsSftp,
    };
  }

  String encode() => jsonEncode(toJson());

  EmTaskSessionProfile copyWith({
    String? id,
    String? name,
    String? host,
    int? port,
    String? username,
    String? password,
    EmTaskShellKind? shellKind,
    String? initialPath,
    bool? supportsSftp,
  }) {
    return EmTaskSessionProfile(
      id: id ?? this.id,
      name: name ?? this.name,
      host: host ?? this.host,
      port: port ?? this.port,
      username: username ?? this.username,
      password: password ?? this.password,
      shellKind: shellKind ?? this.shellKind,
      initialPath: initialPath ?? this.initialPath,
      supportsSftp: supportsSftp ?? this.supportsSftp,
    );
  }

  static String newId() => _newId();

  static String _newId() => 'session-${DateTime.now().microsecondsSinceEpoch}';
}
