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
        return '自动（UTF-8）';
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
        return '适用于 codex 等现代终端程序，输入按 UTF-8 发送。';
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

class EmTaskClientSettings {
  const EmTaskClientSettings({
    required this.shortcutKeysEnabled,
    required this.terminalKeyboardButtonOnly,
    required this.sftpSmallFileBytes,
    required this.sftpPreviewHeight,
  });

  static const defaultSftpSmallFileBytes = 512 * 1024;
  static const minSftpSmallFileBytes = 64 * 1024;
  static const maxSftpSmallFileBytes = 4 * 1024 * 1024;
  static const defaultSftpPreviewHeight = 640;
  static const minSftpPreviewHeight = 420;
  static const maxSftpPreviewHeight = 1400;

  factory EmTaskClientSettings.defaults({
    bool shortcutKeysEnabled = false,
    bool terminalKeyboardButtonOnly = false,
    int sftpSmallFileBytes = defaultSftpSmallFileBytes,
    int sftpPreviewHeight = defaultSftpPreviewHeight,
  }) {
    return EmTaskClientSettings(
      shortcutKeysEnabled: shortcutKeysEnabled,
      terminalKeyboardButtonOnly: terminalKeyboardButtonOnly,
      sftpSmallFileBytes: clampSftpSmallFileBytes(sftpSmallFileBytes),
      sftpPreviewHeight: clampSftpPreviewHeight(sftpPreviewHeight),
    );
  }

  factory EmTaskClientSettings.fromJson(Map<String, Object?> json) {
    return EmTaskClientSettings(
      shortcutKeysEnabled: json['shortcutKeysEnabled'] as bool? ?? false,
      terminalKeyboardButtonOnly:
          json['terminalKeyboardButtonOnly'] as bool? ?? false,
      sftpSmallFileBytes: clampSftpSmallFileBytes(
        json['sftpSmallFileBytes'] as int? ?? defaultSftpSmallFileBytes,
      ),
      sftpPreviewHeight: clampSftpPreviewHeight(
        json['sftpPreviewHeight'] as int? ?? defaultSftpPreviewHeight,
      ),
    );
  }

  final bool shortcutKeysEnabled;
  final bool terminalKeyboardButtonOnly;
  final int sftpSmallFileBytes;
  final int sftpPreviewHeight;

  static int clampSftpSmallFileBytes(int value) {
    if (value < minSftpSmallFileBytes) {
      return minSftpSmallFileBytes;
    }
    if (value > maxSftpSmallFileBytes) {
      return maxSftpSmallFileBytes;
    }
    return value;
  }

  static int clampSftpPreviewHeight(int value) {
    if (value < minSftpPreviewHeight) {
      return minSftpPreviewHeight;
    }
    if (value > maxSftpPreviewHeight) {
      return maxSftpPreviewHeight;
    }
    return value;
  }

  Map<String, Object?> toJson() {
    return <String, Object?>{
      'shortcutKeysEnabled': shortcutKeysEnabled,
      'terminalKeyboardButtonOnly': terminalKeyboardButtonOnly,
      'sftpSmallFileBytes': sftpSmallFileBytes,
      'sftpPreviewHeight': sftpPreviewHeight,
    };
  }

  String encode() => jsonEncode(toJson());

  EmTaskClientSettings copyWith({
    bool? shortcutKeysEnabled,
    bool? terminalKeyboardButtonOnly,
    int? sftpSmallFileBytes,
    int? sftpPreviewHeight,
  }) {
    return EmTaskClientSettings(
      shortcutKeysEnabled: shortcutKeysEnabled ?? this.shortcutKeysEnabled,
      terminalKeyboardButtonOnly:
          terminalKeyboardButtonOnly ?? this.terminalKeyboardButtonOnly,
      sftpSmallFileBytes: clampSftpSmallFileBytes(
        sftpSmallFileBytes ?? this.sftpSmallFileBytes,
      ),
      sftpPreviewHeight: clampSftpPreviewHeight(
        sftpPreviewHeight ?? this.sftpPreviewHeight,
      ),
    );
  }
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
    int port = 6024,
    EmTaskPanelAuthMode authMode = EmTaskPanelAuthMode.tokenOtp,
    String token = '',
    String otpSecret = '',
    int otpDigits = 6,
    int otpStepSeconds = 60,
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
      port: json['port'] as int? ?? 6024,
      authMode: json.containsKey('authMode')
          ? EmTaskPanelAuthModeX.fromWireName(json['authMode'] as String?)
          : EmTaskPanelAuthMode.tokenOtp,
      token: json['token'] as String? ?? '',
      otpSecret: json['otpSecret'] as String? ?? '',
      otpDigits: json['otpDigits'] as int? ?? 6,
      otpStepSeconds: json['otpStepSeconds'] as int? ?? 60,
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

  static String newId() => 'panel-${DateTime.now().microsecondsSinceEpoch}';
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
    required this.privateKeyPath,
    required this.privateKeyPassphrase,
    required this.shellKind,
    required this.initialPath,
    required this.supportsSftp,
    required this.panelId,
    required this.panelTaskName,
    required this.panelTaskCommand,
    required this.panelTaskWorkingDir,
    required this.panelTaskSyncName,
    required this.panelTaskSyncHost,
    required this.panelTaskSyncPort,
    required this.panelTaskSyncCommand,
    required this.panelTaskSyncWorkingDir,
    required this.panelTaskSyncSftp,
    this.panelTaskStatus = 'unknown',
    this.panelTaskStatusMessage = '',
    this.panelTaskFailureLog = '',
    this.panelTaskListenerOpen = false,
    this.panelTaskTerminalRunning = false,
    this.panelTaskTerminalFaulted = false,
    this.panelTaskLastExitStatus = 0,
  });

  factory EmTaskSessionProfile.defaults({
    String id = 'default-shell',
    String name = 'emtask shell',
    String host = '127.0.0.1',
    int port = 2222,
    String username = 'emtask',
    String password = 'emtask',
    String privateKeyPath = '',
    String privateKeyPassphrase = '',
    EmTaskShellKind shellKind = EmTaskShellKind.cmd,
    String initialPath = '.',
    bool supportsSftp = false,
    String panelId = '',
    String panelTaskName = '',
    String panelTaskCommand = '',
    String panelTaskWorkingDir = '.',
    bool panelTaskSyncName = true,
    bool panelTaskSyncHost = true,
    bool panelTaskSyncPort = true,
    bool panelTaskSyncCommand = true,
    bool panelTaskSyncWorkingDir = true,
    bool panelTaskSyncSftp = true,
    String panelTaskStatus = 'unknown',
    String panelTaskStatusMessage = '',
    String panelTaskFailureLog = '',
    bool panelTaskListenerOpen = false,
    bool panelTaskTerminalRunning = false,
    bool panelTaskTerminalFaulted = false,
    int panelTaskLastExitStatus = 0,
  }) {
    return EmTaskSessionProfile(
      id: id,
      name: name,
      host: host,
      port: port,
      username: username,
      password: password,
      privateKeyPath: privateKeyPath,
      privateKeyPassphrase: privateKeyPassphrase,
      shellKind: shellKind,
      initialPath: initialPath,
      supportsSftp: supportsSftp,
      panelId: panelId,
      panelTaskName: panelTaskName,
      panelTaskCommand: panelTaskCommand,
      panelTaskWorkingDir: panelTaskWorkingDir,
      panelTaskSyncName: panelTaskSyncName,
      panelTaskSyncHost: panelTaskSyncHost,
      panelTaskSyncPort: panelTaskSyncPort,
      panelTaskSyncCommand: panelTaskSyncCommand,
      panelTaskSyncWorkingDir: panelTaskSyncWorkingDir,
      panelTaskSyncSftp: panelTaskSyncSftp,
      panelTaskStatus: panelTaskStatus,
      panelTaskStatusMessage: panelTaskStatusMessage,
      panelTaskFailureLog: panelTaskFailureLog,
      panelTaskListenerOpen: panelTaskListenerOpen,
      panelTaskTerminalRunning: panelTaskTerminalRunning,
      panelTaskTerminalFaulted: panelTaskTerminalFaulted,
      panelTaskLastExitStatus: panelTaskLastExitStatus,
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
      privateKeyPath: json['privateKeyPath'] as String? ?? '',
      privateKeyPassphrase: json['privateKeyPassphrase'] as String? ?? '',
      shellKind: EmTaskShellKindX.fromWireName(json['shellKind'] as String?),
      initialPath: json['initialPath'] as String? ?? '.',
      supportsSftp: json['supportsSftp'] as bool? ?? false,
      panelId: json['panelId'] as String? ?? '',
      panelTaskName: json['panelTaskName'] as String? ?? '',
      panelTaskCommand: json['panelTaskCommand'] as String? ?? '',
      panelTaskWorkingDir: json['panelTaskWorkingDir'] as String? ?? '.',
      panelTaskSyncName: json['panelTaskSyncName'] as bool? ?? true,
      panelTaskSyncHost: json['panelTaskSyncHost'] as bool? ?? true,
      panelTaskSyncPort: json['panelTaskSyncPort'] as bool? ?? true,
      panelTaskSyncCommand: json['panelTaskSyncCommand'] as bool? ?? true,
      panelTaskSyncWorkingDir: json['panelTaskSyncWorkingDir'] as bool? ?? true,
      panelTaskSyncSftp: json['panelTaskSyncSftp'] as bool? ?? true,
      panelTaskStatus: json['panelTaskStatus'] as String? ?? 'unknown',
      panelTaskStatusMessage: json['panelTaskStatusMessage'] as String? ?? '',
      panelTaskFailureLog: json['panelTaskFailureLog'] as String? ?? '',
      panelTaskListenerOpen: json['panelTaskListenerOpen'] as bool? ?? false,
      panelTaskTerminalRunning:
          json['panelTaskTerminalRunning'] as bool? ?? false,
      panelTaskTerminalFaulted:
          json['panelTaskTerminalFaulted'] as bool? ?? false,
      panelTaskLastExitStatus: json['panelTaskLastExitStatus'] as int? ?? 0,
    );
  }

  final String id;
  final String name;
  final String host;
  final int port;
  final String username;
  final String password;
  final String privateKeyPath;
  final String privateKeyPassphrase;
  final EmTaskShellKind shellKind;
  final String initialPath;
  final bool supportsSftp;
  final String panelId;
  final String panelTaskName;
  final String panelTaskCommand;
  final String panelTaskWorkingDir;
  final bool panelTaskSyncName;
  final bool panelTaskSyncHost;
  final bool panelTaskSyncPort;
  final bool panelTaskSyncCommand;
  final bool panelTaskSyncWorkingDir;
  final bool panelTaskSyncSftp;
  final String panelTaskStatus;
  final String panelTaskStatusMessage;
  final String panelTaskFailureLog;
  final bool panelTaskListenerOpen;
  final bool panelTaskTerminalRunning;
  final bool panelTaskTerminalFaulted;
  final int panelTaskLastExitStatus;

  bool get hasPrivateKey => privateKeyPath.trim().isNotEmpty;

  Map<String, Object?> toJson() {
    return <String, Object?>{
      'id': id,
      'name': name,
      'host': host,
      'port': port,
      'username': username,
      'password': password,
      'privateKeyPath': privateKeyPath,
      'privateKeyPassphrase': privateKeyPassphrase,
      'shellKind': shellKind.wireName,
      'initialPath': initialPath,
      'supportsSftp': supportsSftp,
      'panelId': panelId,
      'panelTaskName': panelTaskName,
      'panelTaskCommand': panelTaskCommand,
      'panelTaskWorkingDir': panelTaskWorkingDir,
      'panelTaskSyncName': panelTaskSyncName,
      'panelTaskSyncHost': panelTaskSyncHost,
      'panelTaskSyncPort': panelTaskSyncPort,
      'panelTaskSyncCommand': panelTaskSyncCommand,
      'panelTaskSyncWorkingDir': panelTaskSyncWorkingDir,
      'panelTaskSyncSftp': panelTaskSyncSftp,
      'panelTaskStatus': panelTaskStatus,
      'panelTaskStatusMessage': panelTaskStatusMessage,
      'panelTaskFailureLog': panelTaskFailureLog,
      'panelTaskListenerOpen': panelTaskListenerOpen,
      'panelTaskTerminalRunning': panelTaskTerminalRunning,
      'panelTaskTerminalFaulted': panelTaskTerminalFaulted,
      'panelTaskLastExitStatus': panelTaskLastExitStatus,
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
    String? privateKeyPath,
    String? privateKeyPassphrase,
    EmTaskShellKind? shellKind,
    String? initialPath,
    bool? supportsSftp,
    String? panelId,
    String? panelTaskName,
    String? panelTaskCommand,
    String? panelTaskWorkingDir,
    bool? panelTaskSyncName,
    bool? panelTaskSyncHost,
    bool? panelTaskSyncPort,
    bool? panelTaskSyncCommand,
    bool? panelTaskSyncWorkingDir,
    bool? panelTaskSyncSftp,
    String? panelTaskStatus,
    String? panelTaskStatusMessage,
    String? panelTaskFailureLog,
    bool? panelTaskListenerOpen,
    bool? panelTaskTerminalRunning,
    bool? panelTaskTerminalFaulted,
    int? panelTaskLastExitStatus,
  }) {
    return EmTaskSessionProfile(
      id: id ?? this.id,
      name: name ?? this.name,
      host: host ?? this.host,
      port: port ?? this.port,
      username: username ?? this.username,
      password: password ?? this.password,
      privateKeyPath: privateKeyPath ?? this.privateKeyPath,
      privateKeyPassphrase: privateKeyPassphrase ?? this.privateKeyPassphrase,
      shellKind: shellKind ?? this.shellKind,
      initialPath: initialPath ?? this.initialPath,
      supportsSftp: supportsSftp ?? this.supportsSftp,
      panelId: panelId ?? this.panelId,
      panelTaskName: panelTaskName ?? this.panelTaskName,
      panelTaskCommand: panelTaskCommand ?? this.panelTaskCommand,
      panelTaskWorkingDir: panelTaskWorkingDir ?? this.panelTaskWorkingDir,
      panelTaskSyncName: panelTaskSyncName ?? this.panelTaskSyncName,
      panelTaskSyncHost: panelTaskSyncHost ?? this.panelTaskSyncHost,
      panelTaskSyncPort: panelTaskSyncPort ?? this.panelTaskSyncPort,
      panelTaskSyncCommand: panelTaskSyncCommand ?? this.panelTaskSyncCommand,
      panelTaskSyncWorkingDir:
          panelTaskSyncWorkingDir ?? this.panelTaskSyncWorkingDir,
      panelTaskSyncSftp: panelTaskSyncSftp ?? this.panelTaskSyncSftp,
      panelTaskStatus: panelTaskStatus ?? this.panelTaskStatus,
      panelTaskStatusMessage:
          panelTaskStatusMessage ?? this.panelTaskStatusMessage,
      panelTaskFailureLog: panelTaskFailureLog ?? this.panelTaskFailureLog,
      panelTaskListenerOpen:
          panelTaskListenerOpen ?? this.panelTaskListenerOpen,
      panelTaskTerminalRunning:
          panelTaskTerminalRunning ?? this.panelTaskTerminalRunning,
      panelTaskTerminalFaulted:
          panelTaskTerminalFaulted ?? this.panelTaskTerminalFaulted,
      panelTaskLastExitStatus:
          panelTaskLastExitStatus ?? this.panelTaskLastExitStatus,
    );
  }

  static String newId() => _newId();

  static String _newId() => 'session-${DateTime.now().microsecondsSinceEpoch}';
}
