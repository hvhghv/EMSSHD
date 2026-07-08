import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

import 'models.dart';

class EmTaskProfileStore {
  static const _profilesKey = 'emtask_client.sessions.v1';
  static const _panelsKey = 'emtask_client.panels.v1';
  static const _settingsKey = 'emtask_client.settings.v1';
  static const _hiddenPanelTasksKey = 'emtask_client.hidden_panel_tasks.v1';

  Future<List<EmTaskSessionProfile>> loadProfiles() async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getStringList(_profilesKey);
    if (saved == null || saved.isEmpty) {
      return <EmTaskSessionProfile>[];
    }

    final profiles = <EmTaskSessionProfile>[];
    for (final item in saved) {
      try {
        final json = jsonDecode(item);
        if (json is Map<String, Object?>) {
          profiles.add(EmTaskSessionProfile.fromJson(json));
        }
      } catch (_) {
        // Ignore broken entries and keep loading valid sessions.
      }
    }

    return profiles;
  }

  Future<void> saveProfiles(List<EmTaskSessionProfile> profiles) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setStringList(
      _profilesKey,
      profiles.map((profile) => profile.encode()).toList(growable: false),
    );
  }

  Future<List<EmTaskPanelProfile>> loadPanels() async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getStringList(_panelsKey);
    if (saved == null || saved.isEmpty) {
      return <EmTaskPanelProfile>[];
    }

    final panels = <EmTaskPanelProfile>[];
    for (final item in saved) {
      try {
        final json = jsonDecode(item);
        if (json is Map<String, Object?>) {
          panels.add(EmTaskPanelProfile.fromJson(json));
        }
      } catch (_) {
        // Ignore broken entries and keep loading valid panels.
      }
    }
    return panels;
  }

  Future<void> savePanels(List<EmTaskPanelProfile> panels) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setStringList(
      _panelsKey,
      panels.map((panel) => panel.encode()).toList(growable: false),
    );
  }

  Future<EmTaskClientSettings> loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getString(_settingsKey);
    if (saved == null || saved.isEmpty) {
      return EmTaskClientSettings.defaults();
    }

    try {
      final json = jsonDecode(saved);
      if (json is Map<String, Object?>) {
        return EmTaskClientSettings.fromJson(json);
      }
    } catch (_) {
      // Ignore broken settings and use safe defaults.
    }
    return EmTaskClientSettings.defaults();
  }

  Future<void> saveSettings(EmTaskClientSettings settings) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_settingsKey, settings.encode());
  }

  Future<Set<String>> loadHiddenPanelTasks() async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getStringList(_hiddenPanelTasksKey);
    if (saved == null || saved.isEmpty) {
      return <String>{};
    }
    return saved
        .map((item) => item.trim())
        .where((item) => item.isNotEmpty)
        .toSet();
  }

  Future<void> saveHiddenPanelTasks(Set<String> hiddenTaskKeys) async {
    final prefs = await SharedPreferences.getInstance();
    final saved = hiddenTaskKeys
        .map((item) => item.trim())
        .where((item) => item.isNotEmpty)
        .toList(growable: false)
      ..sort();
    await prefs.setStringList(_hiddenPanelTasksKey, saved);
  }
}
