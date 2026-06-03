import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

import 'models.dart';

class EmTaskProfileStore {
  static const _profilesKey = 'emtask_client.sessions.v1';
  static const _panelsKey = 'emtask_client.panels.v1';

  Future<List<EmTaskSessionProfile>> loadProfiles() async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getStringList(_profilesKey);
    if (saved == null || saved.isEmpty) {
      return <EmTaskSessionProfile>[
        EmTaskSessionProfile.defaults(),
        EmTaskSessionProfile.defaults(
          id: 'default-powershell',
          name: 'emtask powershell',
          port: 2223,
          shellKind: EmTaskShellKind.powershell,
        ),
      ];
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

    return profiles.isEmpty
        ? <EmTaskSessionProfile>[EmTaskSessionProfile.defaults()]
        : profiles;
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
      return const <EmTaskPanelProfile>[];
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
}
