package com.emtask.emtask_client

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import androidx.core.content.FileProvider
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.BufferedInputStream
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import java.util.zip.ZipInputStream

class MainActivity: FlutterActivity() {
    private val apkInstallerChannel = "github_updater/apk_installer"
    private val windowChannel = "emtask_client/window"
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            apkInstallerChannel
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "downloadAndInstallApk" -> {
                    val args = call.arguments as? Map<*, *>
                    val url = args?.get("url") as? String
                    val name = args?.get("name") as? String ?: "update.apk"
                    val token = args?.get("token") as? String
                    val isActionArtifactZip =
                        args?.get("isActionArtifactZip") as? Boolean ?: false
                    if (url.isNullOrBlank()) {
                        result.error("bad_args", "Missing APK download url", null)
                        return@setMethodCallHandler
                    }
                    Thread {
                        runCatching {
                            downloadUpdatePackage(
                                url = url,
                                name = name,
                                token = token,
                                isActionArtifactZip = isActionArtifactZip,
                            )
                        }.onSuccess {
                            mainHandler.post {
                                runCatching {
                                    launchApkInstaller(it)
                                }.onSuccess {
                                    result.success(null)
                                }.onFailure { error ->
                                    result.error(
                                        "install_failed",
                                        error.message ?: error.javaClass.simpleName,
                                        null,
                                    )
                                }
                            }
                        }.onFailure { error ->
                            mainHandler.post {
                                result.error(
                                    "install_failed",
                                    error.message ?: error.javaClass.simpleName,
                                    null,
                                )
                            }
                        }
                    }.start()
                }
                else -> result.notImplemented()
            }
        }
        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            windowChannel
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "setSoftInputMode" -> {
                    val args = call.arguments as? Map<*, *>
                    val mode = (args?.get("mode") as? String) ?: (call.arguments as? String)
                    setSoftInputMode(mode)
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }
    }

    private fun downloadUpdatePackage(
        url: String,
        name: String,
        token: String?,
        isActionArtifactZip: Boolean,
    ): File {
        val safeName = name.replace(Regex("[^A-Za-z0-9._-]"), "_")
        val updateDir = File(cacheDir, "github-updater/${UUID.randomUUID()}")
        if (!updateDir.mkdirs()) {
            throw IllegalStateException("Cannot create update directory")
        }
        val target = File(updateDir, if (isActionArtifactZip) "$safeName.zip" else safeName)
        downloadFile(url, token, target)
        if (!isActionArtifactZip) {
            if (!target.name.endsWith(".apk", ignoreCase = true)) {
                throw IllegalStateException("Downloaded file is not an APK: ${target.name}")
            }
            return target
        }
        return extractSingleApk(target, updateDir)
    }

    private fun downloadFile(url: String, token: String?, target: File) {
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.instanceFollowRedirects = true
        connection.setRequestProperty("Accept", "application/vnd.github+json")
        connection.setRequestProperty("User-Agent", "github-updater-android")
        if (!token.isNullOrBlank()) {
            connection.setRequestProperty("Authorization", "Bearer ${token.trim()}")
        }
        connection.connectTimeout = 30000
        connection.readTimeout = 30000
        try {
            val status = connection.responseCode
            if (status !in 200..299) {
                throw IllegalStateException("Download failed: HTTP $status")
            }
            BufferedInputStream(connection.inputStream).use { input ->
                FileOutputStream(target).use { output ->
                    input.copyTo(output)
                }
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun extractSingleApk(zipFile: File, outputDir: File): File {
        val apks = mutableListOf<File>()
        ZipInputStream(BufferedInputStream(zipFile.inputStream())).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                if (!entry.isDirectory && entry.name.endsWith(".apk", ignoreCase = true)) {
                    val apk = File(outputDir, File(entry.name).name)
                    FileOutputStream(apk).use { output ->
                        zip.copyTo(output)
                    }
                    apks += apk
                }
                zip.closeEntry()
            }
        }
        if (apks.isEmpty()) {
            throw IllegalStateException("No APK found in action artifact")
        }
        if (apks.size > 1) {
            throw IllegalStateException("Multiple APK files found in action artifact")
        }
        return apks.single()
    }

    private fun setSoftInputMode(mode: String?) {
        val softInputMode = when (mode) {
            "adjustNothing" -> WindowManager.LayoutParams.SOFT_INPUT_ADJUST_NOTHING
            "adjustResize" -> WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE
            else -> WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE
        }
        mainHandler.post {
            window.setSoftInputMode(softInputMode)
        }
    }

    private fun launchApkInstaller(apk: File) {
        val uri: Uri = FileProvider.getUriForFile(
            this,
            "${applicationContext.packageName}.fileprovider",
            apk,
        )
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        try {
            startActivity(intent)
        } catch (error: ActivityNotFoundException) {
            throw IllegalStateException("No system APK installer is available", error)
        }
    }
}
