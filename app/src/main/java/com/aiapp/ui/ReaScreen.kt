package com.aiapp.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aiapp.builder.ReaEngine
import com.aiapp.builder.ReaEngine.ReaApkSummary
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

@Composable
fun ReaScreen(
    onBack: () -> Unit,
    apkFile: java.io.File,
    onResult: (ReaApkSummary) -> Unit
) {
    var summary by remember { mutableStateOf<ReaApkSummary?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(scrollState).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Button(onClick = onBack) {
            Text("Back")
        }

        Text("REA Analysis", fontSize = 24.sp, fontWeight = FontWeight.Bold)

        if (loading) {
            Text("Analyzing APK…", fontSize = 16.sp)
        } else if (error != null) {
            Text("Error: $error", fontSize = 16.sp, color = Color.Red)
        } else if (summary != null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = androidx.compose.material3.CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Package: ${summary!!.packageName}", fontSize = 16.sp)
                    Text("App Label: ${summary!!.appLabel}", fontSize = 16.sp)
                    Text("Version: ${summary!!.versionName} (${summary!!.versionCode})", fontSize = 16.sp)
                    Text("Min SDK: ${summary!!.minSdk}, Target SDK: ${summary!!.targetSdk}", fontSize = 16.sp)
                    Text("SHA-256: ${summary!!.signatureReport.sha256Digest.take(32)}…", fontSize = 14.sp)
                    Text("Signing: ${summary!!.signatureReport.schemesSummary}", fontSize = 14.sp)
                    Text("DEX files: ${summary!!.dexFileCount}", fontSize = 14.sp)
                    Text("Classes: ${summary!!.classesCount}", fontSize = 14.sp)
                    Text("Methods: ${summary!!.methodsCount}", fontSize = 14.sp)
                    Text("Fields: ${summary!!.fieldsCount}", fontSize = 14.sp)
                    Text("Drawables: ${summary!!.drawablesCount}", fontSize = 14.sp)
                    Text("Layouts: ${summary!!.layouts.size}", fontSize = 14.sp)
                    Text("Assets: ${summary!!.assets.size}", fontSize = 14.sp)
                    Text("Native libs: ${summary!!.nativeLibraries.size}", fontSize = 14.sp)
                    Text("Permissions: ${summary!!.permissions.size}", fontSize = 14.sp)
                    Text("Activities: ${summary!!.activities.size}", fontSize = 14.sp)
                    Text("Services: ${summary!!.services.size}", fontSize = 14.sp)
                    Text("Receivers: ${summary!!.receivers.size}", fontSize = 14.sp)
                    Text("Providers: ${summary!!.providers.size}", fontSize = 14.sp)
                    Text("Network URLs: ${summary!!.networkUrls.size}", fontSize = 14.sp)
                    Text("UI Strings: ${summary!!.stringConstants.size}", fontSize = 14.sp)
                }
            }
            Button(onClick = { onResult(summary!!) }) {
                Text("Use This APK for Reconstruction", fontSize = 16.sp)
            }
        } else {
            Button(onClick = {
                loading = true
                error = null
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        val result = ReaEngine.inspectApk(apkFile)
                        androidx.compose.runtime.Snapshot.sendApplyNotifications()
                        summary = result
                    } catch (e: Exception) {
                        error = e.message ?: "Unknown error"
                    } finally {
                        loading = false
                    }
                }
            }) {
                Text("Start Analysis", fontSize = 16.sp)
            }
        }
    }
}

@Composable
fun ReaImportScreen(
    onBack: () -> Unit,
    apkFile: java.io.File,
    onResult: (ReaApkSummary) -> Unit
) {
    var summary by remember { mutableStateOf<ReaApkSummary?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Button(onClick = onBack) {
            Text("Back")
        }

        Text("Import APK", fontSize = 24.sp, fontWeight = FontWeight.Bold)

        if (loading) {
            Text("Importing APK…", fontSize = 16.sp)
        } else if (error != null) {
            Text("Error: $error", fontSize = 16.sp, color = Color.Red)
        } else if (summary != null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = androidx.compose.material3.CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Package: ${summary!!.packageName}", fontSize = 16.sp)
                    Text("App Label: ${summary!!.appLabel}", fontSize = 16.sp)
                    Text("Version: ${summary!!.versionName} (${summary!!.versionCode})", fontSize = 16.sp)
                    Text("SHA-256: ${summary!!.signatureReport.sha256Digest.take(32)}…", fontSize = 14.sp)
                    Text("Signing: ${summary!!.signatureReport.schemesSummary}", fontSize = 14.sp)
                    Text("Reusable resources: ${summary!!.reusableResourcePaths.size}", fontSize = 14.sp)
                }
            }
            Button(onClick = { onResult(summary!!) }) {
                Text("Import Resources", fontSize = 16.sp)
            }
        } else {
            Button(onClick = {
                loading = true
                error = null
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        val result = ReaEngine.importApk(apkFile)
                        androidx.compose.runtime.Snapshot.sendApplyNotifications()
                        summary = result
                    } catch (e: Exception) {
                        error = e.message ?: "Unknown error"
                    } finally {
                        loading = false
                    }
                }
            }) {
                Text("Import", fontSize = 16.sp)
            }
        }
    }
}
