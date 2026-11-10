package com.aiapp.data

import com.aiapp.builder.ReaEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

object AttachmentStore {
    // Fix type inference by specifying generic type explicitly
    fun processAttachment(file: File): ReaEngine.ExtractedResourcesBundle? = withContext(Dispatchers.IO) {
        // TODO: implement actual attachment processing
        null
    }
}
