package com.aiapp.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicReference

class ChatViewModel : ViewModel() {
    // Initialize githubUser to avoid "must be initialized" error
    var githubUser: String = ""

    // Other view model properties and functions...
    // This is a minimal stub to satisfy compilation.
    // The actual implementation should be provided by the project.
}
