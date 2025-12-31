//
//  ContentView.swift
//  NFCTagWriter
//
//  Created by 刘平安 on 11/26/25.
//
import Foundation
import SwiftUI
import CoreNFC


struct ContentView: View {
    @State private var scanner = NFCScanner()
    @State private var nfcMessage: String = ""
    @State private var nfcError: String = ""
    
    @State private var textPassword: String = ""
    @State private var textRead: String = ""
    @State private var textToWrite: String = ""
    @State private var tagInfo: NFCTagInfo? = nil
    @State private var alertMessage: String = ""
    @State private var showAlert: Bool = false
    @State private var writeOnlyProtection: Bool = true  // Default: Write Protected Only (Read full access)
    @FocusState private var isTextFieldFocused: Bool
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    Image(systemName: "sensor.tag.radiowaves.forward")
                        .imageScale(.large)
                        .foregroundStyle(.tint)
                        .font(.system(size: 50))
                    
                    Text("NFC Tag Reader/Writer")
                        .font(.title2)
                        .fontWeight(.bold)
                    
                    Text("NTAG213/215/216 Support")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    // Navigation to NTAG 424 View
                    NavigationLink(destination: NTAG424View()) {
                        HStack {
                            Image(systemName: "lock.shield.fill")
                            Text("NTAG 424 DNA")
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .font(.headline)
                        .foregroundColor(.white)
                        .padding()
                        .frame(maxWidth: .infinity)
                        .background(Color.indigo)
                        .cornerRadius(10)
                    }
                    .padding(.horizontal)
                    
                    Divider()
            
            // Display read result above Read Button
            VStack(alignment: .leading, spacing: 8) {
                Text("Read Result:")
                    .font(.headline)
                Text(textRead)
                    .font(.body)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.gray.opacity(0.1))
                    .cornerRadius(8)
            }
            .padding(.horizontal)
            
            // Read Button
            Button(action: {
                readNFC()
            }) {
                HStack {
                    Image(systemName: "arrow.down.circle.fill")
                    Text("Read NFC Tag")
                }
                .font(.headline)
                .foregroundColor(.white)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color.blue)
                .cornerRadius(10)
            }
            .padding(.horizontal)
            
            // TextField for input text to write
            VStack(alignment: .leading, spacing: 8) {
                Text("Text to Write:")
                    .font(.headline)
                TextField("Enter URL or text (e.g., https://example.com)", text: $textToWrite)
                    .textFieldStyle(.roundedBorder)
                    .focused($isTextFieldFocused)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .submitLabel(.done)
            }
            .padding(.horizontal)
            
            // Write Button
            Button(action: {
                writeNFC()
            }) {
                HStack {
                    Image(systemName: "arrow.up.circle.fill")
                    Text("Write NFC Tag")
                }
                .font(.headline)
                .foregroundColor(.white)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color.green)
                .cornerRadius(10)
            }
            .padding(.horizontal)
            
            // Password Input Section
            VStack(alignment: .leading, spacing: 8) {
                Text("Password (Optional):")
                    .font(.headline)
                Text("4-character password for tag protection")
                    .font(.caption)
                    .foregroundColor(.secondary)
                TextField("Enter 4-character password", text: $textPassword)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.asciiCapable)
                    .submitLabel(.done)
                    .onChange(of: textPassword) { oldValue, newValue in
                        // Limit to 4 characters
                        if newValue.count > 4 {
                            textPassword = String(newValue.prefix(4))
                        }
                    }
            }
            .padding(.horizontal)
            
            // Protection Mode Toggle
            VStack(alignment: .leading, spacing: 8) {
                Text("Password Protection Mode:")
                    .font(.headline)
                Picker("Protection Mode", selection: $writeOnlyProtection) {
                    Text("Write Protected").tag(true)
                    Text("Read & Write Protected").tag(false)
                }
                .pickerStyle(.segmented)
            }
            .padding(.horizontal)
            
            // Set Password Button
            Button(action: {
                setPassword()
            }) {
                HStack {
                    Image(systemName: "lock.fill")
                    Text("Set Password")
                }
                .font(.headline)
                .foregroundColor(.white)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color.orange)
                .cornerRadius(10)
            }
            .padding(.horizontal)
            .disabled(textPassword.isEmpty)
            
            // Read Tag Info Button
            Button(action: {
                readTagInfo()
            }) {
                HStack {
                    Image(systemName: "info.circle.fill")
                    Text("Read Tag Information")
                }
                .font(.headline)
                .foregroundColor(.white)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color.purple)
                .cornerRadius(10)
            }
            .padding(.horizontal)
            
            // Display read results
            if !nfcMessage.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("NFC Message:")
                        .font(.headline)
                    Text(nfcMessage)
                        .font(.body)
                        .padding()
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(8)
                }
                .padding()
            }
            
            if !nfcError.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("NFC Error:")
                        .font(.headline)
                        .foregroundColor(.red)
                    Text(nfcError)
                        .font(.body)
                        .foregroundColor(.red)
                        .padding()
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(8)
                }
                .padding()
            }
            
            // Tag Information Display at the bottom
            if let info = tagInfo {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Tag Information:")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(info.details.components(separatedBy: "\n").enumerated()), id: \.offset) { index, line in
                            Text(line)
                                .font(.system(.caption, design: .monospaced))
                        }
                    }
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.blue.opacity(0.1))
                    .cornerRadius(8)
                }
                .padding()
            }
                }
                .padding()
            }
            .navigationTitle("NFC Tags")
            .navigationBarTitleDisplayMode(.inline)
            .alert("Rule Status", isPresented: $showAlert) {
                Button("OK", role: .cancel) { }
            } message: {
                Text(alertMessage)
            }
            .scrollDismissesKeyboard(.interactively)
        }
    }
    
    private func readNFC() {
        nfcMessage = ""
        nfcError = ""
        scanner.onWriteCompleted = nil
        scanner.onReadCompleted = { text, message, error in
            DispatchQueue.main.async {
                if let error = error {
                    nfcError = error.localizedDescription
                    nfcMessage = ""
                } else if let message = message {
                    nfcMessage = message
                    nfcError = ""
                }
                textRead = text
                
                // Parse URL and handle rule activation/deactivation
                if !text.isEmpty {
                    handleRuleFromText(text)
                }
            }
        }
        
        scanner.beginReading(password: textPassword)
    }
    
    // Parse URL and extract rule number, toggle state, show alert
    // This is an optional feature for specific URL formats
    private func handleRuleFromText(_ text: String) {
        // Optional: Handle specific URL patterns if needed
        // This can be customized for different use cases
        guard let url = URL(string: text),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
              let ruleItem = components.queryItems?.first(where: { $0.name == "rule" }),
              let ruleString = ruleItem.value,
              let ruleNumber = Int(ruleString) else {
            return
        }
        
        // Get current state from UserDefaults
        let key = "rule_\(ruleNumber)_activated"
        let currentState = UserDefaults.standard.bool(forKey: key)
        
        // Toggle state
        let newState = !currentState
        UserDefaults.standard.set(newState, forKey: key)
        
        // Show alert with new state
        let status = newState ? "activated" : "deactivated"
        alertMessage = "Rule \(ruleNumber) is \(status)"
        showAlert = true
        
        print("📋 Rule \(ruleNumber) toggled: \(currentState ? "activated" : "deactivated") -> \(newState ? "activated" : "deactivated")")
    }
    
    private func readTagInfo() {
        nfcError = ""
        scanner.onReadCompleted = nil
        scanner.onWriteCompleted = nil
        scanner.onSetPasswordCompleted = nil
        scanner.onTagInfoCompleted = { info, error in
            DispatchQueue.main.async {
                if let error = error {
                    // Show error but don't clear existing tag info
                    nfcError = "Tag Info Error: \(error.localizedDescription)"
                    print("Tag info read error: \(error.localizedDescription)")
                } else if let info = info {
                    tagInfo = info
                    nfcError = ""
                }
            }
        }
        scanner.beginReadingTagInfo()
    }
    
    private func writeNFC() {
        nfcMessage = ""
        nfcError = ""
        scanner.onReadCompleted = nil
        scanner.onSetPasswordCompleted = nil
        scanner.onWriteCompleted = { (msg, error) in
            DispatchQueue.main.async {
                if let error = error {
                    nfcError = "Write Error: \(error.localizedDescription)"
                } else {
                    nfcMessage = "Write Successful!"
                }
            }
        }
        scanner.beginWriting(password: textPassword, textToWrite: textToWrite)
    }
    
    private func setPassword() {
        nfcMessage = ""
        nfcError = ""
        
        guard !textPassword.isEmpty else {
            nfcError = "Please enter a password"
            return
        }
        
        guard textPassword.count == 4 else {
            nfcError = "Password must be exactly 4 characters"
            return
        }
        
        scanner.onReadCompleted = nil
        scanner.onWriteCompleted = nil
        scanner.textPassword = textPassword
        scanner.onSetPasswordCompleted = { (msg, error) in
            DispatchQueue.main.async {
                if let error = error {
                    nfcError = "Set Password Error: \(error.localizedDescription)"
                    nfcMessage = ""
                } else if let message = msg {
                    nfcMessage = message
                    nfcError = ""
                } else {
                    nfcMessage = "Password set successfully!"
                    nfcError = ""
                }
            }
        }
        scanner.beginSettingPassword(password: textPassword, writeOnlyProtection: writeOnlyProtection)
    }
}

#Preview {
    ContentView()
}
