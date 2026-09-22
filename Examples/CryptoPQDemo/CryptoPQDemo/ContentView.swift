import SwiftUI

struct ContentView: View {
    @StateObject private var model = DemoModel()

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text("A KEM makes the shared secret. HKDF turns it into an AEAD key. ML-DSA-65 signs the ciphertext before it is opened.")
                        .font(.subheadline)
                        .foregroundColor(.secondary)

                    pickerCard(title: "Key encapsulation") {
                        Picker("KEM", selection: $model.kem) {
                            ForEach(DemoModel.KEMKind.allCases) { kind in
                                Text(kind.rawValue).tag(kind)
                            }
                        }
                        .pickerStyle(.segmented)
                    }

                    pickerCard(title: "Authenticated encryption") {
                        Picker("Cipher", selection: $model.cipher) {
                            ForEach(DemoModel.CipherKind.allCases) { kind in
                                Text(kind.rawValue).tag(kind)
                            }
                        }
                        .pickerStyle(.segmented)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        Text("Message")
                            .font(.headline)
                        TextEditor(text: $model.plaintext)
                            .frame(minHeight: 100)
                            .padding(8)
                            .background(Color(uiColor: .secondarySystemBackground))
                            .cornerRadius(10)
                    }

                    VStack(spacing: 12) {
                        Button(action: model.encryptAndSign) {
                            Label("Encrypt and sign", systemImage: "lock.fill")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.isBusy || model.plaintext.isEmpty)

                        Button(action: model.decryptAndVerify) {
                            Label("Verify and decrypt", systemImage: "lock.open.fill")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .disabled(model.isBusy)

                        Button("New keys", action: model.regenerateKeys)
                            .font(.footnote)
                            .disabled(model.isBusy)
                    }

                    resultCard
                }
                .padding()
            }
            .navigationTitle("CryptoPQ")
        }
        .navigationViewStyle(.stack)
    }

    private func pickerCard<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)
            content()
        }
    }

    private var resultCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(model.status)
                .font(.body)

            if let signatureValid = model.signatureValid {
                Label(
                    signatureValid ? "ML-DSA-65 signature valid" : "ML-DSA-65 signature rejected",
                    systemImage: signatureValid ? "checkmark.seal.fill" : "xmark.seal.fill"
                )
                .foregroundColor(signatureValid ? .green : .red)
            }

            if !model.recovered.isEmpty {
                Text(model.recovered)
                    .font(.system(.body, design: .monospaced))
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(uiColor: .secondarySystemBackground))
                    .cornerRadius(8)
            }

            ForEach(Array(model.steps.enumerated()), id: \.offset) { _, step in
                Text(step)
                    .font(.footnote)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(uiColor: .tertiarySystemBackground))
        .cornerRadius(12)
    }
}
