import LocalAuthentication
import SwiftRs
import Tauri
import UIKit
import WebKit

/// iOS part of the SecCorp device plugin.
///
/// iOS apps are sandboxed: they cannot inspect other apps or the system, so
/// the only native capability needed is the device security posture.
class DevicePlugin: Plugin {
  @objc public func deviceSecurity(_ invoke: Invoke) throws {
    let context = LAContext()
    var passcodeError: NSError?
    let passcode = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &passcodeError)
    var biometricError: NSError?
    let biometrics = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &biometricError)

    var biometryType = "none"
    switch context.biometryType {
    case .faceID:
      biometryType = "faceId"
    case .touchID:
      biometryType = "touchId"
    default:
      biometryType = biometrics ? "other" : "none"
    }

    invoke.resolve([
      "platform": "ios",
      "osVersion": UIDevice.current.systemVersion,
      "model": UIDevice.current.model,
      "manufacturer": "Apple",
      "screenLock": passcode,
      "biometrics": biometrics,
      "biometryType": biometryType,
    ])
  }
}

@_cdecl("init_plugin_seccom_device")
public func initPlugin() -> Plugin {
  return DevicePlugin()
}
