/* === This file is part of Calamares - <https://calamares.io> ===
 *
 *   SPDX-FileCopyrightText: 2026 Parch Linux
 *   SPDX-License-Identifier: GPL-3.0-or-later
 *
 *   Calamares is Free Software: see the License-Identifier above.
 *
 *   Fallback page for the Parch Settings step. A branded copy of this
 *   page (parchsettings.qml in the branding directory) takes precedence
 *   at runtime.
 */

import io.calamares.core 1.0
import io.calamares.ui 1.0

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

Kirigami.ScrollablePage {
    width: parent.width
    height: parent.height

    header: Kirigami.Heading {
        Layout.fillWidth: true
        height: 50
        horizontalAlignment: Qt.AlignHCenter
        text: qsTr("Parch Settings")
    }

    ColumnLayout {
        width: parent.width
        spacing: Kirigami.Units.smallSpacing

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: qsTr("Fine-tune how Parch Linux is set up. Everything here can also be changed after installation.")
        }

        SwitchDelegate {
            Layout.fillWidth: true
            text: qsTr("Import data from a previous installation")
            checked: config.migrationEnabled
            onToggled: config.migrationEnabled = checked
        }
        SwitchDelegate {
            Layout.fillWidth: true
            text: qsTr("Use display scaling for HiDPI screens")
            checked: config.hidpiEnabled
            onToggled: config.hidpiEnabled = checked
        }
        SwitchDelegate {
            Layout.fillWidth: true
            text: qsTr("Limit battery charging to extend battery life")
            checked: config.batteryGuardEnabled
            onToggled: config.batteryGuardEnabled = checked
        }
        Slider {
            Layout.fillWidth: true
            from: 50
            to: 100
            stepSize: 1
            value: config.chargeLimit
            onMoved: config.chargeLimit = value
        }
        SwitchDelegate {
            Layout.fillWidth: true
            text: qsTr("Use compressed RAM swap (zram) when no disk swap is set")
            checked: config.zramEnabled
            onToggled: config.zramEnabled = checked
        }

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: qsTr("Hardware clock mode")
        }

        RowLayout {
            RadioButton {
                text: qsTr("Automatic")
                checked: config.rtcMode == "auto"
                onToggled: config.rtcMode = "auto"
            }
            RadioButton {
                text: qsTr("Local time (Windows style)")
                checked: config.rtcMode == "localtime"
                onToggled: config.rtcMode = "localtime"
            }
            RadioButton {
                text: qsTr("UTC")
                checked: config.rtcMode == "utc"
                onToggled: config.rtcMode = "utc"
            }
        }
    }
}
