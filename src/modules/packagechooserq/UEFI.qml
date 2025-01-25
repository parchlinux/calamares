/* === This file is part of Calamares - <https://calamares.io> ===
 *
 *   SPDX-FileCopyrightText: 2021 Anke Boersma <demm@kaosx.us>
 *   SPDX-License-Identifier: GPL-3.0-or-later
 *
 *   Calamares is Free Software: see the License-Identifier above.
 *
 */

import io.calamares.core 1.0
import io.calamares.ui 1.0

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.3

Column {
    id: column
    anchors.centerIn: parent
    spacing: 7

    ButtonGroup {
        id: switchGroup
    }

    Rectangle {
        //id: rectangle
        width: 700
        height: 50
        color: "#2a2e32"
        border.width: 0
        Text {
            height: 25
            anchors.centerIn: parent
            text: qsTr("Please select a <strong>bootloader</strong> option for your install, or leave the already selected default option, <strong>Systemd-boot</strong>.")
            font.pointSize: 11
            color: "#ffffff"
            wrapMode: Text.WordWrap
        }
    }

    Rectangle {
        width: 700
        height: 135
        color: "#1b1e20"
        radius: 5
        border.width: 1
        border.color: "#646b75"
        Text {
            width: 600
            height: 90
            anchors.centerIn: parent
            text: qsTr("<strong>Systemd-boot</strong><br><br>provides a simple experience<br>which will work for most circumstances.<br>This is the default option for <strong>Parch Linux</strong>.")
            font.pointSize: 10
            color: "#ffffff"
            anchors.verticalCenterOffset: 0
            anchors.horizontalCenterOffset: -20.0
            wrapMode: Text.WordWrap
        }

        Switch {
            id: element2
            x: 500
            y: 90
            width: 187
            height: 14
            text: qsTr("Systemd-boot")
            checked: true
            hoverEnabled: true
            ButtonGroup.group: switchGroup

            indicator: Rectangle {
                implicitWidth: 40
                implicitHeight: 14
                radius: 10
                color: element2.checked ? "#3498db" : "#B9B9B9"
                border.color: element2.checked ? "#3498db" : "#cccccc"

                Rectangle {
                    x: element2.checked ? parent.width - width : 0
                    y: (parent.height - height) / 2
                    width: 20
                    height: 20
                    radius: 10
                    color: element2.down ? "#cccccc" : "#ffffff"
                    border.color: element2.checked ? (element2.down ? "#3498db" : "#3498db") : "#999999"
                }
            }

            onCheckedChanged: {
                if (! checked) {
                    print("systemd not used")
                } else {
                    config.packageChoice = "systemd-boot"
                    print(config.packageChoice)
                }
            }
        }
    }
 }

