"use client";

// A new document starts from what it is for: a shell or PowerShell command,
// an automation runbook, a session profile or a change calendar. The choice
// fills type, format and a working sample; the rest waits under More.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateDocument } from "@mws-dashboard/ui/model/ssm";
import { freeName, MoreFields, PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import { SquareTerminal, Wrench } from "lucide-react";
import { useState } from "react";

const TYPES = ["Command", "Automation", "Session", "Policy", "ChangeCalendar", "Package", "Automation.ChangeTemplate"];

interface Kind extends PresetItem {
  type: string;
  format: "YAML" | "JSON" | "TEXT";
  base: string;
  targetType?: string;
  content: string;
}

const SHELL = `schemaVersion: "2.2"
description: Say hello
parameters:
  name:
    type: String
    default: world
mainSteps:
  - action: aws:runShellScript
    name: hello
    inputs:
      runCommand:
        - echo "hello {{ name }}"
`;

const POWERSHELL = `schemaVersion: "2.2"
description: Say hello
parameters:
  name:
    type: String
    default: world
mainSteps:
  - action: aws:runPowerShellScript
    name: hello
    precondition:
      StringEquals: [platformType, Windows]
    inputs:
      runCommand:
        - Write-Output "hello {{ name }}"
`;

const AUTOMATION = `schemaVersion: "0.3"
description: Wait, then finish
parameters:
  wait:
    type: String
    default: PT5S
mainSteps:
  - name: wait
    action: aws:sleep
    inputs:
      Duration: "{{ wait }}"
`;

const SESSION = `schemaVersion: "1.0"
description: Shell session that starts in the home directory
sessionType: Standard_Stream
inputs:
  shellProfile:
    linux: cd ~ && exec bash
    windows: ""
`;

const CALENDAR = `BEGIN:VCALENDAR
PRODID:-//AWS//Change Calendar 1.0//EN
VERSION:2.0
X-CALENDAR-TYPE:DEFAULT_OPEN
X-WR-CALDESC:
END:VCALENDAR
`;

const KINDS: Kind[] = [
  { id: "shell", label: "Shell script", icon: "brand/gnubash", type: "Command", format: "YAML", base: "Run-Shell", targetType: "/AWS::EC2::Instance", content: SHELL },
  { id: "powershell", label: "PowerShell", icon: <SquareTerminal size={26} aria-hidden />, type: "Command", format: "YAML", base: "Run-PowerShell", targetType: "/AWS::EC2::Instance", content: POWERSHELL },
  { id: "automation", label: "Runbook", icon: "resource/AWSSystemsManagerAutomation", type: "Automation", format: "YAML", base: "Runbook", content: AUTOMATION, title: "Automation runbook" },
  { id: "session", label: "Session", icon: "resource/AWSSystemsManagerSessionManager", type: "Session", format: "YAML", base: "Session-Profile", content: SESSION, title: "Session Manager preferences" },
  { id: "calendar", label: "Calendar", icon: "resource/AWSSystemsManagerChangeCalendar", type: "ChangeCalendar", format: "TEXT", base: "Change-Calendar", content: CALENDAR, title: "Change Calendar (open by default)" },
  { id: "custom", label: "Custom", icon: <Wrench size={22} aria-hidden />, type: "Command", format: "YAML", base: "Document", content: "" },
];

export function DocumentFields({ taken }: { taken: string[] }) {
  const [kind, setKind] = useState<Kind>(KINDS[0]);
  const custom = kind.id === "custom";
  return (
    <>
      <PresetGallery presets={KINDS.map((k) => ({ ...k, added: taken.includes(k.base) }))} chosen={kind.id} choose={(k) => setKind(KINDS.find((x) => x.id === k.id)!)} label="Document" size={26} />
      <div key={kind.id} className="preset-fields">
        <FieldShell label="Name" rule={CreateDocument.Name} unique taken={taken} generate="name">
          <input name="name" required defaultValue={custom ? undefined : freeName(kind.base, taken)} placeholder="Hello-World" />
        </FieldShell>
        {custom ? (
          <div className="form-row">
            <FieldShell label="Type" rule={CreateDocument.DocumentType}>
              <select name="type" defaultValue="Command">
                {TYPES.map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </FieldShell>
            <FieldShell label="Format" rule={CreateDocument.DocumentFormat}>
              <select name="format" defaultValue="YAML">
                <option>YAML</option>
                <option>JSON</option>
                <option>TEXT</option>
              </select>
            </FieldShell>
          </div>
        ) : (
          <>
            <input type="hidden" name="type" value={kind.type} />
            <input type="hidden" name="format" value={kind.format} />
          </>
        )}
        <FieldShell label="Content" rule={{ ...CreateDocument.Content, format: kind.format === "YAML" && !custom ? "yaml" : undefined }}>
          <textarea name="content" rows={14} className="code-editor" spellCheck={false} defaultValue={kind.content} required />
        </FieldShell>
        <MoreFields>
          <div className="form-row">
            <FieldShell label="Target type" rule={CreateDocument.TargetType}>
              <input name="targetType" defaultValue={kind.targetType} placeholder="/AWS::EC2::Instance" />
            </FieldShell>
            <FieldShell label="Version name" rule={CreateDocument.VersionName}>
              <input name="versionName" />
            </FieldShell>
          </div>
          <FieldShell label="Tags" format="tags">
            <textarea name="tags" rows={2} />
          </FieldShell>
        </MoreFields>
      </div>
    </>
  );
}
