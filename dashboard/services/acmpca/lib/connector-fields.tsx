"use client";

// A SCEP connector is general purpose (static challenge passwords) or for
// Microsoft Intune; only Intune asks for its Azure application.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { PresetGallery } from "@mws-dashboard/ui/presets";
import { KeyRound } from "lucide-react";
import { useState } from "react";

const KINDS = [
  { id: "GENERAL_PURPOSE", label: "General purpose", title: "Devices enroll with challenge passwords", icon: <KeyRound size={26} aria-hidden /> },
  { id: "INTUNE", label: "Intune", title: "Microsoft Intune enrolls devices", icon: "ai/microsoft" },
];

export function ConnectorKind() {
  const [kind, setKind] = useState("GENERAL_PURPOSE");
  return (
    <>
      <PresetGallery label="Connector type" presets={KINDS} chosen={kind} choose={(k) => setKind(k.id)} testId="connector-type" />
      <input type="hidden" name="type" value={kind} />
      {kind === "INTUNE" && (
        <div className="form-row">
          <FieldShell label="Azure application ID" member="MobileDeviceManagement.Intune.AzureApplicationId">
            <input name="azureApp" required />
          </FieldShell>
          <FieldShell label="Domain" member="MobileDeviceManagement.Intune.Domain" format="domain">
            <input name="azureDomain" required placeholder="contoso.onmicrosoft.com" />
          </FieldShell>
        </div>
      )}
    </>
  );
}
