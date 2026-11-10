"use client";

// The create-template form: start from a common transactional email (or a
// blank one); each fills a unique name, subject, text and HTML with the
// {{placeholders}} it uses.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import type { Rule } from "@mws-dashboard/ui/validation";
import { FilePlus2, KeyRound, PackageCheck, PartyPopper, Receipt } from "lucide-react";
import { useState, type ReactNode } from "react";

interface TemplatePreset {
  id: string;
  label: string;
  icon: ReactNode;
  name: string;
  subject?: string;
  text?: string;
  html?: string;
}

const PRESETS: TemplatePreset[] = [
  { id: "blank", label: "Blank", icon: <FilePlus2 size={26} aria-hidden />, name: "template" },
  {
    id: "welcome",
    label: "Welcome",
    icon: <PartyPopper size={26} aria-hidden />,
    name: "welcome",
    subject: "Welcome, {{name}}!",
    text: "Hi {{name}},\n\nThanks for signing up. We're glad you're here.",
    html: "<h1>Welcome, {{name}}!</h1>\n<p>Thanks for signing up. We're glad you're here.</p>",
  },
  {
    id: "reset",
    label: "Password reset",
    icon: <KeyRound size={26} aria-hidden />,
    name: "password-reset",
    subject: "Reset your password",
    text: "Hi {{name}},\n\nReset your password here: {{link}}\nThe link expires in an hour.",
    html: '<p>Hi {{name}},</p>\n<p><a href="{{link}}">Reset your password</a>. The link expires in an hour.</p>',
  },
  {
    id: "shipped",
    label: "Order shipped",
    icon: <PackageCheck size={26} aria-hidden />,
    name: "order-shipped",
    subject: "Your order {{order}} is on its way",
    text: "Hi {{name}},\n\nOrder {{order}} shipped. Track it: {{tracking}}",
    html: '<p>Hi {{name}},</p>\n<p>Order <b>{{order}}</b> shipped. <a href="{{tracking}}">Track it</a>.</p>',
  },
  {
    id: "receipt",
    label: "Receipt",
    icon: <Receipt size={26} aria-hidden />,
    name: "receipt",
    subject: "Receipt for {{order}}",
    text: "Hi {{name}},\n\nWe received your payment of {{amount}} for order {{order}}.",
    html: "<p>Hi {{name}},</p>\n<p>We received your payment of <b>{{amount}}</b> for order {{order}}.</p>",
  },
];

export function TemplateFields({ taken, nameRule }: { taken: string[]; nameRule: Rule }) {
  const [preset, setPreset] = useState(PRESETS[0]);
  return (
    <>
      <PresetGallery presets={PRESETS} chosen={preset.id} choose={setPreset} label="Start from" testId="template-preset" />
      <div key={preset.id}>
        <Field label="Name" rule={nameRule} taken={taken} unique member="TemplateName">
          <input name="name" required defaultValue={freeName(preset.name, taken)} spellCheck={false} />
        </Field>
        <Field label="Subject" rule={{ required: true }} member="Subject">
          <input name="subject" required placeholder="Hello {{name}}" defaultValue={preset.subject} />
        </Field>
        <Field label="Text part" member="Text">
          <textarea name="text" rows={4} placeholder="Hi {{name}}, your order {{order}} shipped." defaultValue={preset.text} />
        </Field>
        <MoreFields label="HTML part" expanded={!!preset.html}>
          <Field label="HTML part" member="Html">
            <textarea name="html" rows={4} className="code-editor" placeholder="<p>Hi {{name}}</p>" defaultValue={preset.html} />
          </Field>
        </MoreFields>
      </div>
    </>
  );
}
