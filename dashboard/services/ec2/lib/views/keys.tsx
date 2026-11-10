import "server-only";

import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Field, List, Pill, Sheet } from "@mws-dashboard/ui";
import { Import, KeyRound, Trash2 } from "lucide-react";

import { createKeyPair, deleteKeyPair, importKeyPair } from "../../routes/ec2/actions";
import { ICONS } from "../clients";
import { listKeyPairs } from "../ec2";
import { KEY_NAME, PUBLIC_KEY } from "../rules";

export async function KeysView() {
  const keys = await load(listKeyPairs);
  const taken = keys.ok ? keys.value.map((k) => k.KeyName!) : [];
  const actions = (
    <>
      <Sheet title="Import key pair" label="Import key pair" icon={<Import size={16} />} testId="import-key-pair">
        <ActionForm action={importKeyPair} submit="Import" testId="import-key-pair">
          <Field label="Name" rule={KEY_NAME} member="KeyName" taken={taken} unique>
            <input name="name" required autoFocus />
          </Field>
          <Field label="Public key" rule={PUBLIC_KEY} member="PublicKeyMaterial">
            <textarea name="publicKey" rows={4} required placeholder="ssh-ed25519 AAAA…" className="code-editor" />
          </Field>
        </ActionForm>
      </Sheet>
      <Sheet title="New key pair" label="Create key pair" icon={<KeyRound size={16} />} testId="create-key-pair">
        <ActionForm action={createKeyPair} submit="Create" testId="create-key-pair">
          <Field label="Name" rule={KEY_NAME} member="KeyName" taken={taken} unique>
            <input name="name" required autoFocus />
          </Field>
          <Field label="Type">
            <select name="type" defaultValue="ed25519">
              <option>ed25519</option>
              <option>rsa</option>
            </select>
          </Field>
        </ActionForm>
      </Sheet>
    </>
  );
  const body = keys.ok ? (
    <List
      label="Key pairs"
      empty={<Empty icon={ICONS.key} />}
      rows={keys.value.map((k) => ({
        key: k.KeyPairId!,
        icon: <KeyRound size={18} />,
        title: k.KeyName,
        subtitle: k.PublicKey ? (
          <details>
            <summary>
              <code>{k.KeyFingerprint}</code>
            </summary>
            <pre className="code">{k.PublicKey}</pre>
          </details>
        ) : (
          <code>{k.KeyFingerprint}</code>
        ),
        meta: (
          <>
            <Pill>{k.KeyType}</Pill>
            <span>{ago(k.CreateTime)}</span>
          </>
        ),
        actions: <ActionForm action={deleteKeyPair.bind(null, k.KeyName!)} submit={`Delete ${k.KeyName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${k.KeyName}?`} />,
      }))}
    />
  ) : (
    <ErrorNotice error={keys.error} />
  );
  return { body, actions };
}
