"use client";

// What automatic management does as usage nears a quota, as two tiles.

import { PresetGallery } from "@mws-dashboard/ui/presets";
import { BellRing, TrendingUp } from "lucide-react";
import { useState } from "react";

const TYPES = [
  { id: "NotifyOnly", label: "Notify", icon: <BellRing size={24} aria-hidden />, title: "Notify when usage reaches 80%" },
  { id: "NotifyAndAdjust", label: "Notify and raise", icon: <TrendingUp size={24} aria-hidden />, title: "Notify and request an increase when usage reaches 80%" },
];

export function AutoType({ type }: { type?: string }) {
  const [chosen, setChosen] = useState(type ?? "NotifyOnly");
  return (
    <>
      <PresetGallery label="When usage reaches 80%" presets={TYPES} chosen={chosen} choose={(p) => setChosen(p.id)} />
      <input type="hidden" name="type" value={chosen} />
    </>
  );
}
