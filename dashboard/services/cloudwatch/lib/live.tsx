"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

/** A live tail: re-renders the page on the server every `every` ms while the
 * tab is visible and nobody is typing, for as long as it is mounted (unlike
 * `LiveRefresh`, it neither backs off nor stops). */
export function Tail({ every = 2000 }: { every?: number }) {
  const router = useRouter();
  useEffect(() => {
    const timer = setInterval(() => {
      const typing = document.activeElement?.matches?.(
        "input, textarea, select, [contenteditable]",
      );
      if (
        !document.hidden &&
        !typing &&
        !document.querySelector("dialog[open]")
      )
        router.refresh();
    }, every);
    return () => clearInterval(timer);
  }, [every, router]);
  return null;
}
