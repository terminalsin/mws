import type { Metadata } from "next";

import { InlinePolicy } from "../../../../inline";

type Props = { params: Promise<{ name: string; policy: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).policy) };
}

export default async function Page({ params }: Props) {
  const { name, policy } = await params;
  return <InlinePolicy kind="role" name={decodeURIComponent(name)} policy={decodeURIComponent(policy)} />;
}
