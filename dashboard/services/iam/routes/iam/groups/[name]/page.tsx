import type { Metadata } from "next";

import { Principal } from "../../principal";

type Props = { params: Promise<{ name: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).name) };
}

export default async function Page({ params }: Props) {
  return <Principal kind="group" name={decodeURIComponent((await params).name)} />;
}
