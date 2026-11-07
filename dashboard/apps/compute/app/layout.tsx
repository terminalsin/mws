import "@mws-dashboard/ui/styles.css";

import { frameInfo } from "@mws-dashboard/aws";
import { Frame } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: { default: "Compute · MWS", template: "%s · MWS" },
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Frame zone="compute" info={await frameInfo()}>
          {children}
        </Frame>
      </body>
    </html>
  );
}
