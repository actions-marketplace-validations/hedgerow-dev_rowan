import open from "open";
import type { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";

export class BrowserOAuthProvider implements Partial<OAuthClientProvider> {
  constructor(private readonly callbackPort: number) {}

  get redirectUrl(): string {
    return `http://127.0.0.1:${this.callbackPort}/callback`;
  }

  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    const url = new URL(authorizationUrl.toString());
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      throw new Error(`Refusing to open a ${url.protocol} authorization URL`);
    }
    await open(url.href);
  }
}
