export type FeedErrorKind = "blocked" | "unavailable" | "invalid";

export class FeedError extends Error {
  constructor(
    readonly kind: FeedErrorKind,
    message: string,
  ) {
    super(message);
    this.name = "FeedError";
  }
}
