"use client";

export default function ErrorPage({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <div className="section">
      <h2>Something went wrong</h2>
      <p className="muted">{error.message || "The page failed to render."}</p>
      <button className="button primary" onClick={reset}>
        Try again
      </button>
    </div>
  );
}
