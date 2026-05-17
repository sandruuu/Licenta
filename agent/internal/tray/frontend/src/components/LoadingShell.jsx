function LoadingShell() {
  return (
    <main className="grid h-full w-full place-items-center bg-[var(--surface)]">
      <div className="h-[34px] w-[34px] animate-spin rounded-full border-[3px] border-[var(--border)] border-t-[var(--accent)]" />
    </main>
  );
}

export default LoadingShell;
