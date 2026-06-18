import LoadingSpinner from './LoadingSpinner';

function PageLoading({ label = 'Loading...' }) {
  return (
    <div
      className="grid min-h-[calc(100vh-8rem)] place-items-center"
      role="status"
      aria-live="polite"
      aria-label={label}
    >
      <LoadingSpinner size="lg" />
    </div>
  );
}

export default PageLoading;
