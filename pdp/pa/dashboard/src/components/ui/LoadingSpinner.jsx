const segments = Array.from({ length: 12 }, (_, index) => index);

const sizes = {
  sm: {
    '--spinner-size': '16px',
    '--spinner-bar-width': '2px',
    '--spinner-bar-height': '5px',
  },
  md: {
    '--spinner-size': '34px',
    '--spinner-bar-width': '3px',
    '--spinner-bar-height': '10px',
  },
  lg: {
    '--spinner-size': '40px',
    '--spinner-bar-width': '3px',
    '--spinner-bar-height': '12px',
  },
};

export default function LoadingSpinner({ size = 'md', className = '' }) {
  return (
    <div className={`session-spinner ${className}`} style={sizes[size] || sizes.md} aria-hidden="true">
      {segments.map((index) => (
        <span key={index} style={{ '--segment-index': index }} />
      ))}
    </div>
  );
}
