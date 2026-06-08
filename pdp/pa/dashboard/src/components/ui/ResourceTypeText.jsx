export default function ResourceTypeText({ type }) {
  return (
    <span className="inline-block text-xs font-bold uppercase leading-5 text-text-secondary">
      {String(type || '-').toUpperCase()}
    </span>
  );
}
