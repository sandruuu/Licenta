/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './index.html',
    './src/**/*.{js,jsx,ts,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        surface: 'var(--surface)',
        card: 'var(--surface-card)',
        accent: 'var(--accent)',
        graphite: 'var(--text-primary)',
      },
      borderRadius: {
        agent: '6px',
      },
    },
  },
  plugins: [],
};
