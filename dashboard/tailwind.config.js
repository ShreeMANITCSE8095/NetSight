/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      colors: {
        canvas: 'var(--bg-canvas)',
        surface: 'var(--bg-surface)',
        sidebar: 'var(--bg-sidebar)',
        subtle: 'var(--border-subtle)',
        primary: 'var(--text-primary)',
        secondary: 'var(--text-secondary)',
        accent: {
          DEFAULT: '#4F46E5',
          light: '#818CF8',
        },
      },
    },
  },
  plugins: [],
};
