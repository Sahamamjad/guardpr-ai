/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        guard: {
          950: '#0a0f1c',
          900: '#0f172a',
          800: '#1e293b',
          700: '#334155',
          accent: '#22d3ee',
          danger: '#f87171',
          warn: '#fbbf24',
          ok: '#4ade80',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
